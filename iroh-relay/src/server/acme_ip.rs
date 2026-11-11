//! Certificates for the relay's IP address from an ACME certificate authority.
//!
//! A dialer that falls back to the TCP tunnel knows nothing about the relay but its IP
//! address, and verifies the relay's TLS certificate against that address. The
//! certificate therefore has to be issued for the IP address, not for a hostname.
//!
//! Certificate authorities that speak ACME issue such certificates when the applicant
//! proves control of the address. The relay does that with the `http-01` challenge: the
//! authority fetches a token from the relay's plain HTTP server on port 80. Let's Encrypt
//! issues certificates for IP addresses only with its `shortlived` profile, under which a
//! certificate is valid for about six days. The relay renews in time, on its own.

use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use hyper_util::{client::legacy::Client as HyperClient, rt::TokioExecutor};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, ChallengeType, Identifier,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use n0_error::{e, stack_error};
use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::tls::CaTlsConfig;

/// The directory of Let's Encrypt.
const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// The directory of Let's Encrypt's staging environment, which issues certificates that
/// are not trusted.
const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

/// The certificate profile under which Let's Encrypt issues for IP addresses.
pub const SHORTLIVED_PROFILE: &str = "shortlived";

/// The path under which the `http-01` challenge of ACME is answered, followed by the
/// token of the challenge.
pub(super) const CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

/// The delays between attempts to renew a certificate after a failure.
///
/// Every attempt places an order. Certificate authorities limit how often that may
/// fail: Let's Encrypt allows five failed validations per address and hour. Halfway
/// through a validity period of days there is time to wait.
const MIN_RETRY: Duration = Duration::from_secs(15 * 60);
const MAX_RETRY: Duration = Duration::from_secs(3 * 60 * 60);

/// How long obtaining a certificate may take, from the first request to the ACME server
/// to the certificate.
const OBTAIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Configuration for obtaining a certificate for an IP address through ACME.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IpAcmeConfig {
    /// The URL of the directory of the ACME server.
    pub directory_url: String,
    /// The IP address to obtain the certificate for: the relay's public address.
    ///
    /// The ACME server connects to port 80 of this address to verify that the relay
    /// controls it. The relay's HTTP server has to be reachable there.
    pub ip: IpAddr,
    /// Contact URLs for the ACME account, for example `mailto:admin@example.com`.
    pub contact: Vec<String>,
    /// Where the account and the certificate are kept between restarts. Without it a
    /// new certificate is obtained on every start, which runs into the rate limits of
    /// the certificate authority quickly.
    pub cache_path: Option<PathBuf>,
    /// The certificate profile to ask for. Defaults to [`SHORTLIVED_PROFILE`]. `None`
    /// leaves the choice to the ACME server.
    pub profile: Option<String>,
    /// Which certificate authorities are trusted when connecting to the ACME server.
    pub tls_config: CaTlsConfig,
}

impl IpAcmeConfig {
    /// Creates a configuration for the ACME server with the given directory.
    pub fn new(directory_url: String, ip: IpAddr) -> Self {
        Self {
            directory_url,
            ip,
            contact: Vec::new(),
            cache_path: None,
            profile: Some(SHORTLIVED_PROFILE.to_string()),
            tls_config: CaTlsConfig::default(),
        }
    }

    /// Creates a configuration for Let's Encrypt.
    ///
    /// With `production` set to `false` the staging environment is used, which issues
    /// certificates that are not trusted but has generous rate limits.
    pub fn letsencrypt(production: bool, ip: IpAddr) -> Self {
        let directory_url = if production {
            LETS_ENCRYPT_PRODUCTION_DIRECTORY
        } else {
            LETS_ENCRYPT_STAGING_DIRECTORY
        };
        Self::new(directory_url.to_string(), ip)
    }

    /// Sets the contact URLs for the ACME account.
    pub fn contact(mut self, contact: Vec<String>) -> Self {
        self.contact = contact;
        self
    }

    /// Sets the directory the account and the certificate are kept in.
    pub fn cache_path(mut self, path: PathBuf) -> Self {
        self.cache_path = Some(path);
        self
    }

    /// Sets the certificate profile to ask for.
    pub fn profile(mut self, profile: Option<String>) -> Self {
        self.profile = profile;
        self
    }

    /// Sets which certificate authorities are trusted when connecting to the ACME server.
    pub fn tls_config(mut self, tls_config: CaTlsConfig) -> Self {
        self.tls_config = tls_config;
        self
    }
}

/// Errors when obtaining a certificate for an IP address.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum AcmeIpError {
    #[error("the ACME server could not be used")]
    Acme {
        #[error(std_err)]
        source: instant_acme::Error,
    },
    #[error("the ACME server does not offer the http-01 challenge for the address")]
    NoHttpChallenge,
    #[error("the ACME server did not accept the proof of control: authorization is {status}")]
    Authorization { status: String },
    #[error("the order did not become ready: it is {status}")]
    Order { status: String },
    #[error("failed to create the certificate signing request")]
    Csr {
        #[error(std_err)]
        source: rcgen::Error,
    },
    #[error("the certificate can not be used: {reason}")]
    Certificate { reason: String },
    #[error("failed to access the cache")]
    Cache {
        #[error(std_err)]
        source: io::Error,
    },
    #[error("failed to set up the connection to the ACME server")]
    Tls {
        #[error(std_err)]
        source: io::Error,
    },
    #[error("the ACME server did not answer in time")]
    Timeout,
}

/// The tokens of the challenges that are waiting to be fetched, and what to answer.
#[derive(Debug, Clone, Default)]
pub(super) struct Challenges(Arc<Mutex<HashMap<String, String>>>);

impl Challenges {
    /// Returns the answer for a request to `path`, if it asks for a pending challenge.
    pub(super) fn answer(&self, path: &str) -> Option<String> {
        let token = path.strip_prefix(CHALLENGE_PATH_PREFIX)?;
        self.lock().get(token).cloned()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.0.lock().unwrap_or_else(|err| err.into_inner())
    }
}

/// Serves the current certificate to every client, whatever name it asks for.
///
/// A client that connects to an IP address sends no server name.
#[derive(Debug, Default)]
pub(super) struct IpCertResolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for IpCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current
            .read()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }
}

/// When a certificate has to be replaced.
#[derive(Debug, Clone, Copy)]
struct Validity {
    /// When to obtain the next certificate: halfway through the validity period.
    renew_at: SystemTime,
    not_after: SystemTime,
}

/// Where a cached certificate came from. A certificate from another ACME server, such as
/// a staging environment, or of another profile is not what was asked for.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct CertificateOrigin {
    directory_url: String,
    profile: Option<String>,
}

/// What is kept of the ACME account between restarts.
#[derive(Serialize, Deserialize)]
struct CachedAccount {
    /// The directory the account belongs to. An account can not be used elsewhere.
    directory_url: String,
    credentials: AccountCredentials,
}

/// Obtains and renews the certificate for the relay's IP address.
#[derive(derive_more::Debug)]
pub(super) struct IpAcme {
    config: IpAcmeConfig,
    #[debug("CryptoProvider")]
    provider: Arc<CryptoProvider>,
    challenges: Challenges,
    resolver: Arc<IpCertResolver>,
    #[debug("ClientConfig")]
    client_tls: rustls::ClientConfig,
    /// The ACME account, once it is known. Without a cache this is the only place it is
    /// kept, and a renewal must not create another account.
    #[debug("Account")]
    account: tokio::sync::Mutex<Option<Account>>,
}

impl IpAcme {
    pub(super) fn new(
        config: IpAcmeConfig,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, AcmeIpError> {
        let client_tls = config
            .tls_config
            .client_config(provider.clone())
            .map_err(|err| e!(AcmeIpError::Tls, err))?;
        Ok(Self {
            config,
            provider,
            challenges: Challenges::default(),
            resolver: Arc::default(),
            client_tls,
            account: tokio::sync::Mutex::new(None),
        })
    }

    /// The challenges to answer on the plain HTTP server.
    pub(super) fn challenges(&self) -> Challenges {
        self.challenges.clone()
    }

    /// The resolver to serve the certificate with.
    pub(super) fn resolver(&self) -> Arc<IpCertResolver> {
        self.resolver.clone()
    }

    /// Makes sure a certificate is being served: the cached one if it is still good,
    /// otherwise a new one. Returns when the certificate has to be renewed.
    pub(super) async fn ensure_certificate(&self) -> Result<SystemTime, AcmeIpError> {
        let mut cached_is_valid = false;
        if let Some((chain, key)) = self.load_certificate().await? {
            match self.install(&chain, &key) {
                Ok(validity) if SystemTime::now() < validity.renew_at => {
                    info!(ip = %self.config.ip, "using the cached certificate");
                    return Ok(validity.renew_at);
                }
                // Past its renewal time, but still valid. It stays in use until the
                // new one is there.
                Ok(_) => {
                    debug!("the cached certificate is due for renewal");
                    cached_is_valid = true;
                }
                Err(err) => warn!("the cached certificate can not be used: {err:#}"),
            }
        }
        match self.obtain().await {
            Ok(validity) => Ok(validity.renew_at),
            // There is a certificate to serve. Start, and keep trying.
            Err(err) if cached_is_valid => {
                warn!(ip = %self.config.ip, "failed to renew the certificate: {err:#}");
                Ok(SystemTime::now() + MIN_RETRY)
            }
            Err(err) => Err(err),
        }
    }

    /// Renews the certificate whenever it is due. Does not return.
    pub(super) async fn renew_forever(self, mut renew_at: SystemTime) {
        let mut retry = MIN_RETRY;
        loop {
            let wait = renew_at
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO);
            tokio::time::sleep(wait).await;
            match self.obtain().await {
                Ok(validity) => {
                    renew_at = validity.renew_at;
                    retry = MIN_RETRY;
                }
                Err(err) => {
                    error!(ip = %self.config.ip, "failed to renew the certificate: {err:#}");
                    tokio::time::sleep(retry).await;
                    retry = (retry * 2).min(MAX_RETRY);
                }
            }
        }
    }

    /// Obtains a new certificate, starts serving it and stores it.
    async fn obtain(&self) -> Result<Validity, AcmeIpError> {
        info!(ip = %self.config.ip, "obtaining a certificate");
        let (chain, key) = tokio::time::timeout(OBTAIN_TIMEOUT, self.issue())
            .await
            .map_err(|_| e!(AcmeIpError::Timeout))??;
        let validity = self.install(&chain, &key)?;
        // The certificate is in use. Failing to store it only costs another order after
        // a restart, it is no reason to order another one now.
        if let Err(err) = self.store_certificate(chain, key).await {
            warn!("failed to store the certificate: {err:#}");
        }
        let valid_for = validity
            .not_after
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        info!(ip = %self.config.ip, ?valid_for, "obtained a certificate");
        Ok(validity)
    }

    /// Starts serving the certificate. Returns when it has to be replaced.
    fn install(&self, chain_pem: &str, key_pem: &str) -> Result<Validity, AcmeIpError> {
        let invalid = |reason: String| e!(AcmeIpError::Certificate { reason });
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(chain_pem.as_bytes())
                .collect::<Result<_, _>>()
                .map_err(|err| invalid(format!("the chain can not be parsed: {err}")))?;
        let leaf = chain
            .first()
            .ok_or_else(|| invalid("the chain is empty".to_string()))?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|err| invalid(format!("the key can not be parsed: {err}")))?;

        let (_, parsed) = x509_parser::parse_x509_certificate(leaf)
            .map_err(|err| invalid(format!("the certificate can not be parsed: {err}")))?;
        let to_system_time = |time: x509_parser::time::ASN1Time| {
            let secs = u64::try_from(time.timestamp())
                .map_err(|_| invalid("the validity is before 1970".to_string()))?;
            Ok::<_, AcmeIpError>(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
        };
        let not_before = to_system_time(parsed.validity().not_before)?;
        let not_after = to_system_time(parsed.validity().not_after)?;
        let lifetime = not_after
            .duration_since(not_before)
            .map_err(|_| invalid("the validity ends before it starts".to_string()))?;
        if SystemTime::now() >= not_after {
            return Err(invalid("the certificate has expired".to_string()));
        }

        let signing_key = self
            .provider
            .key_provider
            .load_private_key(key)
            .map_err(|err| invalid(format!("the key can not be used: {err}")))?;
        let certified = CertifiedKey::new(chain, signing_key);
        certified
            .keys_match()
            .map_err(|err| invalid(format!("the key does not belong to the certificate: {err}")))?;
        *self
            .resolver
            .current
            .write()
            .unwrap_or_else(|err| err.into_inner()) = Some(Arc::new(certified));
        Ok(Validity {
            renew_at: not_before + lifetime / 2,
            not_after,
        })
    }

    /// Runs the ACME protocol. Returns the certificate chain and its key, both in PEM.
    async fn issue(&self) -> Result<(String, String), AcmeIpError> {
        let acme = |err| e!(AcmeIpError::Acme, err);
        let account = self.account().await?;

        let identifiers = [Identifier::Ip(self.config.ip)];
        let mut new_order = NewOrder::new(&identifiers);
        if let Some(profile) = &self.config.profile {
            new_order = new_order.profile(profile);
        }
        let mut order = match account.new_order(&new_order).await {
            Ok(order) => order,
            Err(err) => {
                if account_is_gone(&err) {
                    // The server no longer knows the account. Start over with a new
                    // one on the next attempt.
                    warn!("the ACME server rejected the account: {err:#}");
                    self.forget_account().await;
                }
                return Err(acme(err));
            }
        };

        // Prove control of the address: the server fetches the token from port 80.
        let mut tokens = Vec::new();
        let proven = async {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization = authorization.map_err(acme)?;
                match authorization.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    status => {
                        return Err(e!(AcmeIpError::Authorization {
                            status: format!("{status:?}")
                        }));
                    }
                }
                let mut challenge = authorization
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| e!(AcmeIpError::NoHttpChallenge))?;
                let token = challenge.token.clone();
                let answer = challenge.key_authorization().as_str().to_string();
                self.challenges.lock().insert(token.clone(), answer);
                tokens.push(token);
                challenge.set_ready().await.map_err(acme)?;
            }
            order
                .poll_ready(&RetryPolicy::default())
                .await
                .map_err(acme)
        }
        .await;
        for token in tokens {
            self.challenges.lock().remove(&token);
        }
        let status = proven?;
        if status != OrderStatus::Ready {
            return Err(e!(AcmeIpError::Order {
                status: format!("{status:?}")
            }));
        }

        // A new key for every certificate.
        let csr = |err| e!(AcmeIpError::Csr, err);
        let key = rcgen::KeyPair::generate().map_err(csr)?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(csr)?;
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(self.config.ip)];
        params.distinguished_name = rcgen::DistinguishedName::new();
        let request = params.serialize_request(&key).map_err(csr)?;
        order.finalize_csr(request.der()).await.map_err(acme)?;
        let chain = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(acme)?;
        Ok((chain, key.serialize_pem()))
    }

    /// Returns the ACME account: the one in use, the cached one, or a new one.
    async fn account(&self) -> Result<Account, AcmeIpError> {
        let acme = |err| e!(AcmeIpError::Acme, err);
        let mut current = self.account.lock().await;
        if let Some(account) = current.as_ref() {
            return Ok(account.clone());
        }
        if let Some(cached) = self.load_account().await? {
            match self.account_builder().from_credentials(cached).await {
                Ok(account) => {
                    *current = Some(account.clone());
                    return Ok(account);
                }
                // The server says the account is no good. Create another one.
                Err(err) if account_is_gone(&err) => {
                    warn!("the cached ACME account can not be used: {err:#}");
                }
                // Anything else, such as the server not answering, says nothing about
                // the account. Creating a new one would orphan it.
                Err(err) => return Err(acme(err)),
            }
        }
        let contact: Vec<&str> = self.config.contact.iter().map(String::as_str).collect();
        let new_account = NewAccount {
            contact: &contact,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let (account, credentials) = self
            .account_builder()
            .create(&new_account, self.config.directory_url.clone(), None)
            .await
            .map_err(acme)?;
        if let Err(err) = self.store_account(credentials).await {
            warn!("failed to store the ACME account: {err:#}");
        }
        *current = Some(account.clone());
        Ok(account)
    }

    /// Forgets the ACME account, in memory and in the cache.
    async fn forget_account(&self) {
        *self.account.lock().await = None;
        if let Some(path) = self.cache_file(ACCOUNT_FILE) {
            let _ = blocking(move || match std::fs::remove_file(&path) {
                Err(err) if err.kind() != io::ErrorKind::NotFound => {
                    Err(e!(AcmeIpError::Cache, err))
                }
                _ => Ok(()),
            })
            .await;
        }
    }

    fn account_builder(&self) -> instant_acme::AccountBuilder {
        // The scheme of the directory URL decides. Plain HTTP is for tests.
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(self.client_tls.clone())
            .https_or_http()
            .enable_http1()
            .build();
        let client: HyperClient<_, BodyWrapper<Bytes>> =
            HyperClient::builder(TokioExecutor::new()).build(connector);
        Account::builder_with_http(Box::new(client))
    }

    fn cache_file(&self, name: &str) -> Option<PathBuf> {
        self.config.cache_path.as_ref().map(|dir| dir.join(name))
    }

    /// The files of the cached certificate: the chain, the key, and where it came from.
    fn certificate_files(&self) -> Option<(PathBuf, PathBuf, PathBuf)> {
        // An IPv6 address has colons, which are not allowed in file names everywhere.
        let ip = self.config.ip.to_string().replace(':', "_");
        Some((
            self.cache_file(&format!("ip-{ip}.cert.pem"))?,
            self.cache_file(&format!("ip-{ip}.key.pem"))?,
            self.cache_file(&format!("ip-{ip}.origin.json"))?,
        ))
    }

    fn origin(&self) -> CertificateOrigin {
        CertificateOrigin {
            directory_url: self.config.directory_url.clone(),
            profile: self.config.profile.clone(),
        }
    }

    async fn load_account(&self) -> Result<Option<AccountCredentials>, AcmeIpError> {
        let Some(path) = self.cache_file(ACCOUNT_FILE) else {
            return Ok(None);
        };
        let Some(json) = blocking(move || read_if_exists(&path)).await? else {
            return Ok(None);
        };
        match serde_json::from_str::<CachedAccount>(&json) {
            Ok(cached) if cached.directory_url == self.config.directory_url => {
                Ok(Some(cached.credentials))
            }
            // An account of another ACME server.
            Ok(_) => Ok(None),
            Err(err) => {
                warn!("the cached ACME account can not be read: {err}");
                Ok(None)
            }
        }
    }

    async fn store_account(&self, credentials: AccountCredentials) -> Result<(), AcmeIpError> {
        let Some(path) = self.cache_file(ACCOUNT_FILE) else {
            return Ok(());
        };
        let cached = CachedAccount {
            directory_url: self.config.directory_url.clone(),
            credentials,
        };
        let json = serde_json::to_string(&cached).map_err(|err| {
            e!(
                AcmeIpError::Cache,
                io::Error::new(io::ErrorKind::InvalidData, err)
            )
        })?;
        blocking(move || write_private(&path, &json)).await
    }

    /// Loads the cached certificate, if it is one from the configured ACME server and
    /// of the configured profile.
    async fn load_certificate(&self) -> Result<Option<(String, String)>, AcmeIpError> {
        let Some((cert, key, origin)) = self.certificate_files() else {
            return Ok(None);
        };
        let expected = self.origin();
        blocking(move || {
            let (Some(cert), Some(key), Some(origin)) = (
                read_if_exists(&cert)?,
                read_if_exists(&key)?,
                read_if_exists(&origin)?,
            ) else {
                return Ok(None);
            };
            match serde_json::from_str::<CertificateOrigin>(&origin) {
                Ok(origin) if origin == expected => Ok(Some((cert, key))),
                _ => {
                    debug!("the cached certificate is from another ACME server or profile");
                    Ok(None)
                }
            }
        })
        .await
    }

    async fn store_certificate(&self, chain: String, key: String) -> Result<(), AcmeIpError> {
        let Some((cert_path, key_path, origin_path)) = self.certificate_files() else {
            return Ok(());
        };
        let origin = serde_json::to_string(&self.origin()).map_err(|err| {
            e!(
                AcmeIpError::Cache,
                io::Error::new(io::ErrorKind::InvalidData, err)
            )
        })?;
        blocking(move || {
            // The origin goes last. Without it the rest is not used, so a crash in
            // between does not leave a certificate and a key that do not belong
            // together in use.
            let _ = std::fs::remove_file(&origin_path);
            write_private(&key_path, &key)?;
            write_private(&cert_path, &chain)?;
            write_private(&origin_path, &origin)
        })
        .await
    }
}

/// The name of the file the ACME account is cached in.
const ACCOUNT_FILE: &str = "ip-acme-account.json";

/// Returns whether `err` is the ACME server saying that it does not accept the account.
fn account_is_gone(err: &instant_acme::Error) -> bool {
    let instant_acme::Error::Api(problem) = err else {
        return false;
    };
    problem
        .r#type
        .as_deref()
        .is_some_and(|ty| ty.ends_with(":accountDoesNotExist") || ty.ends_with(":unauthorized"))
}

/// Runs file system work off the async runtime.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, AcmeIpError> + Send + 'static,
) -> Result<T, AcmeIpError> {
    match tokio::task::spawn_blocking(work).await {
        Ok(res) => res,
        Err(err) => Err(e!(AcmeIpError::Cache, io::Error::other(err))),
    }
}

fn read_if_exists(path: &std::path::Path) -> Result<Option<String>, AcmeIpError> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(e!(AcmeIpError::Cache, err)),
    }
}

/// Writes a file that only its owner can read.
fn write_private(path: &std::path::Path, content: &str) -> Result<(), AcmeIpError> {
    let write = || -> io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Written next to the file and moved into place, so that a crash does not
        // leave half a file behind.
        let tmp = path.with_extension("tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        io::Write::write_all(&mut file, content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    };
    write().map_err(|err| e!(AcmeIpError::Cache, err))
}
