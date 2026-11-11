//! Tests of obtaining a certificate for an IP address, against a small ACME server.
//!
//! The ACME server in here does what the relay depends on: it hands out an `http-01`
//! challenge, fetches the answer from the relay's plain HTTP server, and signs the
//! certificate request with its own certificate authority. It does not verify the
//! signatures of the requests it gets.

use std::{
    convert::Infallible,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use iroh_relay::server::{
    CertConfig, IpAcmeConfig, RelayConfig, Server, ServerConfig, SpawnError, TlsConfig,
};
use rustls::pki_types::CertificateDer;
use serde_json::{Value, json};
use tokio::net::TcpListener;

const TIMEOUT: Duration = Duration::from_secs(20);

/// What the ACME server remembers.
struct Acme {
    /// The URL the server is reached at.
    url: String,
    /// The port of the relay's plain HTTP server, where challenges are fetched from.
    /// A real ACME server uses port 80.
    validation_port: u16,
    /// How long the certificates it issues are valid.
    validity: Duration,
    ca: rcgen::Issuer<'static, rcgen::KeyPair>,
    ca_cert: rcgen::Certificate,
    /// Set to answer every request with an error, as if the server was down.
    broken: AtomicBool,
    state: Mutex<AcmeState>,
}

#[derive(Default)]
struct AcmeState {
    accounts: u32,
    /// The orders, by their number minus one.
    orders: Vec<Order>,
    nonces: u32,
}

struct Order {
    /// What the relay asked for.
    request: Value,
    /// Whether the relay proved control of the address, once it was asked to.
    proven: Option<bool>,
    /// The certificate chain, once issued.
    certificate: Option<String>,
}

impl Acme {
    /// Starts the server. Returns it and stops serving when the result is dropped.
    async fn spawn(validation_port: u16, validity: Duration) -> Arc<Self> {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test ACME authority");
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca = rcgen::Issuer::new(ca_params, ca_key);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let acme = Arc::new(Self {
            url: format!("http://{}", listener.local_addr().unwrap()),
            validation_port,
            validity,
            ca,
            ca_cert,
            broken: AtomicBool::new(false),
            state: Mutex::default(),
        });
        let weak = Arc::downgrade(&acme);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Some(acme) = weak.upgrade() else { return };
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let acme = acme.clone();
                        async move { Ok::<_, Infallible>(acme.handle(req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        acme
    }

    fn directory_url(&self) -> String {
        format!("{}/directory", self.url)
    }

    /// The certificate of the authority, to verify the certificates it issued.
    fn root(&self) -> CertificateDer<'static> {
        self.ca_cert.der().clone()
    }

    fn orders(&self) -> usize {
        self.state.lock().unwrap().orders.len()
    }

    fn accounts(&self) -> u32 {
        self.state.lock().unwrap().accounts
    }

    /// What the relay asked for in its `n`th order.
    fn order_request(&self, n: usize) -> Value {
        self.state.lock().unwrap().orders[n].request.clone()
    }

    fn order_json(&self, n: usize) -> Value {
        let state = self.state.lock().unwrap();
        let order = &state.orders[n];
        let status = match (&order.certificate, order.proven) {
            (Some(_), _) => "valid",
            (None, Some(true)) => "ready",
            (None, Some(false)) => "invalid",
            (None, None) => "pending",
        };
        let mut json = json!({
            "status": status,
            "identifiers": order.request["identifiers"],
            "authorizations": [format!("{}/authz/{n}", self.url)],
            "finalize": format!("{}/finalize/{n}", self.url),
        });
        if order.certificate.is_some() {
            json["certificate"] = format!("{}/cert/{n}", self.url).into();
        }
        json
    }

    /// The status of the authorization and the challenge of order `n`.
    fn proof_status(&self, n: usize) -> &'static str {
        match self.state.lock().unwrap().orders[n].proven {
            Some(true) => "valid",
            Some(false) => "invalid",
            None => "pending",
        }
    }

    fn challenge_json(&self, n: usize) -> Value {
        json!({
            "type": "http-01",
            "url": format!("{}/chall/{n}", self.url),
            "token": format!("token-{n}"),
            "status": self.proof_status(n),
        })
    }

    /// Fetches the answer to the challenge of order `n` from the relay.
    async fn validate(&self, n: usize) -> bool {
        let token = format!("token-{n}");
        let url = format!(
            "http://127.0.0.1:{}/.well-known/acme-challenge/{token}",
            self.validation_port
        );
        let Ok(response) = reqwest::get(&url).await else {
            return false;
        };
        if response.status() != StatusCode::OK {
            return false;
        }
        // The answer is the token and the thumbprint of the account key.
        let body = response.text().await.unwrap_or_default();
        body.strip_prefix(&format!("{token}."))
            .is_some_and(|thumbprint| !thumbprint.is_empty())
    }

    /// Signs the certificate request of order `n`.
    fn issue(&self, csr: &[u8]) -> String {
        let csr = rustls::pki_types::CertificateSigningRequestDer::from(csr.to_vec());
        let mut request = rcgen::CertificateSigningRequestParams::from_der(&csr).unwrap();
        let now = time::OffsetDateTime::now_utc();
        // Certificates are dated back a little, like those of real authorities.
        request.params.not_before = now - Duration::from_secs(1);
        request.params.not_after = now + self.validity;
        let cert = request.signed_by(&self.ca).unwrap();
        format!("{}{}", cert.pem(), self.ca_cert.pem())
    }

    async fn handle(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        if self.broken.load(Ordering::Relaxed) {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::default())
                .unwrap();
        }
        let path = req.uri().path().to_string();
        let method = req.method().clone();
        let body = req.into_body().collect().await.unwrap().to_bytes();
        // Requests are signed objects with the payload in base64. An empty payload asks
        // for the resource.
        let payload: Value = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|jws| {
                let payload = jws["payload"].as_str()?.to_string();
                let payload = BASE64URL_NOPAD.decode(payload.as_bytes()).ok()?;
                serde_json::from_slice(&payload).ok()
            })
            .unwrap_or(Value::Null);

        let nonce = {
            let mut state = self.state.lock().unwrap();
            state.nonces += 1;
            format!("nonce-{}", state.nonces)
        };
        let response = |status: StatusCode, body: Vec<u8>| {
            {
                Response::builder()
                    .status(status)
                    .header("Replay-Nonce", &nonce)
                    .header("Content-Type", "application/json")
            }
            .body(Full::from(body))
            .unwrap()
        };
        let json =
            |status: StatusCode, body: Value| response(status, body.to_string().into_bytes());
        let created = |location: String, body: Value| {
            let mut response = json(StatusCode::CREATED, body);
            response
                .headers_mut()
                .insert("Location", location.parse().unwrap());
            response
        };
        let number = |prefix: &str| -> Option<usize> {
            let n = path.strip_prefix(prefix)?.parse().ok()?;
            (n < self.orders()).then_some(n)
        };

        if path == "/directory" {
            return json(
                StatusCode::OK,
                json!({
                    "newNonce": format!("{}/new-nonce", self.url),
                    "newAccount": format!("{}/new-account", self.url),
                    "newOrder": format!("{}/new-order", self.url),
                    "meta": {
                        "profiles": {
                            "shortlived": "certificates for a few days, also for IP addresses",
                        },
                    },
                }),
            );
        }
        if path == "/new-nonce" {
            return response(StatusCode::OK, Vec::new());
        }
        if method != hyper::Method::POST {
            return json(StatusCode::METHOD_NOT_ALLOWED, json!({}));
        }
        if path == "/new-account" {
            let id = {
                let mut state = self.state.lock().unwrap();
                state.accounts += 1;
                state.accounts
            };
            return created(
                format!("{}/account/{id}", self.url),
                json!({ "status": "valid" }),
            );
        }
        if path == "/new-order" {
            let n = {
                let mut state = self.state.lock().unwrap();
                state.orders.push(Order {
                    request: payload,
                    proven: None,
                    certificate: None,
                });
                state.orders.len() - 1
            };
            return created(format!("{}/order/{n}", self.url), self.order_json(n));
        }
        if let Some(n) = number("/order/") {
            return json(StatusCode::OK, self.order_json(n));
        }
        if let Some(n) = number("/authz/") {
            let identifier = self.order_request(n)["identifiers"][0].clone();
            return json(
                StatusCode::OK,
                json!({
                    "identifier": identifier,
                    "status": self.proof_status(n),
                    "challenges": [self.challenge_json(n)],
                }),
            );
        }
        if let Some(n) = number("/chall/") {
            // The relay says that it is ready to be asked. A failed validation is final.
            let proven = self.validate(n).await;
            self.state.lock().unwrap().orders[n].proven = Some(proven);
            return json(StatusCode::OK, self.challenge_json(n));
        }
        if let Some(n) = number("/finalize/") {
            if self.state.lock().unwrap().orders[n].proven != Some(true) {
                return json(
                    StatusCode::FORBIDDEN,
                    json!({
                        "type": "urn:ietf:params:acme:error:orderNotReady",
                        "detail": "the order is not ready",
                    }),
                );
            }
            let csr = payload["csr"].as_str().unwrap_or_default();
            let csr = BASE64URL_NOPAD.decode(csr.as_bytes()).unwrap();
            let chain = self.issue(&csr);
            self.state.lock().unwrap().orders[n].certificate = Some(chain);
            return json(StatusCode::OK, self.order_json(n));
        }
        if let Some(n) = number("/cert/") {
            let chain = self.state.lock().unwrap().orders[n].certificate.clone();
            return match chain {
                Some(chain) => response(StatusCode::OK, chain.into_bytes()),
                None => json(StatusCode::NOT_FOUND, json!({})),
            };
        }
        json(StatusCode::NOT_FOUND, json!({}))
    }
}

/// A directory that is removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "iroh-relay-acme-ip-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Returns a TCP port on localhost that is free right now.
fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn ring() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Starts a relay that obtains its certificate from `acme`.
async fn spawn_relay(
    acme: &Acme,
    http_port: u16,
    cache: Option<&TempDir>,
) -> Result<Server, SpawnError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut acme_config = IpAcmeConfig::new(acme.directory_url(), Ipv4Addr::LOCALHOST.into());
    if let Some(cache) = cache {
        acme_config = acme_config.cache_path(cache.0.clone());
    }
    let server_config_builder = rustls::ServerConfig::builder_with_provider(ring())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth();
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, http_port));
    relay.tls = Some(TlsConfig::new(
        (Ipv4Addr::LOCALHOST, 0),
        CertConfig::AcmeIp {
            acme_config,
            server_config_builder,
        },
    ));
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    tokio::time::timeout(TIMEOUT, Server::spawn(config))
        .await
        .expect("timeout starting the relay")
}

/// Fetches a page from the relay over HTTPS, the way a dialer of the TCP fallback
/// connects: by IP address, trusting only the test authority. Returns the serial number
/// of the certificate the relay presented.
async fn fetch(acme: &Acme, addr: SocketAddr) -> Result<String, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(acme.root()).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(ring())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .tls_info(true)
        .build()
        .unwrap();
    let response = client
        .get(format!("https://{addr}/ping"))
        .send()
        .await
        .map_err(|err| format!("{err:?}"))?;
    assert_eq!(response.status(), StatusCode::OK);
    let info = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .expect("TLS info is enabled");
    let cert = info
        .peer_certificate()
        .expect("the relay sent a certificate");
    let (_, cert) = x509_parser::parse_x509_certificate(cert).unwrap();
    Ok(cert.raw_serial_as_string())
}

#[tokio::test]
async fn obtains_a_certificate_for_its_ip_address() {
    let http_port = free_port();
    let acme = Acme::spawn(http_port, Duration::from_secs(6 * 24 * 3600)).await;
    let server = spawn_relay(&acme, http_port, None).await.unwrap();

    // The relay asked for a certificate for its address, under the profile that allows
    // one.
    assert_eq!(acme.orders(), 1);
    let request = acme.order_request(0);
    assert_eq!(
        request["identifiers"],
        json!([{ "type": "ip", "value": "127.0.0.1" }])
    );
    assert_eq!(request["profile"], "shortlived");

    // A client that only knows the IP address verifies the relay against it.
    fetch(&acme, server.https_addr().unwrap()).await.unwrap();

    // The challenge is no longer answered once it is done.
    let url = format!("http://127.0.0.1:{http_port}/.well-known/acme-challenge/token-0");
    assert_eq!(
        reqwest::get(&url).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    // The other service on the plain HTTP server is still there.
    let url = format!("http://127.0.0.1:{http_port}/generate_204");
    assert_eq!(
        reqwest::get(&url).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn keeps_account_and_certificate_between_restarts() {
    let http_port = free_port();
    let cache = TempDir::new();
    let acme = Acme::spawn(http_port, Duration::from_secs(6 * 24 * 3600)).await;

    let server = spawn_relay(&acme, http_port, Some(&cache)).await.unwrap();
    let serial = fetch(&acme, server.https_addr().unwrap()).await.unwrap();
    server.shutdown().await.unwrap();
    assert_eq!((acme.accounts(), acme.orders()), (1, 1));

    // The key is only readable by its owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = cache.0.join("ip-127.0.0.1.key.pem");
        let mode = std::fs::metadata(key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // A restart finds the certificate and does not ask for another one.
    let server = spawn_relay(&acme, http_port, Some(&cache)).await.unwrap();
    assert_eq!(
        fetch(&acme, server.https_addr().unwrap()).await.unwrap(),
        serial
    );
    server.shutdown().await.unwrap();
    assert_eq!((acme.accounts(), acme.orders()), (1, 1));

    // Without the certificate the account is still used.
    std::fs::remove_file(cache.0.join("ip-127.0.0.1.cert.pem")).unwrap();
    let server = spawn_relay(&acme, http_port, Some(&cache)).await.unwrap();
    assert_ne!(
        fetch(&acme, server.https_addr().unwrap()).await.unwrap(),
        serial
    );
    assert_eq!((acme.accounts(), acme.orders()), (1, 2));
}

#[tokio::test]
async fn renews_before_the_certificate_expires() {
    let http_port = free_port();
    // Valid for a few seconds. The relay renews halfway through.
    let acme = Acme::spawn(http_port, Duration::from_secs(6)).await;
    let server = spawn_relay(&acme, http_port, None).await.unwrap();
    let addr = server.https_addr().unwrap();
    let first = fetch(&acme, addr).await.unwrap();
    assert_eq!(acme.orders(), 1);

    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while acme.orders() < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the certificate was not renewed"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // New connections get the new certificate, without a restart.
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        if fetch(&acme, addr).await.unwrap() != first {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the new certificate is not served"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The account is reused for the renewal.
    assert_eq!(acme.accounts(), 1);
}

#[tokio::test]
async fn fails_to_start_without_proof_of_control() {
    let http_port = free_port();
    // The ACME server looks for the answer where the relay is not listening.
    let acme = Acme::spawn(free_port(), Duration::from_secs(3600)).await;
    let err = spawn_relay(&acme, http_port, None).await.unwrap_err();
    assert!(matches!(err, SpawnError::AcmeIp { .. }), "{err:?}");
    assert_eq!(acme.orders(), 1);
}

#[tokio::test]
async fn starts_with_the_cached_certificate_when_renewal_fails() {
    let http_port = free_port();
    let cache = TempDir::new();
    // Valid for a few seconds, due for renewal halfway through.
    let acme = Acme::spawn(http_port, Duration::from_secs(8)).await;
    let server = spawn_relay(&acme, http_port, Some(&cache)).await.unwrap();
    let serial = fetch(&acme, server.https_addr().unwrap()).await.unwrap();
    server.shutdown().await.unwrap();

    // The relay is restarted when the certificate is due for renewal but still valid,
    // and the ACME server is down.
    tokio::time::sleep(Duration::from_secs(5)).await;
    acme.broken.store(true, Ordering::Relaxed);
    let server = spawn_relay(&acme, http_port, Some(&cache)).await.unwrap();
    assert_eq!(
        fetch(&acme, server.https_addr().unwrap()).await.unwrap(),
        serial
    );
    assert_eq!(acme.orders(), 1);
    server.shutdown().await.unwrap();

    // Without a certificate to fall back on the relay does not start.
    let empty = TempDir::new();
    let err = spawn_relay(&acme, http_port, Some(&empty))
        .await
        .unwrap_err();
    assert!(matches!(err, SpawnError::AcmeIp { .. }), "{err:?}");
}

#[tokio::test]
async fn does_not_use_a_cached_certificate_of_another_acme_server() {
    let http_port = free_port();
    let cache = TempDir::new();
    let validity = Duration::from_secs(6 * 24 * 3600);
    // Think of the first as a staging environment, whose certificates nobody trusts.
    let staging = Acme::spawn(http_port, validity).await;
    let production = Acme::spawn(http_port, validity).await;

    let server = spawn_relay(&staging, http_port, Some(&cache))
        .await
        .unwrap();
    fetch(&staging, server.https_addr().unwrap()).await.unwrap();
    server.shutdown().await.unwrap();

    // The same cache, now with the other server. Neither the account nor the
    // certificate of the first is used.
    let server = spawn_relay(&production, http_port, Some(&cache))
        .await
        .unwrap();
    let addr = server.https_addr().unwrap();
    fetch(&production, addr).await.unwrap();
    assert!(fetch(&staging, addr).await.is_err());
    assert_eq!((production.accounts(), production.orders()), (1, 1));
    assert_eq!((staging.accounts(), staging.orders()), (1, 1));
}
