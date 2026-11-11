use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Convenience aliases
        with_crypto_provider: { any(feature = "tls-ring", feature = "tls-aws-lc-rs") }
    }
}
