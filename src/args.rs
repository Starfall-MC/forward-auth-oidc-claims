use std::path::PathBuf;

#[derive(clap::Parser, Debug, Clone)]
pub struct Args {
    /// File containing the OIDC client ID
    #[clap(long = "client-id", short = 'i')]
    pub oidc_client_id_path: PathBuf,

    /// File containing the OIDC client secret
    #[clap(long = "client-secret", short = 's')]
    pub oidc_client_secret_path: PathBuf,

    /// OIDC issuer URL **without trailing slash**: example https://accounts.google.com, https://gitlab.com
    #[clap(long = "issuer", short = 'u')]
    pub oidc_issuer_url: String,

    /// The URL where this app will be available **without trailing slash**: example http://app.example.com
    #[clap(long = "url", short = 'U')]
    pub url: String,

    /// Socket address to listen on
    #[clap(long = "listen", short = 'l', default_value = "0.0.0.0:8080")]
    pub http_listen: String,

    /// Path for internal OIDC operations
    #[clap(long = "oidc-path", short = 'o', default_value = "/_oidc")]
    pub oidc_path: String,

    /// Path to the file with the secret key used to encrypt cookies: needs to be exactly 64 bytes of randomness
    #[clap(long = "cookie-key", short = 'k')]
    pub cookie_key_path: PathBuf,

    /// If the cookie file doesn't exist, should I generate it?
    #[clap(long = "generate-cookie-key", short = 'g')]
    pub generate_cookie_key: bool,

    /// Prefix to use for the cookie names, so they don't collide with other apps
    #[clap(long = "cookie-prefix", short = 'p', default_value = "_oidc_client_")]
    pub cookie_prefix: String,

    /// Which path to specify for token cookies?
    /// This must cover the entire application to be protected,
    /// any other paths will not be able to read this token.
    #[clap(long = "cookie-path", short = 'P', default_value = "/")]
    pub cookie_path: String,

    /// Claim mapping: like email:X-Client-Email. Comma-separated list
    #[clap(long = "claim-mapping", short = 'm', value_delimiter = ',', num_args=0..)]
    pub claim_mapping: Vec<String>,

    /// Which scopes to request from the identity provider (try 'openid' if none required). Comma-separated list
    #[clap(long = "scopes", short = 'S', value_delimiter = ',', num_args=1..)]
    pub scopes: Vec<String>,

    /// Which claims to drop from the token after receiving them from the identity provider.
    /// Note that some claims are critical, so they will not be dropped even if they are listed here.
    /// Comma-separated list
    #[clap(long = "drop-claims", short = 'd', value_delimiter = ',', num_args=0..)]
    pub drop_claims: Vec<String>,

    /// Enrichment URL for claims. If provided, when getting a token, it will be POSTed to this URL,
    /// then replaced with the response.
    /// So, the endpoint must return a copy of all the incoming claims,
    /// unless it wants to remove some of them.
    /// Note that this is before claims are dropped:
    /// any added ones could be dropped if listed in `drop-claims`.
    #[cfg(feature = "enrichment")]
    #[clap(long = "enrich_url", short = 'e')]
    pub enrich_url: Option<String>,
}
