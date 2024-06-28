use std::path::PathBuf;

#[derive(clap::Parser, Debug, Clone)]
pub struct Args {
    /// File containing the OIDC client ID
    #[clap(long = "client-id", short = 'i')]
    pub oidc_client_id_path: PathBuf,

    /// File containing the OIDC client secret
    #[clap(long = "client-secret", short = 's')]
    pub oidc_client_secret_path: PathBuf,

    /// OIDC issuer URL: example https://accounts.google.com, https://gitlab.com
    #[clap(long = "issuer", short = 'u')]
    pub oidc_issuer_url: String,

    /// The URL where this app will be available
    #[clap(long = "url", short = 'U')]
    pub url: String,

    /// Socket address to listen on
    #[clap(long = "listen", short = 'l', default_value = "0.0.0.0:8080")]
    pub http_listen: String,

    /// Path for internal OIDC operations
    #[clap(long = "oidc-path", short = 'o', default_value = "/_oidc")]
    pub oidc_path: String,
}
