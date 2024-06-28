use axum::{routing::any, Router};
use clap::Parser;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    ClientId, ClientSecret, IssuerUrl,
};
use tokio::net::TcpListener;
mod args;
mod oidc_flow;
pub mod validate;

#[derive(Clone)]
pub struct AppState {
    pub client: CoreClient,
    pub app_url: String,
    pub oidc_path: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = args::Args::parse();

    // Fetch the OIDC client ID and secret
    let client_id = tokio::fs::read_to_string(&args.oidc_client_id_path)
        .await
        .expect("failed to read client ID file");
    let client_secret = tokio::fs::read_to_string(&args.oidc_client_secret_path)
        .await
        .expect("failed to read client secret file");

    let client_id = client_id.trim();
    let client_id = ClientId::new(client_id.to_string());
    let client_secret = client_secret.trim();
    let client_secret = ClientSecret::new(client_secret.to_string());

    tracing::info!("OIDC client ID: {:?}", client_id);

    let issuer = IssuerUrl::new(args.oidc_issuer_url.clone()).expect("failed to parse issuer URL");

    // async_http_client creates a new client for each call,
    // but that's okay because we're only calling this once.
    let metadata = CoreProviderMetadata::discover_async(issuer.clone(), async_http_client)
        .await
        .expect("failed to gather issuer metadata");

    tracing::debug!("issuer metadata: {:?}", metadata);

    let client = CoreClient::from_provider_metadata(metadata, client_id, Some(client_secret));

    let app_state = AppState {
        client,
        app_url: args.url,
        oidc_path: args.oidc_path.clone(),
    };

    let app: Router = axum::Router::new()
        .nest(&args.oidc_path, oidc_flow::make_router())
        .fallback(any(validate::check_token))
        .with_state(app_state);

    axum::serve(
        TcpListener::bind(args.http_listen)
            .await
            .expect("failed to bind to listen port"),
        app.into_make_service(),
    )
    .await
    .expect("failed to serve HTTP");
}
