use std::collections::HashMap;

use additional_claims::CoreClientWithClaims;
use axum::{extract::FromRef, routing::any, Router};
use axum_extra::extract::cookie::Key;
use clap::Parser;
use openidconnect::{
    core::CoreProviderMetadata, reqwest::async_http_client, ClientId, ClientSecret, IssuerUrl,
    RedirectUrl,
};
use tokio::net::TcpListener;
mod additional_claims;
mod args;
mod cookie;
mod oidc_flow;
pub mod validate;

#[derive(Clone)]
pub struct AppState {
    pub client: CoreClientWithClaims,
    pub app_url: String,
    pub oidc_path: String,

    pub cookie_key: Key,
    pub cookie_prefix: String,
    pub cookie_path: String,

    pub claim_mapping: HashMap<String, String>,

    pub http_client: reqwest::Client,
}

impl AppState {
    pub async fn async_http_client(
        &self,
        request: openidconnect::HttpRequest,
    ) -> Result<openidconnect::HttpResponse, openidconnect::reqwest::Error<reqwest::Error>> {
        use openidconnect::reqwest::Error;
        let client = &self.http_client;

        let mut request_builder = client
            .request(request.method, request.url.as_str())
            .body(request.body);
        for (name, value) in &request.headers {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }
        let request = request_builder.build().map_err(Error::Reqwest)?;

        let response = client.execute(request).await.map_err(Error::Reqwest)?;

        let status_code = response.status();
        let headers = response.headers().to_owned();
        let chunks = response.bytes().await.map_err(Error::Reqwest)?;
        Ok(openidconnect::HttpResponse {
            status_code,
            headers,
            body: chunks.to_vec(),
        })
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = args::Args::parse();

    // Parse the claim mapping
    let mut claim_mapping = HashMap::new();
    for item in args.claim_mapping {
        let mut parts = item.splitn(2, ':');
        let claim = parts.next().unwrap();
        let header = parts
            .next()
            .expect("Must have two parts: first is claim name, second is header name");
        claim_mapping.insert(claim.to_string(), header.to_string());
    }

    if claim_mapping.is_empty() {
        tracing::warn!("no claim mapping provided! Will not add any headers describing the user, this only works in access control mode");
    } else {
        for (claim, header) in &claim_mapping {
            tracing::info!("claim mapping: claim {} -> header {}", claim, header);
        }
    }

    // Fetch the OIDC client ID and secret
    let client_id = tokio::fs::read_to_string(&args.oidc_client_id_path)
        .await
        .expect("failed to read client ID file");
    let client_secret = tokio::fs::read_to_string(&args.oidc_client_secret_path)
        .await
        .expect("failed to read client secret file");

    // Try fetching the key
    // If that fails, maybe try generating it.
    let cookie_key = match tokio::fs::read(&args.cookie_key_path).await {
        Ok(data) => Key::from(&data),
        Err(why) => {
            tracing::error!("failed to read cookie key: {}", why);
            if args.generate_cookie_key {
                tracing::warn!("generating new cookie key");
                let key = Key::generate();
                tokio::fs::write(&args.cookie_key_path, key.master())
                    .await
                    .unwrap();
                key
            } else {
                panic!("failed to read cookie key");
            }
        }
    };

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

    let client =
        CoreClientWithClaims::from_provider_metadata(metadata, client_id, Some(client_secret))
            .set_redirect_uri(
                RedirectUrl::new(format!("{}{}/authorize", args.url, args.oidc_path))
                    .expect("invalid redirect url attempted"),
            );

    let http_client = {
        let builder = reqwest::Client::builder();

        // Following redirects opens the client up to SSRF vulnerabilities.
        // but this is not possible to prevent on wasm targets
        let builder = builder.redirect(reqwest::redirect::Policy::none());

        builder.build().expect("failed to build http client")
    };

    let app_state = AppState {
        client,
        app_url: args.url,
        oidc_path: args.oidc_path.clone(),

        cookie_key,
        cookie_prefix: args.cookie_prefix,
        cookie_path: args.cookie_path,

        claim_mapping,
        http_client,
    };

    let app: Router = axum::Router::new()
        .nest(&args.oidc_path, oidc_flow::make_router())
        .fallback(any(validate::check_token))
        .with_state(app_state)
        // add logging
        .layer(
            tower_http::trace::TraceLayer::new_for_http().make_span_with(
                tower_http::trace::DefaultMakeSpan::default().level(tracing::Level::DEBUG),
            ),
        );

    axum::serve(
        TcpListener::bind(args.http_listen)
            .await
            .expect("failed to bind to listen port"),
        app.into_make_service(),
    )
    .await
    .expect("failed to serve HTTP");
}
