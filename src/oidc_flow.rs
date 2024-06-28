use axum::routing::get;
use axum::Router;

use crate::AppState;

pub fn make_router() -> axum::Router<AppState> {
    Router::new().route("/", get(|| async { "hello world" }))
}
