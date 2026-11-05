//! Hygeia control plane: enrollment, bundle distribution, rules, audit.
//!
//! Tenant and group are always derived from the credential, never from client
//! parameters, on the data-plane endpoints (`/v1/enroll`, `/v1/bundle`).
//! Admin endpoints use a static bearer token for now; OIDC + RBAC replace it.

pub mod accesslog;
pub mod auth;
pub mod build;
pub mod doh;
pub mod oidc;
mod routes;
mod state;
pub mod tls;
pub mod ui;

pub use auth::{AuthConfig, BreakGlass, LocalOwner, Principal};
pub use oidc::{OidcConfig, OidcVerifier};
pub use routes::{OidcPublic, PublicConfig, router, router_with_ui};
pub use state::{AppState, DEFAULT_GROUP, DEFAULT_TENANT, now};

pub use axum::Router;

/// Serve the API until `shutdown` resolves.
pub async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}
