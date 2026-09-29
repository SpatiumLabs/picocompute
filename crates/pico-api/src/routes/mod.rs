//! HTTP route construction for the PicoCompute platform API.

use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, post};

use crate::auth::BearerAuth;
use crate::handlers;
use crate::middleware::request_tracing_layer;
use crate::state::AppState;

/// Build the v1 router. The `public` sub-router serves `/v1/livez` and `/v1/readyz` with no auth.
/// The `protected` sub-router is layered with `BearerAuth` so every route added to it (lifecycle, exec, files, tasks)
/// requires `Authorization: Bearer <token>`.
pub fn build_router(state: AppState, token: String) -> Router {
    let public: Router = Router::new()
        .route("/v1/livez", get(handlers::health::livez))
        .route("/v1/readyz", get(handlers::health::readyz))
        .with_state(Arc::clone(&state));

    let protected: Router = Router::new()
        .route(
            "/v1/sandboxes",
            post(handlers::sandbox::create).get(handlers::sandbox::list),
        )
        .route(
            "/v1/sandboxes/{id}",
            get(handlers::sandbox::get_one).delete(handlers::sandbox::destroy),
        )
        .route("/v1/sandboxes/{id}/purge", post(handlers::sandbox::purge))
        .route("/v1/sandboxes/{id}/stop", post(handlers::sandbox::stop))
        .route(
            "/v1/sandboxes/{id}/suspend",
            post(handlers::sandbox::suspend),
        )
        .route("/v1/sandboxes/{id}/resume", post(handlers::sandbox::resume))
        .route("/v1/jobs/{job_id}/pause", post(handlers::jobs::pause_job))
        .route("/v1/jobs/{job_id}/resume", post(handlers::jobs::resume_job))
        .route(
            "/v1/sandboxes/{id}/keepalive",
            post(handlers::sandbox::keepalive),
        )
        .route("/v1/sandboxes/{id}/lease", post(handlers::leases::issue))
        .route("/v1/sandboxes/{id}/exec", post(handlers::exec::exec))
        .route(
            "/v1/sandboxes/{id}/files",
            get(handlers::files::get).put(handlers::files::put),
        )
        .route("/v1/sandboxes/{id}/tasks", post(handlers::tasks::start))
        .route(
            "/v1/sandboxes/{id}/tasks/{task_id}",
            get(handlers::tasks::get_one).delete(handlers::tasks::cancel),
        )
        .route(
            "/v1/sandboxes/{id}/tasks/{task_id}/events",
            get(handlers::tasks::events),
        )
        .route(
            "/v1/sandboxes/{id}/tasks/{task_id}/cancel",
            post(handlers::tasks::cancel),
        )
        .route("/v1/sandboxes/{id}/ssh", get(handlers::ssh::ssh_info))
        .route(
            "/v1/sandboxes/{id}/ssh/tunnel",
            get(handlers::ssh_tunnel::ssh_tunnel),
        )
        .route(
            "/v1/sandboxes/{id}/ports",
            post(handlers::port_forward::expose).get(handlers::port_forward::list),
        )
        .route(
            "/v1/sandboxes/{id}/ports/{endpoint_id}",
            delete(handlers::port_forward::revoke),
        )
        .with_state(state)
        .layer(BearerAuth::new(token));

    Router::new()
        .merge(public)
        .merge(protected)
        .layer(request_tracing_layer())
}

#[cfg(test)]
mod tests;
