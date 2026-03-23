use std::sync::Arc;

use axum::routing::any;
use axum::Router;
use tonic::transport::Channel;

use crate::auth::GatewayAuth;
use crate::resolver::Resolver;

/// Application state shared across REST handlers.
pub struct AppState {
    pub resolver: Arc<Resolver>,
    pub auth: Arc<GatewayAuth>,
    pub kernel_channel: Channel,
}

/// Build the REST router.
/// Routes REST_ROOT_PATH/* to the generated route table handler.
pub fn router(state: Arc<AppState>) -> Router {
    let rest_route = format!("{}/{{*rest}}", crate::rest_dispatch::REST_ROOT_PATH);
    Router::new()
        .route(&rest_route, any(crate::rest_dispatch::rest_handler))
        .with_state(state)
}
