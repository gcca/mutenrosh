pub mod mutenroshi;

use axum::Router;

use mutenroshi::core::{Context, conf::settings};
use mutenroshi::handling::auth::routes::init_routes as init_auth_routes;
use mutenroshi::handling::index::routes::init_routes as init_index_routes;

#[tokio::main]
async fn main() {
    let c = Context::open(
        &settings.dbpath,
        settings.session_secret.as_bytes().to_vec(),
        settings.session_ttl_seconds,
    )
    .expect("failed to open the read-only database");
    let app = init_auth_routes(init_index_routes(Router::new())).with_state(c.clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000")
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");

    c.dbro
        .lock()
        .expect("read-only database mutex is poisoned")
        .close();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, StatusCode};
    use mutenroshi::utils::testing::{TestContext, dispatch, test_context};

    fn app() -> (Router, TestContext) {
        let c = test_context();
        let app = init_auth_routes(init_index_routes(Router::new())).with_state(c.context.clone());
        (app, c)
    }

    #[tokio::test]
    async fn the_composed_router_serves_both_route_sets() {
        let (router, _context) = app();
        assert_eq!(
            dispatch(router, Method::GET, "/healthcheck").await.status(),
            StatusCode::OK
        );
        let (router, _context) = app();
        assert_eq!(
            dispatch(router, Method::GET, "/auth/signin").await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn the_composed_router_keeps_the_index_redirect() {
        let (app, _context) = app();
        let response = dispatch(app, Method::GET, "/").await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }
}
