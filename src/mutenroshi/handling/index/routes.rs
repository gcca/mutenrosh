use axum::{
    Router,
    response::{Html, Redirect},
    routing::get,
};
use mustache2::Data;

use crate::mutenroshi::core::Context;
use crate::mutenroshi::utils::shortcuts::render;

const ABOUT_TEMPLATE: &str = include_str!("templates/about.html");

async fn healthcheck() -> &'static str {
    "🍻"
}

async fn index() -> Redirect {
    Redirect::to("/auth/signin")
}

async fn about() -> Html<String> {
    Html(render(
        ABOUT_TEMPLATE,
        Data::map_from([("appname".into(), Data::from("mutenroshi"))]),
    ))
}

pub fn init_routes(router: Router<Context>) -> Router<Context> {
    router
        .route("/", get(index))
        .route("/healthcheck", get(healthcheck))
        .route("/about", get(about))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutenroshi::utils::testing::{
        TestContext, body_of, dispatch, location_of, test_context,
    };
    use axum::http::{Method, StatusCode};

    fn rendered_about() -> String {
        ABOUT_TEMPLATE.replace("{{appname}}", "mutenroshi")
    }

    fn app() -> (Router, TestContext) {
        let c = test_context();
        (init_routes(Router::new()).with_state(c.context.clone()), c)
    }

    #[tokio::test]
    async fn healthcheck_reports_a_live_process() {
        assert_eq!(healthcheck().await, "🍻");
    }

    #[tokio::test]
    async fn about_interpolates_the_application_name() {
        let Html(body) = about().await;

        assert_eq!(body, rendered_about());
    }

    #[tokio::test]
    async fn healthcheck_route_dispatches_to_its_handler() {
        let (app, _context) = app();
        let response = dispatch(app, Method::GET, "/healthcheck").await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, "🍻");
    }

    #[tokio::test]
    async fn index_route_redirects_to_the_signin_route() {
        let (app, _context) = app();
        let response = dispatch(app, Method::GET, "/").await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location_of(&response), "/auth/signin");
    }

    #[tokio::test]
    async fn about_route_serves_the_rendered_template() {
        let (app, _context) = app();
        let response = dispatch(app, Method::GET, "/about").await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, rendered_about());
    }

    #[tokio::test]
    async fn index_route_rejects_a_post() {
        let (app, _context) = app();
        let response = dispatch(app, Method::POST, "/").await;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn an_unregistered_path_is_not_found() {
        let (app, _context) = app();
        let response = dispatch(app, Method::GET, "/absent").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
