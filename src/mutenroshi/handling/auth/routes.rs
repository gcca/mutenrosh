use axum::{
    Router,
    extract::{Form, State},
    http::{HeaderMap, HeaderValue, header::SET_COOKIE},
    response::{Html, Redirect},
    routing::get,
};
use std::collections::HashMap;

use crate::mutenroshi::core::{self, Context};
use crate::mutenroshi::repositories::AuthRepository;
use crate::mutenroshi::utils::shortcuts::renders;

const SIGNIN_TEMPLATE: &str = include_str!("templates/signin.html");

async fn signin_get() -> Html<String> {
    Html(renders(SIGNIN_TEMPLATE))
}

async fn signin_post(
    State(c): State<Context>,
    Form(values): Form<HashMap<String, String>>,
) -> (HeaderMap, Redirect) {
    let Some(username) = values.get("username") else {
        return (HeaderMap::new(), Redirect::to("/auth/signin"));
    };
    let Some(password) = values.get("password") else {
        return (HeaderMap::new(), Redirect::to("/auth/signin"));
    };

    let user = AuthRepository::new(c.clone()).user_by(username);

    match user {
        Some(user) if user.password == *password => {
            let cookie = core::auth::create_session_cookie(
                &user.username,
                &c.session_secret,
                c.session_ttl_seconds,
                core::auth::now_unix(),
            );
            let mut headers = HeaderMap::new();
            headers.insert(
                SET_COOKIE,
                HeaderValue::from_str(&cookie).expect("session cookie header value is valid"),
            );
            (headers, Redirect::to("/"))
        }
        _ => (HeaderMap::new(), Redirect::to("/auth/signin")),
    }
}

pub fn init_routes(router: Router<Context>) -> Router<Context> {
    router.route("/auth/signin", get(signin_get).post(signin_post))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutenroshi::db::{Database, Step};
    use crate::mutenroshi::utils::testing::{
        TEST_SESSION_SECRET, TEST_SESSION_TTL_SECONDS, TestContext, body_of, dispatch,
        dispatch_form, location_of, set_cookie_of, test_context,
    };
    use axum::http::{Method, StatusCode};

    const SIGNIN_DATABASE: &str =
        "file:mutenroshi-auth-routes-signin-test?mode=memory&cache=shared";

    fn execute(database: &Database, sql: &str) {
        let mut statement = database.prepare(sql).expect("failed to prepare test SQL");
        assert_eq!(statement.step(), Ok(Step::Done));
        statement.finalize();
    }

    fn app_with_registered_user(username: &str, password: &str) -> (Router, Database) {
        let setup =
            Database::open_rw(SIGNIN_DATABASE).expect("failed to open signin test database");
        execute(
            &setup,
            "CREATE TABLE auth_user (username TEXT PRIMARY KEY, password TEXT NOT NULL)",
        );
        execute(
            &setup,
            &format!(
                "INSERT INTO auth_user (username, password) VALUES ('{username}', '{password}')"
            ),
        );
        let context = Context::open(
            SIGNIN_DATABASE,
            TEST_SESSION_SECRET.as_bytes().to_vec(),
            TEST_SESSION_TTL_SECONDS,
        )
        .expect("failed to open signin test context");

        (init_routes(Router::new()).with_state(context), setup)
    }

    fn app() -> (Router, TestContext) {
        let c = test_context();
        (init_routes(Router::new()).with_state(c.context.clone()), c)
    }

    #[tokio::test]
    async fn signin_get_serves_the_signin_template() {
        let Html(body) = signin_get().await;

        assert_eq!(body, SIGNIN_TEMPLATE);
    }

    #[tokio::test]
    async fn signin_post_redirects_to_signin_without_form_values() {
        let c = test_context();
        let (headers, redirect) = signin_post(State(c.context.clone()), Form(HashMap::new())).await;

        assert!(headers.get(SET_COOKIE).is_none());
        assert_eq!(redirect.status_code(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn signin_route_serves_the_template_on_get() {
        let (app, _context) = app();
        let response = dispatch(app, Method::GET, "/auth/signin").await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, SIGNIN_TEMPLATE);
    }

    #[tokio::test]
    async fn signin_route_uses_form_values_on_post() {
        let (app, _context) = app();
        let response =
            dispatch_form(app, "/auth/signin", "username=absent&password=incorrect").await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location_of(&response), "/auth/signin");
        assert!(response.headers().get(SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn signin_route_sets_a_signed_session_cookie_on_successful_signin() {
        let (app, mut setup) = app_with_registered_user("alice", "correct horse");
        let response =
            dispatch_form(app, "/auth/signin", "username=alice&password=correct horse").await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location_of(&response), "/");

        let set_cookie = set_cookie_of(&response);
        let (name_and_token, attributes) = set_cookie
            .split_once(';')
            .expect("cookie header has attributes");
        let (cookie_name, token) = name_and_token
            .split_once('=')
            .expect("cookie header has a name=value pair");

        assert_eq!(cookie_name, core::auth::SESSION_COOKIE_NAME);
        assert!(attributes.contains("HttpOnly"));
        assert!(attributes.contains("SameSite=Strict"));
        assert!(attributes.contains("Path=/"));

        let session = core::auth::verify_session(
            token,
            TEST_SESSION_SECRET.as_bytes(),
            core::auth::now_unix(),
        )
        .expect("the issued cookie should verify");
        assert_eq!(session.username, "alice");

        setup.close();
    }

    #[tokio::test]
    async fn signin_route_rejects_an_unregistered_method() {
        let (app, _context) = app();
        let response = dispatch(app, Method::DELETE, "/auth/signin").await;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn an_unregistered_path_is_not_found() {
        let (app, _context) = app();
        let response = dispatch(app, Method::GET, "/auth/absent").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
