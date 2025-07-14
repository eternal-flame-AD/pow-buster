use core::fmt::Write;
use std::sync::Arc;

use axum::{
    Form, Json, Router,
    body::Body,
    extract::{Request, State},
    http::HeaderValue,
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use reqwest::StatusCode;
use tokio::sync::Semaphore;

use crate::client::AnubisChallengeDescriptor;

async fn index() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}

#[derive(Clone)]
pub struct AppState {
    pool: Arc<rayon::ThreadPool>,
    semaphore: Arc<Semaphore>,
    limit: u32,
}

impl AppState {
    pub fn new(n_threads: usize, limit: u32) -> Self {
        Self {
            pool: Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(n_threads)
                    .thread_name(|idx| format!("solver-{}", idx))
                    .build()
                    .unwrap(),
            ),
            semaphore: Arc::new(Semaphore::new(n_threads)),
            limit,
        }
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/", get(index))
            .route("/solve/anubis", post(solve_anubis))
            .layer(tower_http::limit::RequestBodyLimitLayer::new(128 << 10))
            .layer(
                tower_http::trace::TraceLayer::new_for_http()
                    .make_span_with(tower_http::trace::DefaultMakeSpan::new())
                    .on_request(
                        tower_http::trace::DefaultOnRequest::new().level(tracing::Level::INFO),
                    )
                    .on_response(
                        tower_http::trace::DefaultOnResponse::new()
                            .level(tracing::Level::INFO)
                            .latency_unit(tower_http::LatencyUnit::Micros),
                    ),
            )
            .layer(tower_http::timeout::TimeoutLayer::new(
                std::time::Duration::from_secs(5),
            ))
            .layer(tower_http::catch_panic::CatchPanicLayer::new())
            .layer(axum::middleware::from_fn(add_headers))
            .with_state(self.clone())
    }

    pub fn router_with_origin_check(&self, expected_origin: url::Url) -> Router {
        self.router().layer(axum::middleware::from_fn_with_state(
            Arc::new(expected_origin),
            check_origin,
        ))
    }
}

#[derive(serde::Deserialize)]
struct SolveAnubisForm {
    challenge: String,
}

#[derive(thiserror::Error, Debug)]
enum SolveError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("solver failed or server limit reached")]
    SolverFailed { limit: u32, attempted: u32 },

    #[error("solver fatal error")]
    SolverFatal,

    #[error("unexpected origin")]
    UnexpectedOrigin,
}

impl IntoResponse for SolveError {
    fn into_response(self) -> Response {
        #[derive(serde::Serialize)]
        struct Wrapper {
            code: u16,
            message: String,
        }
        let (code, message) = match self {
            SolveError::Json(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            SolveError::SolverFailed { limit, attempted } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "solver failed or server limit reached: limit: {}, attempted: {}",
                    limit, attempted
                ),
            ),
            SolveError::SolverFatal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "solver fatal error".to_string(),
            ),
            SolveError::UnexpectedOrigin => {
                (StatusCode::FORBIDDEN, "unexpected origin".to_string())
            }
        };
        (
            code,
            Json(Wrapper {
                code: code.as_u16(),
                message,
            }),
        )
            .into_response()
    }
}

#[tracing::instrument(skip(state, form), name = "solve_anubis")]
async fn solve_anubis(
    remote_addr: axum::extract::ConnectInfo<std::net::SocketAddr>,
    x_forwarded_for: axum_extra::TypedHeader<XForwardedFor>,
    State(state): State<AppState>,
    form: Form<SolveAnubisForm>,
) -> Result<String, SolveError> {
    let form = form.0;

    let left_strip = form.challenge.find('{').unwrap_or(0);
    let right_strip = form
        .challenge
        .rfind('}')
        .map(|x| x + 1)
        .unwrap_or(form.challenge.len());
    let challenge = &form.challenge[left_strip..right_strip];

    let descriptor: AnubisChallengeDescriptor = serde_json::from_str(challenge)?;

    let rules = descriptor.rules();
    tracing::info!("solving anubis challenge {:?}", rules);

    let ((result, attempted_nonces), elapsed) = {
        let _permit = state.semaphore.acquire().await.unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();
        state.pool.spawn(move || {
            let start = std::time::Instant::now();
            let result = descriptor.solve_with_limit(state.limit);
            let elapsed = start.elapsed();
            tx.send((result, elapsed)).ok();
        });

        rx.await.map_err(|_| SolveError::SolverFatal)?
    };

    let (nonce, result) = result.ok_or(SolveError::SolverFailed {
        limit: state.limit,
        attempted: attempted_nonces,
    })?;

    let plausible_time = attempted_nonces / 1024;

    let mut response_hex = [0u8; 64];
    crate::encode_hex(&mut response_hex, result);

    let mut final_url = format!(
        "/.within.website/x/cmd/anubis/api/pass-challenge?elapsedTime={}&response=",
        plausible_time
    );
    final_url
        .write_str(&unsafe { std::str::from_utf8_unchecked(&response_hex) })
        .unwrap();
    write!(final_url, "&nonce={}&redir=", nonce).unwrap();

    let hash_rate_mhs = attempted_nonces as f32 / elapsed.as_secs_f32() / 1024.0 / 1024.0;
    let limit_used = attempted_nonces as f32 / state.limit as f32 * 100.0;

    tracing::info!(
        "solver completed in {}ms; nonce: {}; hash rate: {:.2} MH/s; limit used: {:.2}%",
        elapsed.as_millis(),
        nonce,
        hash_rate_mhs,
        limit_used,
    );

    let mut output = format!(
        "# elapsed time: {}ms; attempted nonces: {}; {:.2} MH/s; {:.2}% limit used",
        elapsed.as_millis(),
        attempted_nonces,
        hash_rate_mhs,
        limit_used
    )
    .into_bytes();

    output.extend_from_slice(b"\r\nwindow.location.replace(");
    // This only fails for non trivial types, for string it is infallible
    serde_json::to_writer(&mut output, &final_url).unwrap();
    output.extend_from_slice(b" + encodeURIComponent(window.location.href));");

    Ok(String::from_utf8(output).unwrap())
}

async fn add_headers(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'none'; form-action 'self'"),
    );
    response
}

async fn check_origin(
    method: axum::http::Method,
    State(expected_origin): State<Arc<url::Url>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if method.is_safe() {
        return next.run(req).await;
    }
    let Some(origin) = req.headers().get("Origin") else {
        return SolveError::UnexpectedOrigin.into_response();
    };
    let Ok(origin) = origin.to_str() else {
        return SolveError::UnexpectedOrigin.into_response();
    };
    let Ok(parsed) = url::Url::parse(origin) else {
        return SolveError::UnexpectedOrigin.into_response();
    };
    if parsed.host_str() != expected_origin.host_str() {
        return SolveError::UnexpectedOrigin.into_response();
    }
    if parsed.port_or_known_default() != expected_origin.port_or_known_default() {
        return SolveError::UnexpectedOrigin.into_response();
    }
    if parsed.scheme() != expected_origin.scheme() {
        return SolveError::UnexpectedOrigin.into_response();
    }
    next.run(req).await
}

#[derive(Debug)]
struct XForwardedFor(Vec<std::net::IpAddr>);

impl headers::Header for XForwardedFor {
    fn name() -> &'static headers::HeaderName {
        static NAME: headers::HeaderName = headers::HeaderName::from_static("x-forwarded-for");
        &NAME
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let mut result = Vec::new();
        for value in values {
            let Ok(value) = value.to_str() else {
                return Err(headers::Error::invalid());
            };
            result.extend(
                value
                    .split(',')
                    .filter_map(|x| x.trim().parse::<std::net::IpAddr>().ok()),
            );
        }
        Ok(XForwardedFor(result))
    }

    fn encode<E>(&self, _values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        unimplemented!()
    }
}
