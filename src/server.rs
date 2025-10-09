use core::fmt::Write;
use std::sync::Arc;

use axum::{
    Form, Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, header::ACCEPT},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::response::JavaScript;
use headers::Header;
use tokio::sync::Semaphore;

use crate::{
    Align16, CerberusSolver, DecimalSolver,
    adapter::{
        AnubisChallengeDescriptor, CapJsChallengeDescriptor, CerberusChallengeDescriptor,
        GoAwayConfig, SolveCapJsResponse,
    },
    compute_target_anubis,
    message::DecimalMessage,
    solver::{SOLVE_TYPE_LT, SOLVE_TYPE_MASK, Solver},
};

#[cfg(feature = "server-wasm")]
mod assets {
    use axum::response::{IntoResponse, Response};

    #[derive(rust_embed::Embed)]
    #[folder = "pkg/"]
    pub struct WasmAssets;

    pub struct StaticFile<T>(pub T);

    impl<T> IntoResponse for StaticFile<T>
    where
        T: Into<String>,
    {
        fn into_response(self) -> Response {
            let path = self.0.into();

            match WasmAssets::get(path.as_str()) {
                Some(content) => {
                    let mime = content.metadata.mimetype();
                    ([("Content-Type", mime)], content.data).into_response()
                }
                None => (axum::http::StatusCode::NOT_FOUND, "404 Not Found").into_response(),
            }
        }
    }
}

async fn index() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}

async fn serve_worker() -> JavaScript<&'static str> {
    JavaScript(include_str!("static/worker.js"))
}

#[derive(Clone)]
/// Server app state
pub struct AppState {
    pool: Arc<rayon::ThreadPool>,
    semaphore: Arc<Semaphore>,
    limit: u64,
}

struct Accept(u8);

impl Accept {
    const MASK_GZIP: u8 = 1 << 0;

    fn gzip(&self) -> bool {
        self.0 & Self::MASK_GZIP != 0
    }
}

impl Header for Accept {
    fn name() -> &'static headers::HeaderName {
        &ACCEPT
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let mut mask = 0;
        for value in values {
            let Ok(value) = value.to_str() else {
                continue;
            };

            for key in value.split(',') {
                let key = key.trim();
                if key == "gzip" {
                    mask |= Self::MASK_GZIP;
                }
            }
        }
        Ok(Accept(mask))
    }

    fn encode<E>(&self, _values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        unimplemented!()
    }
}

#[cfg(feature = "server-wasm")]
async fn serve_wasm(
    axum::extract::Path(mut file): axum::extract::Path<String>,
    axum_extra::TypedHeader(accept): axum_extra::TypedHeader<Accept>,
) -> Response {
    use assets::{StaticFile, WasmAssets};

    let mut content_encoding = None;
    if file == "index.txt" {
        let mut index = String::new();
        WasmAssets::iter().for_each(|entry| {
            writeln!(index, "{}", entry.as_ref()).unwrap();
        });
        return (
            axum::http::StatusCode::OK,
            [("Content-Type", "text/plain")],
            index,
        )
            .into_response();
    } else if accept.gzip() && file.ends_with(".wasm") {
        file.push_str(".gz");
        content_encoding = Some("gzip");
    }
    let mut response = StaticFile(file).into_response();
    if let Some(content_encoding) = content_encoding {
        response.headers_mut().insert(
            "Content-Encoding",
            HeaderValue::from_static(content_encoding),
        );
    }
    response
}

#[cfg(not(feature = "server-wasm"))]
async fn serve_wasm(
    axum::extract::Path(_file): axum::extract::Path<String>,
    axum_extra::TypedHeader(_accept): axum_extra::TypedHeader<Accept>,
) -> Response {
    (axum::http::StatusCode::NOT_FOUND, "404 Not Found").into_response()
}

impl AppState {
    /// creates a new app state
    pub fn new(n_threads: usize, limit: u64) -> Self {
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

    /// returns the effective limit clamped to supported range
    pub const fn effective_limit(&self) -> u64 {
        let cap = match cfg!(feature = "compare-64bit") {
            true => u64::MAX,
            false => u32::MAX as u64,
        };
        if self.limit > cap { cap } else { self.limit }
    }

    /// returns the router
    pub fn router(&self) -> Router {
        Router::new()
            .route("/", get(index))
            .route("/worker.js", get(serve_worker))
            .route("/solve", post(solve_generic))
            .route("/pkg/{*file}", get(serve_wasm))
            .route("/api/anubis_offload", post(anubis_offload_api))
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
            .layer(tower_http::catch_panic::CatchPanicLayer::new())
            .layer(axum::middleware::from_fn(add_headers))
            .with_state(self.clone())
    }

    /// returns the router with origin check
    pub fn router_with_origin_check(&self, expected_origin: url::Url) -> Router {
        self.router().layer(axum::middleware::from_fn_with_state(
            Arc::new(expected_origin),
            check_origin,
        ))
    }
}

#[derive(serde::Deserialize)]
struct SolveForm {
    challenge: String,
}

#[derive(thiserror::Error, Debug)]
enum SolveError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("solver failed or server limit reached")]
    SolverFailed { limit: u64, attempted: u64 },

    #[error("estimated workload is greater than server limit")]
    EstimatedWorkloadGreaterThanLimit { limit: u64, estimated: u64 },

    #[error("solver fatal error")]
    SolverFatal,

    #[error("unexpected origin")]
    UnexpectedOrigin,

    #[error("invalid challenge")]
    InvalidChallenge,

    #[error("unexpected challenge format")]
    UnexpectedChallengeFormat,
}

impl IntoResponse for SolveError {
    fn into_response(self) -> Response {
        #[derive(serde::Serialize)]
        struct Wrapper {
            code: u16,
            #[serde(rename = "type")]
            ty: &'static str,
            message: String,
        }
        let (code, message, ty) = match self {
            SolveError::Json(e) => (axum::http::StatusCode::BAD_REQUEST, e.to_string(), "json"),
            SolveError::SolverFailed { limit, attempted } => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "solver failed or server limit reached: limit: {}, attempted: {}",
                    limit, attempted
                ),
                "solver_failed",
            ),
            SolveError::SolverFatal => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "solver fatal error".to_string(),
                "solver_fatal",
            ),
            SolveError::UnexpectedOrigin => (
                axum::http::StatusCode::FORBIDDEN,
                "unexpected origin".to_string(),
                "unexpected_origin",
            ),
            SolveError::InvalidChallenge => (
                axum::http::StatusCode::BAD_REQUEST,
                "invalid challenge".to_string(),
                "invalid_challenge",
            ),
            SolveError::UnexpectedChallengeFormat => (
                axum::http::StatusCode::NOT_IMPLEMENTED,
                "unexpected challenge format".to_string(),
                "unexpected_challenge_format",
            ),
            SolveError::EstimatedWorkloadGreaterThanLimit { limit, estimated } => (
                axum::http::StatusCode::BAD_REQUEST,
                format!(
                    "estimated workload is greater than server limit: limit: {}, estimated: {}",
                    limit, estimated
                ),
                "estimated_workload_greater_than_limit",
            ),
        };
        (
            code,
            Json(Wrapper {
                code: code.as_u16(),
                ty,
                message,
            }),
        )
            .into_response()
    }
}

async fn solve_generic(
    remote_addr: axum::extract::ConnectInfo<std::net::SocketAddr>,
    x_forwarded_for: axum_extra::TypedHeader<XForwardedFor>,
    state: State<AppState>,
    form: Form<SolveForm>,
) -> Result<Response, SolveError> {
    let form = form.0;

    let left_strip = form.challenge.find('{').unwrap_or(0);
    let right_strip = form
        .challenge
        .rfind('}')
        .map(|x| x + 1)
        .unwrap_or(form.challenge.len());
    let challenge = &form.challenge[left_strip..right_strip];

    if let Ok(config) = serde_json::from_str(challenge) {
        return solve_anubis(remote_addr, x_forwarded_for, state, config)
            .await
            .map(IntoResponse::into_response);
    }

    // Cerberus challenge format is a subtype of go-away, so it has to come before it
    if let Ok(config) = serde_json::from_str(challenge) {
        return solve_cerberus(remote_addr, x_forwarded_for, state, config)
            .await
            .map(IntoResponse::into_response);
    }

    if let Ok(config) = serde_json::from_str(challenge) {
        return solve_goaway(remote_addr, x_forwarded_for, state, config)
            .await
            .map(IntoResponse::into_response);
    }

    if let Ok(config) = serde_json::from_str(challenge) {
        return solve_capjs(remote_addr, x_forwarded_for, state, config)
            .await
            .map(IntoResponse::into_response);
    }

    if let Ok(config) = serde_json::from_str(challenge) {
        return solve_gotosocial(remote_addr, x_forwarded_for, state, config)
            .await
            .map(IntoResponse::into_response);
    }

    Err(SolveError::InvalidChallenge)
}

#[derive(Debug, serde::Deserialize)]
/// A GoToSocial challenge descriptor
pub struct GoToSocialChallengeDescriptor {
    #[serde(rename = "nollamas_seed")]
    seed: String,
    #[serde(rename = "nollamas_challenge")]
    challenge: String,
}

#[tracing::instrument(skip(state, config), name = "solve_gotosocial")]
async fn solve_gotosocial(
    remote_addr: axum::extract::ConnectInfo<std::net::SocketAddr>,
    x_forwarded_for: axum_extra::TypedHeader<XForwardedFor>,
    State(state): State<AppState>,
    config: GoToSocialChallengeDescriptor,
) -> Result<String, SolveError> {
    #[cfg(target_feature = "avx512f")]
    use crate::solver::avx512::GoToSocialSolver;

    #[cfg(not(target_feature = "avx512f"))]
    use crate::solver::safe::GoToSocialSolver;

    tracing::info!("solving gotosocial challenge {:?}", config);
    use crate::message::GoToSocialMessage;

    let Ok(seed) = config.seed.as_bytes().try_into() else {
        return Err(SolveError::InvalidChallenge);
    };

    let message = GoToSocialMessage::new(seed);
    let target = GoToSocialSolver::extract_target(config.challenge.as_bytes()).unwrap();
    let _permit = state.semaphore.acquire().await.unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    state.pool.spawn(move || {
        let start = std::time::Instant::now();
        // this is limited to 500k supported nonces, takes about 5ms tops on AVX512
        #[cfg(target_feature = "avx512f")]
        let mut solver = GoToSocialSolver::new(crate::message::BUILT_IN_LUT_16_BUF_VIEW, message);
        #[cfg(not(target_feature = "avx512f"))]
        let mut solver = GoToSocialSolver::from(message);
        solver.set_max_nonce(state.limit);
        let solution =
            solver.solve_nonce_only::<{ crate::solver::SOLVE_TYPE_DH_PREIMAGE }>(target, u64::MAX);
        let elapsed = start.elapsed();
        tx.send((solution, solver.get_attempted_nonces(), elapsed))
            .ok();
    });

    let (solution, attempted_nonces, elapsed) = rx.await.unwrap();

    let Some(solution) = solution else {
        return Err(SolveError::SolverFailed {
            limit: {
                cfg_if::cfg_if! {
                    if #[cfg(target_feature = "avx512f")] {
                        state.limit.min(crate::message::BUILT_IN_LUT_16_BUF_VIEW.max_supported_nonce())
                    } else {
                        state.limit
                    }
                }
            },
            attempted: attempted_nonces,
        });
    };

    let mut response = String::new();
    writeln!(
        response,
        "// elapsed time: {}ms; attempted nonces: {}; {:.2} MH/s; {:.2}% limit used",
        elapsed.as_millis(),
        attempted_nonces,
        attempted_nonces as f32 / elapsed.as_secs_f32() / 1024.0 / 1024.0,
        attempted_nonces as f32 / state.limit as f32 * 100.0
    )
    .unwrap();
    writeln!(
        response,
        "const redirectURL = new URL(window.location.href);"
    )
    .unwrap();

    writeln!(
        response,
        "redirectURL.searchParams.set('nollamas_solution', '{}');",
        solution
    )
    .unwrap();

    writeln!(response, "window.location.replace(redirectURL.toString());").unwrap();

    Ok(response)
}

#[tracing::instrument(skip(state, config), name = "solve_cerberus")]
async fn solve_cerberus(
    remote_addr: axum::extract::ConnectInfo<std::net::SocketAddr>,
    x_forwarded_for: axum_extra::TypedHeader<XForwardedFor>,
    State(state): State<AppState>,
    config: CerberusChallengeDescriptor,
) -> Result<String, SolveError> {
    tracing::info!("solving cerberus challenge {:?}", config);

    let msg = config.build_msg().ok_or(SolveError::InvalidChallenge)?;
    let mask = config.mask();
    let estimated_workload = config.estimated_workload();
    let effective_limit = state.effective_limit().saturating_mul(2);
    if estimated_workload > effective_limit {
        return Err(SolveError::EstimatedWorkloadGreaterThanLimit {
            limit: effective_limit,
            estimated: estimated_workload,
        });
    }

    let begin = std::time::Instant::now();

    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::task::spawn_blocking(move || {
        let mut solver = CerberusSolver::from(msg);
        solver.set_limit(effective_limit);
        let Some((nonce, hash)) = solver.solve::<{ SOLVE_TYPE_MASK }>(0, mask as u64) else {
            tx.send(Err(SolveError::SolverFailed {
                limit: effective_limit,
                attempted: solver.get_attempted_nonces(),
            }))
            .ok();
            return;
        };
        let attempted_nonces = solver.get_attempted_nonces();

        tx.send(Ok((nonce, hash, attempted_nonces))).ok();
    });
    let (nonce, hash, attempted_nonces) = rx.await.map_err(|_| SolveError::SolverFatal)??;
    let elapsed = begin.elapsed();

    let mut output = String::with_capacity(4096);

    writeln!(
        output,
        "// elapsed time: {}ms; attempted nonces: {}; {:.2} MH/s; {:.2}% limit used",
        elapsed.as_millis(),
        attempted_nonces,
        attempted_nonces as f32 / elapsed.as_secs_f32() / 1024.0 / 1024.0,
        attempted_nonces as f32 / state.limit as f32 * 100.0
    )
    .unwrap();

    output.push_str(r#"
((hash,nonce) => {
    const thisScript = document.getElementById('challenge-script');
    function createAnswerForm(hash, solution, baseURL, nonce, ts, signature) {
        /* 
        Copyright (c) 2025 Yanning Chen <self@lightquantum.me>

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in
        all copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
        THE SOFTWARE.
        */

        function addHiddenInput(form, name, value) {
          const input = document.createElement('input');
          input.type = 'hidden';
          input.name = name;
          input.value = value;
          form.appendChild(input);
        }
      
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = `${baseURL}/answer`;
      
        addHiddenInput(form, 'response', hash);
        addHiddenInput(form, 'solution', solution);
        addHiddenInput(form, 'nonce', nonce);
        addHiddenInput(form, 'ts', ts);
        addHiddenInput(form, 'signature', signature);
        addHiddenInput(form, 'redir', window.location.href);
      
        document.body.appendChild(form);
        return form;
    }

    const { difficulty, nonce: inputNonce, ts, signature } = JSON.parse(thisScript.getAttribute('x-challenge'));
    const { baseURL } = JSON.parse(thisScript.getAttribute('x-meta'));
    createAnswerForm(hash, nonce, baseURL, inputNonce, ts, signature).submit();
})(""#);

    hash.into_iter().for_each(|x| {
        let sb = x.to_le_bytes();
        for i in 0..4 {
            let high_nibble = sb[i] >> 4;
            let low_nibble = sb[i] & 0x0f;
            output.push(if high_nibble < 10 {
                (b'0' + high_nibble) as char
            } else {
                (b'a' + high_nibble - 10) as char
            });
            output.push(if low_nibble < 10 {
                (b'0' + low_nibble) as char
            } else {
                (b'a' + low_nibble - 10) as char
            });
        }
    });
    writeln!(output, "\",{})", nonce).unwrap();

    Ok(output)
}

#[tracing::instrument(skip(state, config), name = "solve_capjs")]
async fn solve_capjs(
    remote_addr: axum::extract::ConnectInfo<std::net::SocketAddr>,
    x_forwarded_for: axum_extra::TypedHeader<XForwardedFor>,
    State(state): State<AppState>,
    config: CapJsChallengeDescriptor,
) -> Result<Json<SolveCapJsResponse>, SolveError> {
    tracing::info!("solving capjs challenge {:?}", config);

    let estimated_workload = config.estimated_workload();
    if estimated_workload > state.effective_limit() {
        return Err(SolveError::EstimatedWorkloadGreaterThanLimit {
            limit: state.effective_limit(),
            estimated: estimated_workload,
        });
    }

    let (result, attempted_nonces) = {
        let _permit = state.semaphore.acquire().await.unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();
        state.pool.spawn(move || {
            let result = config.solve_with_limit(state.limit);
            tx.send(result).ok();
        });

        rx.await.map_err(|_| SolveError::SolverFatal)?
    };

    let response = result.ok_or(SolveError::SolverFailed {
        limit: state.limit,
        attempted: attempted_nonces,
    })?;

    Ok(Json(response))
}

#[tracing::instrument(skip(state, config), name = "solve_goaway")]

async fn solve_goaway(
    remote_addr: axum::extract::ConnectInfo<std::net::SocketAddr>,
    x_forwarded_for: axum_extra::TypedHeader<XForwardedFor>,
    State(state): State<AppState>,
    config: GoAwayConfig,
) -> Result<String, SolveError> {
    tracing::info!("solving goaway challenge {:?}", config);

    if config.challenge().len() != 64 {
        return Err(SolveError::UnexpectedChallengeFormat);
    }

    let mut goaway_token = Align16([b'0'; 64 + 8 * 2]);
    goaway_token[..64].copy_from_slice(config.challenge().as_bytes());

    let estimated_workload = config.estimated_workload();
    if estimated_workload > state.effective_limit() {
        return Err(SolveError::EstimatedWorkloadGreaterThanLimit {
            limit: state.effective_limit(),
            estimated: estimated_workload,
        });
    }

    let ((result, attempted_nonces), elapsed) = {
        let _permit = state.semaphore.acquire().await.unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();
        state.pool.spawn(move || {
            let start = std::time::Instant::now();
            let result = config.solve_with_limit(state.limit);
            let elapsed = start.elapsed();
            tx.send((result, elapsed)).ok();
        });

        rx.await.map_err(|_| SolveError::SolverFatal)?
    };

    let (nonce, result) = result.ok_or(SolveError::SolverFailed {
        limit: state.limit,
        attempted: attempted_nonces,
    })?;

    let plausible_time = nonce / 1024;

    let nonce_bytes = nonce.to_be_bytes();
    for i in 0..8 {
        let high_nibble = nonce_bytes[i] >> 4;
        let low_nibble = nonce_bytes[i] & 0x0f;
        goaway_token[64 + i * 2] = if high_nibble < 10 {
            b'0' + high_nibble
        } else {
            b'a' + high_nibble - 10
        };
        goaway_token[64 + i * 2 + 1] = if low_nibble < 10 {
            b'0' + low_nibble
        } else {
            b'a' + low_nibble - 10
        };
    }

    let mut goaway_id = Align16([0; 32]);
    // this doesn't do anything, just make something up for the id
    for i in 0..4 {
        let result_bytes: [u8; 4] = result[i].to_ne_bytes();
        for j in 0..4 {
            let high_nibble = result_bytes[j] >> 4;
            let low_nibble = result_bytes[j] & 0x0f;
            goaway_id[(4 * i + j) * 2] = if high_nibble < 10 {
                b'0' + high_nibble
            } else {
                b'a' + high_nibble - 10
            };
            goaway_id[(4 * i + j) * 2 + 1] = if low_nibble < 10 {
                b'0' + low_nibble
            } else {
                b'a' + low_nibble - 10
            };
        }
    }

    let mut final_url = "/.well-known/.git.gammaspectra.live/git/go-away/cmd/go-away/challenge/js-pow-sha256/verify-challenge".to_string();
    write!(
        final_url,
        "?__goaway_ElapsedTime={}&__goaway_challenge=js-pow-sha256&__goaway_token={}&__goaway_id={}&__goaway_redirect=",
        plausible_time,
        unsafe { std::str::from_utf8_unchecked(&goaway_token[..]) },
        unsafe { std::str::from_utf8_unchecked(&goaway_id[..]) },
    )
    .unwrap();

    let hash_rate_mhs = nonce as f32 / elapsed.as_secs_f32() / 1024.0 / 1024.0;
    let limit_used = nonce as f32 / state.limit as f32 * 100.0;

    tracing::info!(
        "solver completed in {}ms; nonce: {}; hash rate: {:.2} MH/s; limit used: {:.2}%",
        elapsed.as_millis(),
        nonce,
        hash_rate_mhs,
        limit_used,
    );

    let mut output = format!(
        "// elapsed time: {}ms; attempted nonces: {}; {:.2} MH/s; {:.2}% limit used",
        elapsed.as_millis(),
        nonce,
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

#[derive(serde::Serialize)]
struct OffloadResponseMeta {
    elapsed: u64,
    attempted_nonces: u64,
}

#[derive(serde::Serialize)]
struct OffloadResponse {
    hash: String,
    data: String,
    difficulty: u8,
    nonce: String,
    #[serde(rename = "_meta")]
    meta: OffloadResponseMeta,
}

#[derive(serde::Deserialize)]
struct OffloadForm {
    data: String,
    difficulty: u8,
}

#[tracing::instrument(skip(state, form), name = "offload_api")]
async fn anubis_offload_api(
    State(state): State<AppState>,
    form: Json<OffloadForm>,
) -> Result<Json<OffloadResponse>, SolveError> {
    let form = form.0;

    let estimated_workload = 16u64.pow(form.difficulty as u32);
    if estimated_workload > state.effective_limit() {
        return Err(SolveError::EstimatedWorkloadGreaterThanLimit {
            limit: state.effective_limit(),
            estimated: estimated_workload,
        });
    }

    let target = compute_target_anubis(form.difficulty.try_into().unwrap());
    let target_bytes = target.to_be_bytes();
    let target_u64 = u64::from_be_bytes(target_bytes[..8].try_into().unwrap());

    let ((result, attempted_nonces), elapsed) = if form.difficulty <= 4
    /* 65536, takes more cycles to acquire the semaphore than just get the result */
    {
        let start = std::time::Instant::now();
        let mut solver = DecimalSolver::from(
            DecimalMessage::new(form.data.as_bytes(), 0).ok_or(SolveError::InvalidChallenge)?,
        );
        solver.set_limit(state.limit);
        let result = solver.solve::<{ SOLVE_TYPE_LT }>(target_u64, !0);
        let elapsed = start.elapsed();
        ((result, solver.get_attempted_nonces()), elapsed)
    } else {
        let _permit = state.semaphore.acquire().await.unwrap();

        let data_clone = form.data.clone();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut message =
            DecimalMessage::new(data_clone.as_bytes(), 0).ok_or(SolveError::InvalidChallenge)?;
        state.pool.spawn(move || {
            let start = std::time::Instant::now();
            let mut total_attempted_nonces = 0;
            for next_search_bank in 1.. {
                if state.limit <= total_attempted_nonces {
                    tx.send(((None, total_attempted_nonces), start.elapsed()))
                        .ok();
                    return;
                }

                let mut solver = DecimalSolver::from(message);
                solver.set_limit(state.limit);
                let result = solver.solve::<{ SOLVE_TYPE_LT }>(target_u64, !0);
                total_attempted_nonces += solver.get_attempted_nonces();
                if let Some((result, hash)) = result {
                    tx.send((
                        (Some((result, hash)), total_attempted_nonces),
                        start.elapsed(),
                    ))
                    .ok();
                    return;
                }
                message = match DecimalMessage::new(data_clone.as_bytes(), next_search_bank) {
                    Some(message) => message,
                    None => {
                        tx.send(((None, total_attempted_nonces), start.elapsed()))
                            .ok();
                        return;
                    }
                };
            }
            tx.send(((None, total_attempted_nonces), start.elapsed()))
                .ok();
        });

        rx.await.map_err(|_| SolveError::SolverFatal)?
    };

    let Some((nonce, hash)) = result else {
        return Err(SolveError::SolverFailed {
            limit: state.limit,
            attempted: attempted_nonces,
        });
    };

    let mut hash_hex = vec![0u8; 64];
    for i in 0..8 {
        let bytes = hash[i].to_be_bytes();
        for j in 0..4 {
            let high_nibble = bytes[j] >> 4;
            let low_nibble = bytes[j] & 0x0f;
            hash_hex[i * 8 + j * 2] = if high_nibble < 10 {
                b'0' + high_nibble
            } else {
                b'a' + high_nibble - 10
            };
            hash_hex[i * 8 + j * 2 + 1] = if low_nibble < 10 {
                b'0' + low_nibble
            } else {
                b'a' + low_nibble - 10
            };
        }
    }

    Ok(Json(OffloadResponse {
        meta: OffloadResponseMeta {
            elapsed: elapsed.as_millis() as u64,
            attempted_nonces,
        },
        hash: String::from_utf8_lossy(&hash_hex).to_string(),
        data: form.data.clone(),
        difficulty: form.difficulty,
        nonce: nonce.to_string(),
    }))
}

#[tracing::instrument(skip(state, descriptor), name = "solve_anubis")]
async fn solve_anubis(
    remote_addr: axum::extract::ConnectInfo<std::net::SocketAddr>,
    x_forwarded_for: axum_extra::TypedHeader<XForwardedFor>,
    State(state): State<AppState>,
    descriptor: AnubisChallengeDescriptor,
) -> Result<String, SolveError> {
    let rules = descriptor.rules();
    tracing::info!("solving anubis challenge {:?}", rules);

    let mut final_url = String::from("/.within.website/x/cmd/anubis/api/pass-challenge?");

    if let Some(id) = descriptor.challenge().id() {
        write!(final_url, "id={}&", id).unwrap();
    }

    let instant = rules.instant();
    let delay = descriptor.delay();

    let estimated_workload = descriptor.estimated_workload();
    if estimated_workload > state.effective_limit() {
        return Err(SolveError::EstimatedWorkloadGreaterThanLimit {
            limit: state.effective_limit(),
            estimated: estimated_workload,
        });
    }

    let ((result, attempted_nonces), elapsed) = if instant {
        let start = std::time::Instant::now();
        let result = descriptor.solve_with_limit(state.limit);
        let elapsed = start.elapsed();
        (result, elapsed)
    } else {
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

    let plausible_time = (attempted_nonces / 1024).max(delay + 100);

    write!(final_url, "elapsedTime={}&response=", plausible_time).unwrap();

    let mut response_hex = [0u8; 64];
    crate::encode_hex(&mut response_hex, result);

    final_url
        .write_str(&unsafe { std::str::from_utf8_unchecked(&response_hex) })
        .unwrap();
    write!(final_url, "&nonce={}", nonce).unwrap();
    final_url.write_str("&redir=").unwrap();

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
        "// elapsed time: {}ms; attempted nonces: {}; {:.2} MH/s; {:.2}% limit used",
        elapsed.as_millis(),
        attempted_nonces,
        hash_rate_mhs,
        limit_used
    )
    .into_bytes();

    if delay > 0 {
        use std::io::Write;
        write!(
            output,
            "\r\n// This challenge is delay-gated, you need to wait {}ms before you can submit your solution.",
            delay - elapsed.as_millis() as u64
        )
        .unwrap();
    }

    output.extend_from_slice(b"\r\nwindow.location.replace(");
    // This only fails for non trivial types, for string it is infallible
    serde_json::to_writer(&mut output, &final_url).unwrap();
    output.extend_from_slice(b" + encodeURIComponent(window.location.href));");

    Ok(String::from_utf8(output).unwrap())
}

static SERVER_HEADER_VALUE_BUF_LEN: ([u8; 256], usize) = {
    let mut buf = [0u8; 256];
    let mut i = 0;
    let cargo_pkg_name = env!("CARGO_PKG_NAME").as_bytes();
    let mut j = 0;
    while i < 256 && j < cargo_pkg_name.len() {
        buf[i] = cargo_pkg_name[j];
        j += 1;
        i += 1;
    }
    buf[i] = b'/';
    i += 1;
    j = 0;
    let cargo_pkg_version = env!("CARGO_PKG_VERSION").as_bytes();
    while i < 256 && j < cargo_pkg_version.len() {
        buf[i] = cargo_pkg_version[j];
        j += 1;
        i += 1;
    }
    buf[i] = b' ';
    i += 1;
    buf[i] = b'(';
    i += 1;
    j = 0;
    let solver_name = crate::SOLVER_NAME.as_bytes();
    while i < 256 && j < solver_name.len() {
        buf[i] = solver_name[j];
        j += 1;
        i += 1;
    }
    buf[i] = b')';
    i += 1;
    (buf, i)
};

async fn add_headers(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        "Server",
        HeaderValue::from_static(unsafe {
            std::str::from_utf8_unchecked(
                &SERVER_HEADER_VALUE_BUF_LEN.0[..SERVER_HEADER_VALUE_BUF_LEN.1],
            )
        }),
    );
    response.headers_mut().insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
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
#[allow(dead_code)]
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
