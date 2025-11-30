use std::{fmt::Write, sync::LazyLock};

use reqwest::Client;
use url::form_urlencoded;

use crate::{
    Align16, adapter, compute_mask_goaway, compute_target_mcaptcha,
    message::{DecimalMessage, GoAwayMessage},
    solver::{SOLVE_TYPE_GT, SOLVE_TYPE_MASK, Solver},
};

struct Selectors {
    meta_refresh: scraper::Selector,
    anubis_base_prefix: scraper::Selector,
    anubis_challenge: scraper::Selector,
    challenge_script: scraper::Selector,
}

static SELECTORS: LazyLock<Selectors> = LazyLock::new(|| Selectors {
    meta_refresh: scraper::Selector::parse("meta[http-equiv='refresh' i]")
        .map_err(|_| SolveError::ScrapeElementNotFound("meta[http-equiv='refresh' i]"))
        .unwrap(),
    anubis_base_prefix: scraper::Selector::parse("script#anubis_base_prefix")
        .map_err(|_| SolveError::ScrapeElementNotFound("anubis_base_prefix"))
        .unwrap(),
    anubis_challenge: scraper::Selector::parse("script#anubis_challenge")
        .map_err(|_| SolveError::ScrapeElementNotFound("anubis_challenge"))
        .unwrap(),
    challenge_script: scraper::Selector::parse(
        "script[src^='/.within.website/x/cmd/anubis/static/js/main.mjs']",
    )
    .map_err(|_| {
        SolveError::ScrapeElementNotFound(
            "script[src^='/.within.website/x/cmd/anubis/static/js/main.mjs']",
        )
    })
    .unwrap(),
});

static DEFAULT_USER_AGENT_VALUE_BUF_LEN: ([u8; 256], usize) = {
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
    // Anubis (and derivatives) by default only challenges UAs that look like browsers
    // so a Mozilla magic word is need for the challenge to appear out of the box
    let tag = b"NotAMozilla";
    while i < 256 && j < tag.len() {
        buf[i] = tag[j];
        j += 1;
        i += 1;
    }
    buf[i] = b')';
    i += 1;
    (buf, i)
};

#[cfg(feature = "client")]
const DEFAULT_USER_AGENT: &str = unsafe {
    std::str::from_utf8_unchecked(core::slice::from_raw_parts(
        DEFAULT_USER_AGENT_VALUE_BUF_LEN.0.as_ptr(),
        DEFAULT_USER_AGENT_VALUE_BUF_LEN.1,
    ))
};

#[cfg(feature = "client")]
static OVERRIDE_USER_AGENT: std::sync::LazyLock<Option<String>> = std::sync::LazyLock::new(|| {
    std::env::var("POW_BUSTER_USER_AGENT")
        .or_else(|_| std::env::var("USER_AGENT"))
        .ok()
});

/// Start building a client suitable for use for end-to-end PoW solving.
///
/// This client is configured to:
/// - not follow redirects
/// - use the default user agent or whatever is set in the `POW_BUSTER_USER_AGENT` or `USER_AGENT` environment variable
/// - support transparent gzip compression
pub fn build_client() -> reqwest::ClientBuilder {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(OVERRIDE_USER_AGENT.as_deref().unwrap_or(DEFAULT_USER_AGENT))
        .gzip(true)
}

#[derive(Debug, thiserror::Error)]
/// PoW Client Error
pub enum SolveError {
    #[error("broken redirect")]
    /// broken redirect
    BrokenRedirect,
    #[error("unknown algorithm: {0}")]
    /// unknown algorithm
    UnknownAlgorithm(String),
    #[error("unexpected challenge format")]
    /// unexpected challenge format
    UnexpectedChallengeFormat,
    #[error("not implemented")]
    /// not implemented
    NotImplemented,
    #[error("cookie not found")]
    /// cookie not found
    CookieNotFound,
    #[error("golden ticket not found")]
    /// golden ticket not found
    GoldenTicketNotFound,
    #[error("solver failed")]
    /// solver failed
    SolverFailed,
    #[error("cross origin redirect")]
    /// cross origin redirect
    CrossOriginRedirect,
    #[error("scrape element not found: {0}")]
    /// scrape element not found
    ScrapeElementNotFound(&'static str),
    #[error("invalid url: {0}")]
    /// invalid url
    InvalidUrl(#[from] url::ParseError),
    #[error(transparent)]
    /// json error
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    /// reqwest error
    Reqwest(#[from] reqwest::Error),
    #[error("unexpected status when requesting work: {0}: {1}")]
    /// unexpected status when requesting work
    UnexpectedStatusRequest(reqwest::StatusCode, String),
    #[error("unexpected status when sending work: {0}: {1}")]
    /// unexpected status when sending work
    UnexpectedStatusSend(reqwest::StatusCode, String),
}

/// Solve a mCaptcha PoW.
pub async fn solve_mcaptcha(
    pool: &rayon::ThreadPool,
    client: &Client,
    base_url: &str,
    site_key: &str,
) -> Result<String, SolveError> {
    solve_mcaptcha_ex(pool, client, base_url, site_key, &mut 0).await
}

/// Solve a Cap.js PoW.
pub async fn solve_capjs(
    pool: &rayon::ThreadPool,
    client: &Client,
    base_url: &str,
    site_key: &str,
) -> Result<
    (
        adapter::capjs::CapJsResponse,
        adapter::capjs::SolveCapJsResponseMeta,
    ),
    SolveError,
> {
    let mut url_buf = format!("{}/{}/challenge", base_url.trim_end_matches('/'), site_key);
    let challenge: adapter::capjs::ChallengeDescriptor = client
        .post(&url_buf)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let solution = challenge.solve_with_limit_parallel(pool, u64::MAX);
    tx.send(solution).unwrap();
    let (result, _) = rx.await.unwrap();
    let Some(solution) = result else {
        return Err(SolveError::SolverFailed);
    };

    url_buf.truncate(url_buf.len() - "challenge".len());
    url_buf.push_str("redeem");

    Ok((
        client
            .post(&url_buf)
            .json(&solution)
            .send()
            .await?
            .json()
            .await?,
        solution.meta,
    ))
}

/// Solve a Cap.js PoW in a worker.
pub async fn solve_capjs_worker(
    pool: &rayon::ThreadPool,
    client: &Client,
    base_url: &str,
    site_key: &str,
    time_iowait: &mut u32,
    semaphore: &tokio::sync::Semaphore,
) -> Result<
    (
        adapter::capjs::CapJsResponse,
        adapter::capjs::SolveCapJsResponseMeta,
    ),
    SolveError,
> {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    let mut forwarded_for = *b"fe00:0000:0000::";
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let counter_bytes = counter.to_be_bytes();
    for i in 0..2 {
        let low_nibble = counter_bytes[i] & 0x0f;
        let high_nibble = counter_bytes[i] >> 4;
        forwarded_for[5 + i * 2] = if high_nibble < 10 {
            b'0' + high_nibble
        } else {
            b'a' + high_nibble - 10
        };
        forwarded_for[5 + i * 2 + 1] = if low_nibble < 10 {
            b'0' + low_nibble
        } else {
            b'a' + low_nibble - 10
        };
    }
    for i in 0..2 {
        let low_nibble = counter_bytes[2 + i] & 0x0f;
        let high_nibble = counter_bytes[2 + i] >> 4;
        forwarded_for[10 + i * 2] = if high_nibble < 10 {
            b'0' + high_nibble
        } else {
            b'a' + high_nibble - 10
        };
        forwarded_for[10 + i * 2 + 1] = if low_nibble < 10 {
            b'0' + low_nibble
        } else {
            b'a' + low_nibble - 10
        };
    }

    let mut url_buf = format!("{}/{}/challenge", base_url.trim_end_matches('/'), site_key);
    let iotime = std::time::Instant::now();
    let challenge: adapter::capjs::ChallengeDescriptor = client
        .post(&url_buf)
        .header("Content-Type", "application/json")
        .header("X-Forwarded-For", unsafe {
            std::str::from_utf8_unchecked(&forwarded_for)
        })
        .body("{}")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let iotime = iotime.elapsed();
    *time_iowait += iotime.as_micros() as u32;

    let (tx, rx) = tokio::sync::oneshot::channel();
    {
        let _permit = semaphore.acquire().await.unwrap();
        pool.spawn(move || {
            let solution = challenge.solve();
            tx.send(solution).unwrap();
        });
    }
    let (result, _) = rx.await.unwrap();
    let Some(solution) = result else {
        return Err(SolveError::SolverFailed);
    };

    url_buf.truncate(url_buf.len() - "challenge".len());
    url_buf.push_str("redeem");

    let iotime = std::time::Instant::now();
    let resp = client
        .post(&url_buf)
        .header("X-Forwarded-For", unsafe {
            std::str::from_utf8_unchecked(&forwarded_for)
        })
        .json(&solution)
        .send()
        .await?
        .json()
        .await?;
    let iotime = iotime.elapsed();
    *time_iowait += iotime.as_micros() as u32;
    Ok((resp, solution.meta))
}

/// Solve a mcaptcha live.
///
/// If `really_solve` is false, the solver will not be used and a dummy nonce and result will be returned.
/// This is useful for testing and benchmarking.
pub async fn solve_mcaptcha_ex(
    pool: &rayon::ThreadPool,
    client: &Client,
    base_url: &str,
    site_key: &str,
    time_iowait: &mut u32,
) -> Result<String, SolveError> {
    let url_get_work = format!("{}/api/v1/pow/config", base_url);
    let iotime = std::time::Instant::now();
    let res = client
        .post(url_get_work)
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "key": site_key,
        }))
        .send()
        .await?;
    let iotime = iotime.elapsed();
    *time_iowait += iotime.as_micros() as u32;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await?;
        return Err(SolveError::UnexpectedStatusRequest(status, body));
    }
    let config: adapter::mcaptcha::PoWConfig = res.json().await?;

    let mut prefix = Vec::new();
    crate::build_mcaptcha_prefix(&mut prefix, &config.string, &config.salt);
    let target = compute_target_mcaptcha(config.difficulty_factor as u64);

    let (nonce, result) = {
        let (tx, rx) = tokio::sync::oneshot::channel();

        pool.spawn(move || {
            let mut result = None;
            for search_bank in 0.. {
                let Some(message) = DecimalMessage::new(&prefix, search_bank) else {
                    break;
                };
                let mut solver: crate::DecimalSolver = message.into();
                result = solver.solve::<{ SOLVE_TYPE_GT }>(target, !0);
                if result.is_some() {
                    break;
                }
            }
            tx.send(result).ok();
        });

        rx.await.unwrap().ok_or(SolveError::SolverFailed)?
    };

    let work = adapter::mcaptcha::Work {
        string: config.string,
        result: crate::extract128_be(result).to_string(),
        nonce,
        key: site_key,
    };
    let url_send_work = format!("{}/api/v1/pow/verify", base_url);

    #[derive(Clone, serde::Deserialize, Debug)]
    struct TokenResponse {
        token: String,
    }

    let iotime = std::time::Instant::now();
    let res = client
        .post(url_send_work)
        .header("Accept", "application/json")
        .json(&work)
        .send()
        .await?;
    let iotime = iotime.elapsed();
    *time_iowait += iotime.as_micros() as u32;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await?;
        return Err(SolveError::UnexpectedStatusSend(status, body));
    }
    let token: TokenResponse = res.json().await?;

    Ok(token.token)
}

/// Solve an Anubis PoW.
pub async fn solve_anubis(client: &Client, base_url: &str) -> Result<String, SolveError> {
    solve_anubis_ex(client, base_url, &mut 0).await
}

/// Solve an Anubis PoW with extended functionality.
///
/// `time_iowait` is a pointer to a u32 that will be incremented by the time spent waiting for the IO instead of solving the PoW.
#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "info", skip(client, time_iowait))
)]
pub async fn solve_anubis_ex(
    client: &Client,
    base_url: &str,
    time_iowait: &mut u32,
) -> Result<String, SolveError> {
    #[derive(Debug)]
    struct DocumentPresentation {
        base_prefix: Option<String>,
        meta_refresh: Option<String>,
        anubis_challenge: Option<String>,
    }

    let url_parsed = url::Url::parse(base_url)?;

    let iotime = std::time::Instant::now();
    let mut response: reqwest::Response = client
        .get(base_url)
        .header("Accept", "text/html")
        .header("Sec-Gpc", "1")
        .send()
        .await?;
    let mut redirects = 5u32;
    while response.status().is_redirection() && redirects > 0 {
        redirects -= 1;
        let location = response
            .headers()
            .get("Location")
            .and_then(|location| location.to_str().ok())
            .ok_or(SolveError::BrokenRedirect)?;
        response = client
            .get(location)
            .header("Accept", "text/html")
            .header("Sec-Gpc", "1")
            .send()
            .await?;
    }
    if response.status().is_redirection() {
        return Err(SolveError::BrokenRedirect);
    }
    let iotime = iotime.elapsed();
    *time_iowait += iotime.as_micros() as u32;

    let return_cookie = response
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str().eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| v.to_str().unwrap().split(';').next())
        .filter(|v| {
            (v.contains("-cookie-verification") || v.contains("if-you-block-this"))
                && !v.ends_with("=")
        })
        .next()
        .map(|s| s.to_string());

    let selectors = &*SELECTORS;

    let document_presentation = if let Some(refresh_header) = response
        .headers()
        .get("refresh")
        .and_then(|refresh| refresh.to_str().ok())
    {
        DocumentPresentation {
            base_prefix: None,
            meta_refresh: Some(refresh_header.to_string()),
            anubis_challenge: None,
        }
    } else {
        let text = response.text().await?;
        let document = scraper::Html::parse_document(&text);
        let base_prefix = document
            .select(&selectors.anubis_base_prefix)
            .next()
            .map(|element| serde_json::from_str(&element.text().collect::<String>()))
            .transpose()?;

        let meta_refresh = document
            .select(&selectors.meta_refresh)
            .next()
            .and_then(|meta| meta.attr("content"))
            .map(|s| s.to_string());
        let anubis_challenge = document
            .select(&selectors.anubis_challenge)
            .next()
            .map(|element| element.text().collect::<String>());
        if meta_refresh.is_none()
            && anubis_challenge.is_none()
            && document
                .select(&selectors.challenge_script)
                .next()
                .is_none()
        {
            #[cfg(feature = "tracing")]
            {
                tracing::warn!("no challenge found");
            }
            return Ok(String::new());
        }

        DocumentPresentation {
            base_prefix,
            meta_refresh,
            anubis_challenge,
        }
    };

    #[cfg(feature = "tracing")]
    {
        tracing::debug!("document presentation: {:?}", document_presentation);
    }

    let (final_url, delay) = match document_presentation {
        DocumentPresentation {
            meta_refresh: Some(ref meta_refresh),
            ..
        } => {
            let (dur, mut url) = meta_refresh
                .split_once(|c| c == ';' || c == ',')
                .unwrap_or((meta_refresh, ""));

            // MDN: fraction part is ignored
            let (dur_int, _rest) = dur.split_once('.').unwrap_or((dur, ""));

            let dur_int = dur_int
                .parse::<u32>()
                .map_err(|_| SolveError::UnexpectedChallengeFormat)?
                .saturating_sub(1);

            url = url.trim();

            if url.len() > 4 && url[..4].eq_ignore_ascii_case("url=") {
                url = url[4..].trim();
            }

            (url_parsed.join(url)?, dur_int as u64 * 900)
        }
        DocumentPresentation {
            base_prefix,
            anubis_challenge: json_text,
            meta_refresh: None,
        } => {
            let json_text = match json_text {
                Some(json_text) => json_text,
                None => {
                    let make_challenge_url =
                        url_parsed.join("/.within.website/x/cmd/anubis/api/make-challenge")?;
                    let response: reqwest::Response = client
                        .post(make_challenge_url)
                        .header("Accept", "application/json")
                        .header("Sec-Gpc", "1")
                        .send()
                        .await?;
                    response.text().await?
                }
            };
            let challenge: adapter::anubis::ChallengeDescriptor = serde_json::from_str(&json_text)?;

            #[cfg(feature = "tracing")]
            {
                tracing::info!(
                    algorithm = challenge.rules().algorithm(),
                    estimated_workload = challenge.estimated_workload(),
                    "Anubis cryptographic challenge",
                );
            }

            if !challenge.supported() {
                return Err(SolveError::UnknownAlgorithm(
                    challenge.rules().algorithm().to_string(),
                ));
            }
            let (result, attempted_nonces) = tokio::task::block_in_place(|| challenge.solve());

            let (nonce, result) = result.ok_or(SolveError::SolverFailed)?;

            #[cfg(feature = "tracing")]
            {
                tracing::info!(
                    nonce = nonce,
                    attempted_nonces = attempted_nonces,
                    "solver finished",
                );
            }

            let plausible_time = crate::compute_plausible_time_sha256(attempted_nonces) + 10;

            let mut response_hex = [0u8; 64];
            crate::encode_hex(&mut response_hex, result);

            let mut final_url = format!(
                "{}://{}",
                url_parsed.scheme(),
                url_parsed.host_str().unwrap(),
            );
            if let Some(port) = url_parsed.port() {
                write!(final_url, ":{}", port).unwrap();
            }
            if let Some(base_prefix) = base_prefix {
                write!(final_url, "{}", base_prefix.trim_end_matches('/')).unwrap();
            }
            write!(
                final_url,
                "/.within.website/x/cmd/anubis/api/pass-challenge?elapsedTime={}&{}=",
                plausible_time,
                challenge.hash_result_key()
            )
            .unwrap();

            final_url
                .write_str(&unsafe { std::str::from_utf8_unchecked(&response_hex) })
                .unwrap();

            if let Some(id) = challenge.challenge().id() {
                write!(final_url, "&id={}", id).unwrap();
            }
            write!(final_url, "&nonce={}&redir=", nonce).unwrap();
            let redir_encoder = url::form_urlencoded::byte_serialize(base_url.as_bytes());
            redir_encoder.for_each(|b| {
                final_url.push_str(b);
            });

            (url::Url::parse(&final_url)?, challenge.delay())
        }
    };

    if url_parsed.origin() != final_url.origin() {
        return Err(SolveError::CrossOriginRedirect);
    }

    // on non PoW protected challenges, Anubis enforces a delay, wait for it
    if delay > 0 {
        #[cfg(feature = "tracing-subscriber")]
        {
            tracing::info!("Applying Anubis server-enforced delay: {}ms", delay);
        }
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
    }

    let iotime = std::time::Instant::now();
    let mut golden_request = client.get(final_url);
    if let Some(cookie) = return_cookie.clone() {
        golden_request = golden_request.header("Cookie", cookie);
    }
    let golden_response = golden_request
        .header("Accept", "text/html")
        .header("Referer", base_url)
        .header("Sec-Gpc", "1")
        .send()
        .await?;
    let iotime = iotime.elapsed();
    *time_iowait += iotime.as_micros() as u32;

    if golden_response.status().is_client_error() || golden_response.status().is_server_error() {
        let status = golden_response.status();
        let body = golden_response.text().await?;
        return Err(SolveError::UnexpectedStatusRequest(status, body));
    }

    let auth_cookie = golden_response
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str().eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| v.to_str().unwrap().split(';').next())
        // some adopters like to pick a fight with user-centric "bypass add-ons" for some reason
        // ref: https://git.gay/49016/NoPoW/issues/5
        // eyJhbGci is base64 '{"alg"'
        .filter(|v| v.contains("=eyJhbGci"))
        .next()
        .ok_or(SolveError::GoldenTicketNotFound)?
        .to_string();

    Ok(auth_cookie)
}

/// Solve a Cerberus PoW.
pub async fn solve_cerberus(client: &Client, base_url: &str) -> Result<String, SolveError> {
    solve_cerberus_ex(client, base_url, &mut 0).await
}

/// Solve a Cerberus PoW.
///
/// `time_iowait` is a pointer to a u32 that will be incremented by the time spent waiting for the IO instead of solving the PoW.
pub async fn solve_cerberus_ex(
    client: &Client,
    base_url: &str,
    time_iowait: &mut u32,
) -> Result<String, SolveError> {
    let url_parsed = url::Url::parse(base_url)?;

    let iotime = std::time::Instant::now();
    let mut response = client
        .get(base_url)
        .header("Accept", "text/html")
        .header("Sec-Gpc", "1")
        .send()
        .await?;
    let mut redirects = 5u32;
    while response.status().is_redirection() && redirects > 0 {
        redirects -= 1;
        let location = response
            .headers()
            .get("Location")
            .and_then(|location| location.to_str().ok())
            .ok_or(SolveError::BrokenRedirect)?;
        response = client
            .get(location)
            .header("Accept", "text/html")
            .header("Sec-Gpc", "1")
            .send()
            .await?;
    }
    if response.status().is_redirection() {
        return Err(SolveError::BrokenRedirect);
    }
    let iotime = iotime.elapsed();
    *time_iowait += iotime.as_micros() as u32;

    fn extract_challenge(
        base_url: &url::Url,
        body: &str,
    ) -> Result<(String, adapter::cerberus::ChallengeDescriptor), SolveError> {
        static ELEMENT_CHALLENGE_SCRIPT: LazyLock<scraper::Selector> = LazyLock::new(|| {
            scraper::Selector::parse("script#challenge-script[x-challenge]")
                .map_err(|_| {
                    SolveError::ScrapeElementNotFound("script#challenge-script[x-challenge]")
                })
                .unwrap()
        });
        let document = scraper::Html::parse_document(&body);

        let element = document.select(&ELEMENT_CHALLENGE_SCRIPT).next().ok_or(
            SolveError::ScrapeElementNotFound("script#challenge-script[x-challenge]"),
        )?;
        let json_text = element
            .attr("x-challenge")
            .ok_or(SolveError::ScrapeElementNotFound(
                "script#challenge-script[x-challenge]",
            ))?;
        let meta = element
            .attr("x-meta")
            .ok_or(SolveError::ScrapeElementNotFound(
                "script#challenge-script[x-meta]",
            ))?;

        #[derive(serde::Deserialize, Debug)]
        struct Meta {
            #[serde(rename = "baseURL")]
            base_url: String,
        }
        let meta: Meta = serde_json::from_str(&meta)?;
        let mut challenge: adapter::cerberus::ChallengeDescriptor =
            serde_json::from_str(&json_text)?;
        if let Some(version) = element
            .attr("src")
            .and_then(|src| base_url.join(src).ok())
            .and_then(|url| {
                url.query_pairs()
                    .find(|(k, _)| k == "v")
                    .and_then(|(_, v)| v.trim_start_matches('v').parse::<semver::Version>().ok())
            })
        {
            challenge.set_version(version);
        }

        Ok((meta.base_url, challenge))
    }

    let text = response.text().await?;
    let (mut answer_url, challenge) = extract_challenge(&url_parsed, &text)?;
    answer_url.push_str("/answer");
    let mask = challenge.mask();
    let (nonce, result) = tokio::task::block_in_place(|| {
        let mut msg = challenge.build_msg(0)?;
        for next_working_set in 1.. {
            let mut solver = crate::CerberusSolver::from(msg);
            let result = solver.solve::<{ crate::solver::SOLVE_TYPE_MASK }>(0, mask as u64);
            if let Some(res) = result {
                return Some(res);
            }
            msg = challenge.build_msg(next_working_set)?;
        }
        None
    })
    .ok_or(SolveError::SolverFailed)?;

    let mut response_hex = [0u8; 64];
    crate::encode_hex_le(&mut response_hex, result);

    let final_url = url_parsed.join(&answer_url)?;

    if url_parsed.origin() != final_url.origin() {
        return Err(SolveError::CrossOriginRedirect);
    }

    let body = form_urlencoded::Serializer::new(String::with_capacity(256))
        .append_pair("response", &unsafe {
            std::str::from_utf8_unchecked(&response_hex)
        })
        .append_pair("solution", &nonce.to_string())
        .append_pair("nonce", &challenge.nonce().to_string())
        .append_pair("ts", &challenge.ts().to_string())
        .append_pair("signature", challenge.signature())
        .append_pair("redir", "/")
        .finish();

    let iotime = std::time::Instant::now();
    let golden_response = client
        .post(final_url)
        .body(body)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "text/html")
        .header("Referer", base_url)
        .header("Sec-Gpc", "1")
        .send()
        .await?;
    let iotime = iotime.elapsed();
    *time_iowait += iotime.as_micros() as u32;

    if golden_response.status().is_client_error() || golden_response.status().is_server_error() {
        let status = golden_response.status();
        let body = golden_response.text().await?;
        return Err(SolveError::UnexpectedStatusRequest(status, body));
    }
    let auth_cookie = golden_response
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str().eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| v.to_str().unwrap().split(';').next())
        .filter(|v| v.contains("cerberus-auth") && !v.ends_with('='))
        .next()
        .ok_or(SolveError::GoldenTicketNotFound)?
        .to_string();

    Ok(auth_cookie)
}

/// Solve a GoAway "js-pow-sha256" PoW.
pub async fn solve_goaway_js_pow_sha256(
    client: &Client,
    base_url: &str,
) -> Result<String, SolveError> {
    let base_url = url::Url::parse(base_url)?;
    let make_challenge_url = base_url.join("/.well-known/.git.gammaspectra.live/git/go-away/cmd/go-away/challenge/js-pow-sha256/make-challenge")?;
    let res = client
        .post(make_challenge_url)
        .header("Accept", "application/json")
        .header("Sec-Gpc", "1")
        .header(
            "User-Agent",
            "Mozilla/5.0 (Android 15; Mobile; rv:140.0) Gecko/140.0 Firefox/140.0",
        )
        .send()
        .await?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await?;
        return Err(SolveError::UnexpectedStatusRequest(status, body));
    }
    let config: adapter::goaway::GoAwayConfig = res.json().await?;

    let mask = compute_mask_goaway(config.difficulty());

    let estimated_workload = 1u64 << config.difficulty().get();

    let (nonce, result) = tokio::task::block_in_place(|| {
        let mut solver = crate::GoAwaySolver::from(
            config
                .challenge()
                .as_bytes()
                .try_into()
                .ok()
                .and_then(|x| GoAwayMessage::new_hex(x, 0))
                .or_else(|| {
                    config
                        .challenge()
                        .as_bytes()
                        .try_into()
                        .ok()
                        .map(|x| GoAwayMessage::new_bytes(x, 0))
                })
                .ok_or(SolveError::UnexpectedChallengeFormat)?,
        );
        solver
            .solve::<{ SOLVE_TYPE_MASK }>(0, mask)
            .ok_or(SolveError::SolverFailed)
    })?;

    let plausible_time = crate::compute_plausible_time_sha256(estimated_workload) + 10;

    let mut goaway_token = Align16([b'0'; 64 + 8 * 2]);
    goaway_token[..64].copy_from_slice(config.challenge().as_bytes());
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
    // this doesn't do anything, just make something up for the request ID
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

    let mut url_send_work = base_url.join("/.well-known/.git.gammaspectra.live/git/go-away/cmd/go-away/challenge/js-pow-sha256/verify-challenge")?.to_string();
    write!(
        url_send_work,
        "?__goaway_ElapsedTime={}&__goaway_challenge=js-pow-sha256&__goaway_redirect={}://{}/&__goaway_token={}&__goaway_id={}",
        plausible_time,
        base_url.scheme(),
        base_url.host_str().unwrap(),
        unsafe { std::str::from_utf8_unchecked(&goaway_token[..]) },
        unsafe { std::str::from_utf8_unchecked(&goaway_id[..]) },
    )
    .unwrap();

    let golden_response = client
        .get(url_send_work)
        .header("Accept", "text/html")
        .header("Sec-Gpc", "1")
        .header(
            "User-Agent",
            "Mozilla/5.0 (Android 15; Mobile; rv:140.0) Gecko/140.0 Firefox/140.0",
        )
        .send()
        .await?;

    if golden_response.status().is_client_error() || golden_response.status().is_server_error() {
        let status = golden_response.status();
        let body = golden_response.text().await?;
        return Err(SolveError::UnexpectedStatusRequest(status, body));
    }
    let auth_cookie = golden_response
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str().eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| v.to_str().unwrap().split(';').next())
        .filter(|v| v.starts_with(".go-away"))
        .next()
        .ok_or(SolveError::GoldenTicketNotFound)?
        .to_string();

    Ok(auth_cookie)
}
