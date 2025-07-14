use core::num::NonZeroU8;
use std::fmt::Write;

use reqwest::Client;

use crate::{Align16, Solver, compute_target, compute_target_anubis, compute_target_goaway};

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct PoWConfig {
    pub string: String,
    pub difficulty_factor: u32,
    pub salt: String,
}

#[derive(Clone, serde::Serialize, Debug)]
pub struct Work<'a> {
    pub string: String,
    pub result: String,
    pub nonce: u64,
    pub key: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum SolveError {
    #[error("unknown algorithm: {0}")]
    UnknownAlgorithm(String),
    #[error("not implemented")]
    NotImplemented,
    #[error("cookie not found")]
    CookieNotFound,
    #[error("golden ticket not found")]
    GoldenTicketNotFound,
    #[error("solver failed")]
    SolverFailed,
    #[error("scrape element not found: {0}")]
    ScrapeElementNotFound(&'static str),
    #[error("invalid url: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error("unexpected status when requesting work: {0}: {1}")]
    UnexpectedStatusRequest(reqwest::StatusCode, String),
    #[error("unexpected status when sending work: {0}: {1}")]
    UnexpectedStatusSend(reqwest::StatusCode, String),
}

/// Solve a mcaptcha live.
///
/// If `really_solve` is false, the solver will not be used and a dummy nonce and result will be returned.
/// This is useful for testing and benchmarking.
pub async fn solve_mcaptcha(
    pool: &rayon::ThreadPool,
    client: &Client,
    base_url: &str,
    site_key: &str,
    really_solve: bool,
) -> Result<String, SolveError> {
    let url_get_work = format!("{}/api/v1/pow/config", base_url);
    let res = client
        .post(url_get_work)
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "key": site_key,
        }))
        .send()
        .await?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await?;
        return Err(SolveError::UnexpectedStatusRequest(status, body));
    }
    let config: PoWConfig = res.json().await?;

    let mut prefix = Vec::new();
    crate::build_prefix(&mut prefix, &config.string, &config.salt);
    let target_bytes = compute_target(config.difficulty_factor).to_be_bytes();
    let target_u32s = core::array::from_fn(|i| {
        u32::from_be_bytes([
            target_bytes[i * 4],
            target_bytes[i * 4 + 1],
            target_bytes[i * 4 + 2],
            target_bytes[i * 4 + 3],
        ])
    });

    let (nonce, result) = if really_solve {
        let (tx, rx) = tokio::sync::oneshot::channel();

        // these length needs to be double-hashed
        if (47..=52).contains(&prefix.len()) {
            pool.spawn(move || {
                let mut solver = crate::DoubleBlockSolver16Way::new((), &prefix).unwrap();
                let result = solver.solve::<true>(target_u32s);
                tx.send(result).ok();
            });
        } else {
            pool.spawn(move || {
                let mut solver = crate::SingleBlockSolver16Way::new((), &prefix).unwrap();
                let result = solver.solve::<true>(target_u32s);
                tx.send(result).ok();
            });
        }

        rx.await.unwrap().ok_or(SolveError::SolverFailed)?
    } else {
        Default::default()
    };

    let work = Work {
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

    let res = client
        .post(url_send_work)
        .header("Accept", "application/json")
        .json(&work)
        .send()
        .await?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await?;
        return Err(SolveError::UnexpectedStatusSend(status, body));
    }
    let token: TokenResponse = res.json().await?;

    Ok(token.token)
}

#[derive(serde::Deserialize, Debug)]
struct AnubisChallengeDescriptor {
    challenge: String,
    rules: AnubisRules,
}

#[derive(serde::Deserialize, Debug)]
struct AnubisRules {
    algorithm: String,
    difficulty: u8,
}

pub async fn solve_anubis(
    client: &Client,
    base_url: &str,
    really_solve: bool,
) -> Result<String, SolveError> {
    let url_parsed = url::Url::parse(base_url)?;
    let response: reqwest::Response = client
        .get(base_url)
        .header("Accept", "text/html")
        .header("Sec-Gpc", "1")
        .header(
            "User-Agent",
            "Mozilla/5.0 (Android 15; Mobile; rv:140.0) Gecko/140.0 Firefox/140.0",
        )
        .send()
        .await?
        .error_for_status()?;

    let return_cookie = response
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str().eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| v.to_str().unwrap().split(';').next())
        .filter(|v| v.contains("-anubis-") && !v.ends_with("="))
        .next()
        .ok_or(SolveError::CookieNotFound)?
        .to_string();

    fn extract_challenge(body: &str) -> Result<AnubisChallengeDescriptor, SolveError> {
        let document = scraper::Html::parse_document(&body);
        let selector = scraper::Selector::parse("script#anubis_challenge")
            .map_err(|_| SolveError::ScrapeElementNotFound("anubis_challenge"))?;
        let element = document
            .select(&selector)
            .next()
            .ok_or(SolveError::ScrapeElementNotFound("anubis_challenge"))?;
        let json_text = element.text().collect::<String>();
        let challenge: AnubisChallengeDescriptor = serde_json::from_str(&json_text)?;

        Ok(challenge)
    }

    let challenge = extract_challenge(&response.text().await?)?;
    if !["fast", "slow"].contains(&challenge.rules.algorithm.as_str()) {
        return Err(SolveError::UnknownAlgorithm(challenge.rules.algorithm));
    }
    let target = compute_target_anubis(challenge.rules.difficulty.try_into().unwrap());
    let target_bytes = target.to_be_bytes();
    let target_u32s = core::array::from_fn(|i| {
        u32::from_be_bytes([
            target_bytes[i * 4],
            target_bytes[i * 4 + 1],
            target_bytes[i * 4 + 2],
            target_bytes[i * 4 + 3],
        ])
    });
    let estimated_workload = 16u64.pow(challenge.rules.difficulty as u32);
    let (nonce, result) = if really_solve {
        // AFAIK as of now there is no way to configure Anubis to require the double solver
        let mut solver =
            crate::SingleBlockSolver16Way::new((), challenge.challenge.as_bytes()).unwrap();
        let result = solver.solve::<false>(target_u32s);
        result.ok_or(SolveError::SolverFailed)?
    } else {
        (0, [0; 8])
    };

    // about 100kH/s
    let plausible_time = estimated_workload / 1024;

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
    write!(
        final_url,
        "/.within.website/x/cmd/anubis/api/pass-challenge?elapsedTime={}&response=",
        plausible_time
    )
    .unwrap();

    final_url
        .write_str(&unsafe { std::str::from_utf8_unchecked(&response_hex) })
        .unwrap();
    write!(final_url, "&nonce={}&redir=", nonce).unwrap();
    let redir_encoder = url::form_urlencoded::byte_serialize(base_url.as_bytes());
    redir_encoder.for_each(|b| {
        final_url.push_str(b);
    });

    let golden_response = client
        .get(final_url)
        .header("Accept", "text/html")
        .header("Cookie", return_cookie.clone())
        .header("Referer", base_url)
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
        .filter(|v| v.contains("-anubis-auth") && !v.ends_with('='))
        .next()
        .ok_or(SolveError::GoldenTicketNotFound)?
        .to_string();

    Ok(auth_cookie)
}

#[derive(serde::Deserialize, Debug)]
struct GoAwayConfig {
    challenge: String,
    // target: String,
    difficulty: NonZeroU8,
}

pub async fn solve_goaway_js_pow_sha256(
    client: &Client,
    base_url: &str,
    really_solve: bool,
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
    let config: GoAwayConfig = res.json().await?;

    let mut solver = crate::GoAwaySolver16Way::new((), &config.challenge.as_bytes()).unwrap();
    let target_bytes = compute_target_goaway(config.difficulty).to_be_bytes();
    let target_u32s = core::array::from_fn(|i| {
        let i = i * 4;
        u32::from_be_bytes([
            target_bytes[i],
            target_bytes[i + 1],
            target_bytes[i + 2],
            target_bytes[i + 3],
        ])
    });

    let estimated_workload = 1u64 << config.difficulty.get();

    let (nonce, result) = if really_solve {
        tokio::task::block_in_place(|| {
            let solve_begin = std::time::Instant::now();
            let result = solver.solve::<false>(target_u32s);
            let Some(result) = result else {
                return Err(SolveError::SolverFailed);
            };
            let elapsed = solve_begin.elapsed();
            eprintln!(
                "solve time: {:?} ({:.2} MH/s)",
                elapsed,
                result.0 as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0
            );
            Ok(result)
        })?
    } else {
        Default::default()
    };

    let plausible_time = estimated_workload / 1024;

    let mut goaway_token = Align16([b'0'; 64 + 8 * 2]);
    goaway_token[..64].copy_from_slice(config.challenge.as_bytes());
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
