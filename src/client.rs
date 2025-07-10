use std::fmt::Write;

use reqwest::Client;

use crate::{Solver, compute_target, compute_target_anubis};

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
        .filter(|v| v.contains("-anubis-cookie-verification="))
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
        "/.within.website/x/cmd/anubis/api/pass-challenge?redir=/&elapsedTime={}&response=",
        plausible_time
    )
    .unwrap();

    final_url
        .write_str(&unsafe { std::str::from_utf8_unchecked(&response_hex) })
        .unwrap();
    write!(final_url, "&nonce={}", nonce).unwrap();

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
        .filter(|v| v.contains("-anubis-auth=") && !v.ends_with('='))
        .next()
        .ok_or(SolveError::GoldenTicketNotFound)?
        .to_string();

    Ok(auth_cookie)
}

#[cfg(feature = "wgpu")]
pub async fn solve_mcaptcha_wgpu(
    ctx: &mut crate::wgpu::VulkanDeviceContext,
    client: &Client,
    base_url: &str,
    site_key: &str,
    really_solve: bool,
) -> Result<String, SolveError> {
    use typenum::U256;

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
    let mut solver = crate::wgpu::VulkanSingleBlockSolver::<U256>::new(ctx, &prefix)
        .ok_or(SolveError::NotImplemented)?;
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
        tokio::task::block_in_place(|| {
            let solve_begin = std::time::Instant::now();
            let result = solver.solve::<true>(target_u32s);
            eprintln!("solve time: {:?}", solve_begin.elapsed());
            result.ok_or(SolveError::SolverFailed)
        })?
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
