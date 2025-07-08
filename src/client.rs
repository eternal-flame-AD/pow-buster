use reqwest::Client;

use crate::{Solver, compute_target};

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
    #[error("not implemented")]
    NotImplemented,
    #[error("solver failed")]
    SolverFailed,
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

    let prefix = crate::build_prefix(&config.string, &config.salt).collect::<Vec<_>>();
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
                let result = solver.solve(target_u32s);
                tx.send(result).ok();
            });
        } else {
            pool.spawn(move || {
                let mut solver = crate::SingleBlockSolver16Way::new((), &prefix).unwrap();
                let result = solver.solve(target_u32s);
                tx.send(result).ok();
            });
        }

        rx.await.unwrap().ok_or(SolveError::SolverFailed)?
    } else {
        (0xdeadbeef, 0xdeadbeef)
    };

    let work = Work {
        string: config.string,
        result: result.to_string(),
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

    let prefix = crate::build_prefix(&config.string, &config.salt).collect::<Vec<_>>();
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
            let result = solver.solve(target_u32s);
            eprintln!("solve time: {:?}", solve_begin.elapsed());
            result.ok_or(SolveError::SolverFailed)
        })?
    } else {
        (0xdeadbeef, 0xdeadbeef)
    };

    let work = Work {
        string: config.string,
        result: result.to_string(),
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
