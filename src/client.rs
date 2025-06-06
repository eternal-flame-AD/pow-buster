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
) -> anyhow::Result<String> {
    let url_get_work = format!("{}/api/v1/pow/config", base_url);
    let res = client
        .post(url_get_work)
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "key": site_key,
        }))
        .send()
        .await?;
    let config: PoWConfig = res.json().await?;

    let mut prefix = Vec::new();
    crate::build_prefix(&mut prefix, &config.string, &config.salt)?;
    let mut solver =
        crate::SingleBlockSolver::new(&prefix).ok_or(anyhow::anyhow!("solver is None"))?;
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
        pool.install(|| solver.solve(target_u32s))
            .ok_or(anyhow::anyhow!("solver failed"))?
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
        return Err(anyhow::anyhow!(
            "Failed to solve mcaptcha, unexpected status: {}: {}",
            status,
            body
        ));
    }
    let token: TokenResponse = res.json().await?;

    Ok(token.token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_solve_mcaptcha() {
        let client = Client::new();
        let base_url = "https://captcha.whimsies.org";
        let site_key = "mZbWXbEBfEJKeKaTZ8JE9xUgwIneDGP2";
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let token = solve_mcaptcha(&pool, &client, base_url, site_key, true)
            .await
            .unwrap();
        println!("token: {}", token);
    }
}
