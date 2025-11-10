use alloc::string::{String, ToString};

use wasm_bindgen::prelude::*;

use crate::solver::Solver;

#[wasm_bindgen(js_name = "AnubisResponse")]
#[derive(Debug, Clone)]
pub struct AnubisResponse {
    subtype: &'static str,
    delay: u32,
    nonce: u64,
    response: String,
    attempted_nonces: u64,
}

#[wasm_bindgen]
impl AnubisResponse {
    #[wasm_bindgen(getter)]
    pub fn subtype(&self) -> String {
        self.subtype.to_string()
    }
    #[wasm_bindgen(getter)]
    pub fn response(&self) -> String {
        self.response.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
    #[wasm_bindgen(getter)]
    pub fn delay(&self) -> u32 {
        self.delay
    }
    #[wasm_bindgen(getter)]
    pub fn attempted_nonces(&self) -> u64 {
        self.attempted_nonces
    }
}

#[wasm_bindgen(js_name = "CerberusWorkerResponse")]
#[derive(Debug, Clone)]
struct CerberusWorkerResponse {
    hash: String,
    nonce: u64,
}

#[wasm_bindgen]
impl CerberusWorkerResponse {
    #[wasm_bindgen(getter)]
    pub fn hash(&self) -> String {
        self.hash.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
}

#[wasm_bindgen]
pub fn solve_json(input: &str) -> Result<AnubisResponse, JsError> {
    if let Ok(descriptor) =
        serde_json::from_str::<crate::adapter::CerberusChallengeDescriptor>(input)
    {
        return solve_cerberus_json(&descriptor, None);
    } else if let Ok(descriptor) =
        serde_json::from_str::<crate::adapter::AnubisChallengeDescriptor>(input)
    {
        return solve_anubis_json(&descriptor);
    } else {
        return Err(JsError::new("invalid descriptor"));
    };
}

#[wasm_bindgen]
pub fn solve_json_set(input: &str, set: u32, iterand: u32) -> Result<AnubisResponse, JsError> {
    if let Ok(descriptor) =
        serde_json::from_str::<crate::adapter::CerberusChallengeDescriptor>(input)
    {
        return solve_cerberus_json(&descriptor, Some((set, iterand)));
    } else {
        return Err(JsError::new("invalid descriptor"));
    };
}

fn solve_anubis_json(
    descriptor: &crate::adapter::AnubisChallengeDescriptor,
) -> Result<AnubisResponse, JsError> {
    if !descriptor.supported() {
        return Err(JsError::new(
            "unsupported algorithm (please choose one of fast, slow, preact)",
        ));
    }

    let (result, attempted_nonces) = descriptor.solve();

    let Some((nonce, result)) = result else {
        return Err(JsError::new("solver failed"));
    };

    let mut response = [0u8; 64];
    crate::encode_hex(&mut response, result);
    Ok(AnubisResponse {
        subtype: "anubis",
        delay: descriptor.delay() as u32,
        nonce,
        response: unsafe { alloc::string::String::from_utf8_unchecked(response.to_vec()) },
        attempted_nonces,
    })
}

fn solve_cerberus_json(
    descriptor: &crate::adapter::CerberusChallengeDescriptor,
    fixed_set: Option<(u32, u32)>,
) -> Result<AnubisResponse, JsError> {
    let mut starting_set = 0;
    let mut loop_iterand = 1;
    let mut msg = descriptor
        .build_msg(0)
        .ok_or_else(|| JsError::new("invalid challenge"))?;
    if let Some((set, iterand)) = fixed_set {
        starting_set = set;
        loop_iterand = iterand;
        msg = descriptor
            .build_msg(set)
            .ok_or_else(|| JsError::new("reached maximum supported inner parallelism"))?;
    }
    let mut solver = crate::CerberusSolver::from(msg);

    for next_working_set in (starting_set..).step_by(loop_iterand as usize).skip(1) {
        let result =
            solver.solve::<{ crate::solver::SOLVE_TYPE_MASK }>(0, descriptor.mask() as u64);

        let Some((nonce, result)) = result else {
            msg = descriptor
                .build_msg(next_working_set)
                .ok_or_else(|| JsError::new("search exhausted"))?;
            solver = crate::CerberusSolver::from(msg);
            continue;
        };

        let mut response = [0u8; 64];
        crate::encode_hex_le(&mut response, result);
        return Ok(AnubisResponse {
            subtype: "cerberus",
            delay: 0,
            nonce,
            response: unsafe { alloc::string::String::from_utf8_unchecked(response.to_vec()) },
            attempted_nonces: solver.get_attempted_nonces(),
        });
    }

    Err(JsError::new("search exhausted"))
}
