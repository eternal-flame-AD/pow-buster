use alloc::string::{String, ToString};

use wasm_bindgen::prelude::*;

use crate::solver::Solver;

#[wasm_bindgen(js_namespace = console)]
extern "C" {
    fn log(s: &str);
}

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

#[wasm_bindgen]
pub fn solve_json(input: &str) -> Result<AnubisResponse, JsError> {
    if let Ok(descriptor) =
        serde_json::from_str::<crate::adapter::CerberusChallengeDescriptor>(input)
    {
        return solve_cerberus_json(&descriptor);
    } else if let Ok(descriptor) =
        serde_json::from_str::<crate::adapter::AnubisChallengeDescriptor>(input)
    {
        return solve_anubis_json(&descriptor);
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
) -> Result<AnubisResponse, JsError> {
    let mut solver = crate::CerberusSolver::from(descriptor.build_msg().unwrap());

    let result = solver.solve::<{ crate::solver::SOLVE_TYPE_MASK }>(0, descriptor.mask() as u64);

    let Some((nonce, result)) = result else {
        return Err(JsError::new("solver failed"));
    };

    let mut response = [0u8; 64];
    crate::encode_hex_le(&mut response, result);
    Ok(AnubisResponse {
        subtype: "cerberus",
        delay: 0,
        nonce,
        response: unsafe { alloc::string::String::from_utf8_unchecked(response.to_vec()) },
        attempted_nonces: solver.get_attempted_nonces(),
    })
}
