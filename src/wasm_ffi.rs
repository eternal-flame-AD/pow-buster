use alloc::string::String;
use core::num::NonZeroU8;

use wasm_bindgen::prelude::*;

use crate::solver::{SOLVE_TYPE_LT, Solver};

#[wasm_bindgen(js_namespace = console)]
extern "C" {
    fn log(s: &str);
}

#[wasm_bindgen(js_name = "AnubisResponse")]
#[derive(Debug, Clone)]
pub struct AnubisResponse {
    delay: u32,
    nonce: u64,
    response: String,
    attempted_nonces: u64,
}

#[wasm_bindgen]
impl AnubisResponse {
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
pub fn solve_anubis(input: &[u8], difficulty_factor: u8) -> Option<AnubisResponse> {
    let target = crate::compute_target_anubis(NonZeroU8::new(difficulty_factor).unwrap());
    let ((nonce, result), attempted_nonces) = crate::message::DecimalMessage::new(input, 0)
        .and_then(|message| {
            let mut solver = crate::DecimalSolver::from(message);
            Some((
                solver.solve::<{ SOLVE_TYPE_LT }>(target, !0)?,
                solver.get_attempted_nonces(),
            ))
        })?;

    let mut response = [0u8; 64];
    crate::encode_hex(&mut response, result);

    Some(AnubisResponse {
        delay: 0,
        nonce,
        response: unsafe { alloc::string::String::from_utf8_unchecked(response.to_vec()) },
        attempted_nonces,
    })
}

#[wasm_bindgen]
pub fn solve_anubis_json(input: &str) -> Result<AnubisResponse, JsError> {
    let descriptor: crate::adapter::AnubisChallengeDescriptor = serde_json::from_str(input)?;

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
        delay: descriptor.delay() as u32,
        nonce,
        response: unsafe { alloc::string::String::from_utf8_unchecked(response.to_vec()) },
        attempted_nonces,
    })
}
