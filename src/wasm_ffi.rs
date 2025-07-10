use alloc::string::String;
use core::num::NonZeroU8;

use wasm_bindgen::prelude::*;

use crate::Solver;

#[wasm_bindgen(js_name = "AnubisResponse")]
#[derive(Debug, Clone)]
pub struct AnubisResponse {
    pub nonce: u64,
    response: String,
}

#[wasm_bindgen]
impl AnubisResponse {
    #[wasm_bindgen(getter)]
    pub fn response(&self) -> String {
        self.response.clone()
    }
}

#[wasm_bindgen]
pub fn solve_anubis(input: String, difficulty_factor: u8) -> Option<AnubisResponse> {
    let target = crate::compute_target_anubis(NonZeroU8::new(difficulty_factor).unwrap());
    let target_u32s = [
        (target >> 96) as u32,
        (target >> 64) as u32,
        (target >> 32) as u32,
        target as u32,
    ];
    let (nonce, result) = match crate::SingleBlockSolver16Way::new((), input.as_bytes()) {
        Some(mut solver) => solver.solve::<true>(target_u32s)?,
        None => {
            let mut solver = crate::DoubleBlockSolver16Way::new((), input.as_bytes()).unwrap();
            solver.solve::<true>(target_u32s)?
        }
    };
    let mut response = [0u8; 64];
    crate::encode_hex(&mut response, result);
    Some(AnubisResponse {
        nonce,
        response: unsafe { alloc::string::String::from_utf8_unchecked(response.to_vec()) },
    })
}
