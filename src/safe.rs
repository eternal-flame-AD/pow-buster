// this is a straight-forward implementation that is what I _think_ the official solution should have done with no dangerous or platform dependent optimizations
// it will use whatever sha2 crate uses (SHA-NI if available)
pub struct SingleBlockSolver {
    // the SHA-256 state A-H for all prefix bytes
    pub(crate) prefix_state: [u32; 8],

    // the message template for the final block
    pub(crate) message:
        sha2::digest::generic_array::GenericArray<u8, sha2::digest::generic_array::typenum::U64>,

    pub(crate) digit_index: usize,

    pub(crate) nonce_addend: u64,
}

impl crate::Solver for SingleBlockSolver {
    type Ctx = ();

    fn new(_ctx: Self::Ctx, mut prefix: &[u8]) -> Option<Self> {
        // construct the message buffer
        let mut prefix_state = crate::sha256::IV;
        let mut nonce_addend = 0u64;
        let mut complete_blocks_before = 0;

        // first consume all full blocks, this is shared so use scalar reference implementation
        while prefix.len() >= 64 {
            crate::sha256::digest_block(
                &mut prefix_state,
                &core::array::from_fn(|i| {
                    u32::from_be_bytes([
                        prefix[i * 4],
                        prefix[i * 4 + 1],
                        prefix[i * 4 + 2],
                        prefix[i * 4 + 3],
                    ])
                }),
            );
            prefix = &prefix[64..];
            complete_blocks_before += 1;
        }
        // if there is not enough room for 9 bytes of padding, '1's and then start a new block whenever possible
        // this avoids having to hash 2 blocks per iteration a naive solution would do
        if prefix.len() + 9 + 9 > 64 {
            let mut tmp_block = [0; 64];
            tmp_block[..prefix.len()].copy_from_slice(prefix);
            tmp_block[prefix.len()..].iter_mut().for_each(|b| {
                nonce_addend *= 10;
                nonce_addend += 1;
                *b = b'1';
            });
            nonce_addend = nonce_addend.checked_mul(1_000_000_000)?;
            complete_blocks_before += 1;
            prefix = &[];
            crate::sha256::digest_block(
                &mut prefix_state,
                &core::array::from_fn(|i| {
                    u32::from_be_bytes([
                        tmp_block[i * 4],
                        tmp_block[i * 4 + 1],
                        tmp_block[i * 4 + 2],
                        tmp_block[i * 4 + 3],
                    ])
                }),
            );
        }

        let mut message = sha2::digest::generic_array::GenericArray::default();
        let mut ptr = 0;
        message[..prefix.len()].copy_from_slice(prefix);
        ptr += prefix.len();
        let digit_index = ptr;

        // skip 9 zeroes, this is the part we will interpolate N into
        // the first 2 digits are used as the lane index (10 + (0..16)*(0..4), offset to avoid leading zeroes), this also keeps our proof plausible
        // the rest are randomly generated then broadcasted to all lanes
        // this gives us about 16e7 * 4 possible attempts, likely enough for any realistic deployment even on the highest difficulty
        // the fail rate would be pgeom(keySpace, 1/difficulty, lower=F) in R
        ptr += 9;

        // set up padding
        message[ptr] = 0x80;
        message[(64 - 8)..]
            .copy_from_slice(&((complete_blocks_before * 64 + ptr) as u64 * 8).to_be_bytes());

        Some(Self {
            prefix_state,
            message,
            digit_index,
            nonce_addend,
        })
    }

    fn solve<const UPWARDS: bool>(&mut self, target: [u32; 4]) -> Option<(u64, [u32; 8])> {
        // start from the blind-spot of the AVX-512 solution first
        for keyspace in [900_000_000..1_000_000_000, 100_000_000..900_000_000] {
            for key in keyspace {
                let mut key_copy = key;
                for i in (0..9).rev() {
                    self.message[self.digit_index + i] = (key_copy % 10) as u8 + b'0';
                    key_copy /= 10;
                }

                let mut state = self.prefix_state;
                sha2::compress256(&mut state, &[self.message]);

                let pass = if UPWARDS {
                    state[0] > target[0]
                } else {
                    state[0] < target[0]
                };

                if pass {
                    return Some((key + self.nonce_addend, state));
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solve_sha2_crate() {
        crate::tests::test_solve::<SingleBlockSolver>();
    }
}
