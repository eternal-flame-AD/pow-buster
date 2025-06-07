@group(0) @binding(0)
var<storage, read_write> solution: atomic<u32>;

@group(0) @binding(1)
var<storage, read> message_template: array<u32, 16>;

@group(0) @binding(2)
var<storage, read> saved_state: array<u32, 12>;

const K32: array<u32, 64> = array(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
);

fn rotate_right(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32 - n));
}

@compute @workgroup_size(256, 1, 1)
fn findNonce(
    @builtin(global_invocation_id) global_id: vec3<u32>,
) {
    let nonce_offset = saved_state[8];
    let target_msb = saved_state[9];
    let digit_byte_offset = saved_state[10];
    let tests_per_thread = saved_state[11];

    let linear_idx = global_id.x * tests_per_thread + nonce_offset;

    for (var work_offset: u32 = 0; work_offset < tests_per_thread; work_offset++) {
        var blocks = message_template;

        let nonce = linear_idx + work_offset;
        var digits = nonce;
        // the first digit extracted goes to the 8-th byte
        // the last digit extracted goes to the 0-th byte
        for (var ri: u32 = 0; ri < 9; ri++) {
            let i = (8 - ri) + digit_byte_offset;
            let digit = digits % 10;
            let byte_value = digit + 0x30;
            let message_word_idx = i / 4;
            let message_byte_idx = 3 - (i % 4);
            blocks[message_word_idx] |= byte_value << (message_byte_idx * 8);
            digits = digits / 10;
        }

        var a = saved_state[0];
        var b = saved_state[1];
        var c = saved_state[2];
        var d = saved_state[3];
        var e = saved_state[4];
        var f = saved_state[5];
        var g = saved_state[6];
        var h = saved_state[7];

        for (var i: u32 = 0; i < 64; i++) {
            var w: u32 = 0;

            if (i < 16) {
                w = blocks[i];
            } else {
                let w15 = blocks[(i - 15) % 16];
                let s0 = (rotate_right(w15, 7)) ^ (rotate_right(w15, 18)) ^ (w15 >> 3);
                let w2 = blocks[(i - 2) % 16];
                let s1 = (rotate_right(w2, 17)) ^ (rotate_right(w2, 19)) ^ (w2 >> 10);
                blocks[i % 16] = blocks[i % 16] + s0 + blocks[(i - 7) % 16] + s1;
                w = blocks[i % 16];
            };

            let s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            let ch = (e & f) ^ ((~e) & g);
            let t1 = s1 + ch + K32[i] + w + h;
            let s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        if a + saved_state[0] > target_msb {
            atomicMin(&solution, nonce);
        }
    }
}