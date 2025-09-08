import init, { solve_anubis_json } from "/pkg/simd_mcaptcha.js";

onmessage = function (e) {
    switch (e.data.type) {
        case "solve":
            const solution = solve_anubis_json(e.data.json);
            postMessage({
                type: "solution",
                solution: {
                    delay: solution.delay,
                    response: solution.response,
                    nonce: solution.nonce,
                    attempted_nonces: solution.attempted_nonces,
                    method: "webworker",
                }
            });
            break;
    }
};

try {
    init();
    postMessage({
        type: "ready",
    });
} catch (e) {
    postMessage({
        type: "error",
        message: e.message,
    });
}

