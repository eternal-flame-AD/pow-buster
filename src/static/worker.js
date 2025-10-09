import init, { solve_json } from "/pkg/pow_buster.js";

onmessage = function (e) {
    switch (e.data.type) {
        case "solve":
            const solution = solve_json(e.data.json);
            postMessage({
                type: "solution",
                solution: {
                    subtype: solution.subtype,
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

