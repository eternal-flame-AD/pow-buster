import init, { solve_json_set, solve_json } from '/pkg/pow_buster.js';

init().then(() => {
    onmessage = function (e) {
        const output = e.data.set ? solve_json_set(e.data.challenge, e.data.set, e.data.iterand) : solve_json(e.data.challenge);
        const solution = {
            nonce: output.nonce,
            response: output.response,
            attempted_nonces: output.attempted_nonces,
            delay: output.delay,
            subtype: output.subtype,
        };
        postMessage({ type: "solution", solution });
    };
    postMessage({ type: "ready" });
}).catch((error) => {
    console.error("error initializing pow_buster", error);
});
