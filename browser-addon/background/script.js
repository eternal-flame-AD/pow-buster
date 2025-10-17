let portFromCS;

const availableConcurrency = Math.max(Math.min(navigator.hardwareConcurrency || 4, 8), 1);

let workers = [];

function terminateWorkers() {
    for (let w of workers) {
        w.terminate();
    }
    workers = [];
}

function reloadWorkers(onSolution, numWorkers) {
    terminateWorkers();

    let loadPromises = [];
    for (let i = 0; i < numWorkers; i++) {
        const loadPromise = new Promise((resolve, reject) => {
            console.log("creating worker", i);
            const worker = new Worker("/background/worker.js", { type: "module" });
            worker.onmessage = (e) => {
                if (e.data.type === "solution") {
                    onSolution(e.data.solution);
                } else if (e.data.type === "ready") {
                    resolve();
                }
            };
            worker.onerror = (e) => {
                console.error("error in worker", e);
            };
            workers.push(worker);
        });
        loadPromises.push(loadPromise);
    }
    return Promise.all(loadPromises);
}

function solveSet(challenge, onSolution) {
    reloadWorkers((m) => {
        const solution = {
            nonce: m.nonce,
            response: m.response,
            attempted_nonces: m.attempted_nonces,
            delay: m.delay,
            subtype: m.subtype,
        };
        terminateWorkers();
        onSolution(solution);
    }, availableConcurrency).then(() => {
        for (let i = 0; i < availableConcurrency; i++) {
            workers[i].postMessage({ challenge, set: i, iterand: availableConcurrency });
        }
    });
}

function solveOne(challenge, onSolution) {
    reloadWorkers((m) => {
        const solution = {
            nonce: m.nonce,
            response: m.response,
            attempted_nonces: m.attempted_nonces,
            delay: m.delay,
            subtype: m.subtype,
        };
        terminateWorkers();
        onSolution(solution);
    }, 1).then(() => {
        workers[0].postMessage({ challenge });
    });
}

async function solveByOffload(challenge) {
    const offloadUrl = await browser.storage.sync.get('offload_url');
    if (offloadUrl.offload_url) {
        console.log("solving by offload", offloadUrl.offload_url);
        const url = new URL(offloadUrl.offload_url);
        const response = await fetch(offloadUrl.offload_url, {
            method: 'POST',
            body: `challenge=${encodeURIComponent(challenge)}`,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': url.origin,
            },
        });
        if (response.ok) {
            return response.text();
        } else {
            console.error("error solving by offload", response.statusText);
            return null;
        }
    }
}

browser.runtime.onConnect.addListener(p => {
    portFromCS = p;
    console.log("connected to content script");
    portFromCS.onDisconnect.addListener(() => {
        terminateWorkers();
    });
    portFromCS.onMessage.addListener((m) => {
        let solvedByOffload = false;
        solveByOffload(m.challenge).then((script) => {
            if (script) {
                solvedByOffload = true;
                portFromCS.postMessage({ type: "script", script });
            }
        }).finally(() => {
            if (!solvedByOffload) {
                if (m.multithreaded) {
                    solveSet(m.challenge, (solution) => {
                        portFromCS.postMessage({ type: "solution", solution });
                    });
                } else {
                    solveOne(m.challenge, (solution) => {
                        portFromCS.postMessage({ type: "solution", solution });
                    });
                }
            }
        });
    });
});
