/** Copyright (c) 2025 WeebDataHoarder, go-away Contributors, Yumechi
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:

* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

let _worker;
let _webWorkerURL;
let _challenge;
let _target;
let _difficulty;

async function setup(config) {
    const { challenge, target, difficulty } = await fetch(config.Path + "/make-challenge", { method: "POST" })
        .then(r => {
            if (!r.ok) {
                throw new Error("Failed to fetch config");
            }
            return r.json();
        })
        .catch(err => {
            throw err;
        });

    _challenge = challenge;
    _target = target;
    _difficulty = difficulty;

    let message = `Difficulty ${difficulty}`;
    if (window.powbuster) {
        message += ` (using powbuster)`;
    } else {
        console.warn("powbuster not found, fallback to webworker");
        _webWorkerURL = URL.createObjectURL(new Blob([
            '(', processTask(challenge, difficulty), ')()'
        ], { type: 'application/javascript' }));
        _worker = new Worker(_webWorkerURL);
    }

    return message;
}

function challenge() {
    return new Promise((resolve, reject) => {
        if (window.powbuster) {
            window.powbuster({ challenge: _challenge, target: _target, difficulty: _difficulty }).then(({
                response,
                attempted_nonces,
            }) => {
                resolve({
                    result: response,
                    info: `iterations ${attempted_nonces}`,
                });
            }).catch(reject);
            return;
        }

        _worker.onmessage = (event) => {
            _worker.terminate();
            resolve(event.data);
        };

        _worker.onerror = (event) => {
            _worker.terminate();
            reject();
        };

        _worker.postMessage({
            challenge: _challenge,
            target: _target,
            difficulty: _difficulty,
        });

        URL.revokeObjectURL(_webWorkerURL);
    });
}

function processTask() {
    return function () {

        const decodeHex = (str) => {
            let result = new Uint8Array(str.length >> 1)
            for (let i = 0; i < str.length; i += 2) {
                result[i >> 1] = parseInt(str.substring(i, i + 2), 16)
            }

            return result
        }

        const encodeHex = (buf) => {
            return buf.reduce((a, b) => a + b.toString(16).padStart(2, '0'), '')
        }

        const lessThan = (buf, target) => {
            for (let i = 0; i < buf.length; ++i) {
                if (buf[i] < target[i]) {
                    return true;
                } else if (buf[i] > target[i]) {
                    return false;
                }
            }

            return false
        }

        const increment = (number) => {
            for (let i = 0; i < number.length; i++) {
                if (number[i] === 255) {
                    number[i] = 0;
                } else {
                    number[i]++;
                    break;
                }
            }
        }

        addEventListener('message', async (event) => {
            let data = decodeHex(event.data.challenge);
            let target = decodeHex(event.data.target);

            let nonce = new Uint8Array(8);
            let buf = new Uint8Array(data.length + nonce.length);
            buf.set(data, 0);

            while (true) {
                buf.set(nonce, data.length);
                let result = new Uint8Array(await crypto.subtle.digest("SHA-256", buf))

                if (lessThan(result, target)) {
                    const nonceNumber = Number(new BigUint64Array(nonce.buffer).at(0))
                    postMessage({
                        result: encodeHex(buf),
                        info: `iterations ${nonceNumber}`,
                    });
                    return
                }
                increment(nonce)
            }

        });
    }.toString();
}

export { setup, challenge }