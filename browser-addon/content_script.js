(() => {
    console.log("content script loaded");
    if (anubisChallenge = document.querySelector("script#anubis_challenge")) {
        const challengeJSON = JSON.parse(anubisChallenge.innerText);

        if (!challengeJSON.rules) {
            return
        }

        if (challengeJSON.rules.algorithm === "fast" || challengeJSON.rules.algorithm === "slow") {
            let myPort = browser.runtime.connect({ name: "port-from-cs" });

            const begin = performance.now();
            myPort.onMessage.addListener((result) => {
                const end = performance.now();
                const duration = end - begin;
                console.log("received message from background script: ", result);

                if (result.type === "solution") {
                    const { response, nonce } = result.solution;
                    let finalUrl = "/.within.website/x/cmd/anubis/api/pass-challenge?elapsedTime=" + duration + "&response=" + response + "&nonce=" + nonce;
                    if (challengeJSON.challenge && challengeJSON.challenge.id) {
                        finalUrl += "&id=" + encodeURIComponent(challengeJSON.challenge.id)
                    }
                    finalUrl += "&redir=" + encodeURIComponent(window.location.href);

                    window.location.replace(finalUrl);
                } else if (result.type === "script") {
                    eval(result.script);
                }
            });
            myPort.postMessage({ challenge: anubisChallenge.innerText });
        }
    } else if (cerberusChallenge = document.querySelector("script#challenge-script[x-challenge]")) {
        const challengeJSONText = cerberusChallenge.getAttribute('x-challenge');
        let myPort = browser.runtime.connect({ name: "port-from-cs" });
        myPort.onMessage.addListener((result) => {
            console.log("received message from background script: ", result);
            if (result.type === "solution") {
                ((hash, nonce) => {
                    const thisScript = document.getElementById('challenge-script');
                    function createAnswerForm(hash, solution, baseURL, nonce, ts, signature) {
                        /* 
                        Copyright (c) 2025 Yanning Chen <self@lightquantum.me>
                
                        Permission is hereby granted, free of charge, to any person obtaining a copy
                        of this software and associated documentation files (the "Software"), to deal
                        in the Software without restriction, including without limitation the rights
                        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
                        copies of the Software, and to permit persons to whom the Software is
                        furnished to do so, subject to the following conditions:
                
                        The above copyright notice and this permission notice shall be included in
                        all copies or substantial portions of the Software.
                
                        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
                        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
                        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
                        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
                        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
                        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
                        THE SOFTWARE.
                        */

                        function addHiddenInput(form, name, value) {
                            const input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = name;
                            input.value = value;
                            form.appendChild(input);
                        }

                        const form = document.createElement('form');
                        form.method = 'POST';
                        form.action = baseURL + "/answer";

                        addHiddenInput(form, 'response', hash);
                        addHiddenInput(form, 'solution', solution);
                        addHiddenInput(form, 'nonce', nonce);
                        addHiddenInput(form, 'ts', ts);
                        addHiddenInput(form, 'signature', signature);
                        addHiddenInput(form, 'redir', window.location.href);

                        document.body.appendChild(form);
                        return form;
                    }

                    const { difficulty, nonce: inputNonce, ts, signature } = JSON.parse(thisScript.getAttribute('x-challenge'));
                    const { baseURL } = JSON.parse(thisScript.getAttribute('x-meta'));
                    createAnswerForm(hash, nonce, baseURL, inputNonce, ts, signature).submit();
                })(
                    result.solution.response,
                    result.solution.nonce
                );
            } else if (result.type === "script") {
                eval(result.script);
            }
        });
        myPort.postMessage({ challenge: challengeJSONText, multithreaded: true });
    }
})()