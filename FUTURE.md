My own early thoughts, all speculative:

The intuitive solution is to use a memory bound (script, Argon2, etc.) function, but I argue that is also a bad idea. For the scale of services that require a PoW Captcha, they likely _cannot_ take 100 RPS of even just validating a memory hard function. They need a semaphore, which is using a DDoS attack vector to substitute another (the endpoint being protected).

The issue with using PoW in a "one-on-one" configuration (unlike cryptocurrency like BTC where it is "one-on-all") is, in fact, even if the function is perfect (an ideal VDF), most services scales sub-linearly (buying twice as much hardware don't serve twice as much users) but you need to adapt to the lowest common denominator for legitimate users, and the attacker would use the fastest and most economic solution possible (which is often superlinear for most intents and purposes when stacking up better hardware and more optimizations), which often is at least one order of magnitude if not more different. So trying to do any kind of pure PoW, for a website, is a losing game.

I think a better avenue to minimize "I got x times faster by doing ..." would be to add fixed constant factor, IO-serialized "mini-PoW" challenges that are easily solved but the challenger needs to submit the results for the first sub-goal to get the input for the next sub-goal (which can be implemented using cheap cryptographic primitives statelessly). 

The benefit of this approach is that it makes it incredibly difficult to get an advantage using more compute-oriented hardware, for example, GPU would never be able to amortize the transfer and dispatch overhead, and with a fixed large constant factor (IO latency), any data parallelism solution would be unlikely to get multiple folds of speedup. Additionally, the server can randomize and withhold the exact number of steps required, which makes building purpose-built solvers (like ASICs) almost impossible. 

On the server end, trying to respond to a particular WebSocket message or HTTP request is incredibly fast (often on the order of 1e5+ RPS), and up to 10 round trips are unlikely to make a significant difference than the capacity of 1 round trip for a traditional pure PoW system.

And obviously, IO-bound task are much "greener" and discriminate much less against less powerful hardware, both are good properties for "the good guys".
