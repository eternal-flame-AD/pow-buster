# Contributing to pow-buster

pow-buster is a consumer advocacy and research project pushing hardware limits on solving interactive Proof-of-Work challenges. We welcome contributions that target generic, site-agnostic solutions with the hope of improving open-web accessibility and providing evidence for informed deployment decisions.

## General Guidelines

- We cannot accept issues or pull requests that target a specific website. Requests targeting bespoke solutions or clearly expressing intent to use the solver for a particular website will not be reviewed.
- All feature-requests must be described in a site-agnostic manner, for example:

  - OK: "Support new nonce format by ACME Protect".
  - OK: "Add support for ${ALGORITHM}".
  - OK: "Bug report: Config option X by ACME Protect is not correctly handled".
  - NOT OK: "Enhance X core to help with automation on example.com".
  - OK: "Add challenge response protocol support by ACME Protect".
  - NOT OK: "Support novel nonce format by example.com".
  - OK: "Workaround ACMEProtect's explicit block of the current User-Agent header".
  - NOT OK: "Change User-Agent header so it is not blocked by example.com".

## Expectations

- Custom cryptographic cores are time-consuming and high-latency. There is no concrete timeline for supporting new algorithms. All requests for new cores will only be pursued if it has non-trivial adoption. Generally I will prioritize blocking pre-visit gates only due to extreme user friction and workflow disruption.
- Protocols should be explained using canonical names and in site-agnotistic and generic terms, with data types and acceptance limits annotated:
  - A good example: ACMEProtect has a new challenge: Salt concatenated with an ASCII decimal nonce. Salt is typically 32 bytes but user-configurable. Decimal nonce are limited to zero to u32::MAX. Test the first word of the hash for less than or equal to difficulty.
  - A bad example: See my `poc.py` for how to solve it. I triede it on example.com and it works.
- This is not a generic collection of cryptographic miners. Systems tuned for batch processing or non-interactive use are not considered, regardless of adoption or vendor support, namely:
  - Peak RAM usage >= 256MB
  - Typical latency > 15seconds
- Issues and pull requests that hardcode specific website endpoints cannot be reviewed.
  - OK: `window.location.replace("/.with-website/x/acmeprotect/pass-challenge?...")`
  - NOT OK: `window.location.replace("https://example.com/pass-challenge?...")`
- Issues that request support for specific websites will not be reviewed. Requesters must show at least two unrelated websites using the same protection scheme.
