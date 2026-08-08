# wafsolver

[![PyPI version](
  <https://badge.fury.io/py/wafsolver.svg>
  )](
  <https://badge.fury.io/py/wafsolver>
) [![CI](
  <https://github.com/eggplants/wafsolver/actions/workflows/ci.yml/badge.svg>
  )](
  <https://github.com/eggplants/wafsolver/actions/workflows/ci.yml>
)

Solve AWS WAF JavaScript challenges without a browser.

_Note: intended for accessing sites you are allowed to access programmatically._

## Install

```bash
pip install wafsolver
```

## Use

```python
import requests
import wafsolver

DOMAIN = "example.com"
URL = f"https://{DOMAIN}/"

session = requests.Session()
res = session.get(URL)

if wafsolver.is_challenged(res.headers):
    token = wafsolver.solve_challenge(DOMAIN, res.text)
    session.cookies.set(wafsolver.TOKEN_COOKIE, token, domain=DOMAIN)
    res = session.get(URL)

print(res.status_code, len(res.text))
```

Reuse one solver when you need several tokens, or want to refresh one:

```python
from wafsolver import WafSolver

solver = WafSolver("example.com")
token = solver.solve(challenge_html)
refreshed = solver.solve(challenge_html, existing_token=token)
```

<!--
## Challenge types

`challenge.js` dispatches on a challenge type identifier. All three are
supported:

| Type | Work | Posted to |
| --- | --- | --- |
| `h7b0c470f…` | SHA-256 proof of work | `/verify` |
| `h72f957df…` | scrypt proof of work | `/verify` |
| `ha9faaffd…` | Bandwidth: upload N zero bytes | `/mp_verify` |

The proof-of-work types search for a nonce whose digest of
`input + checksum + nonce` starts with `difficulty` zero bits. The bandwidth
type has no work at all -- it just uploads a zero-filled buffer, base64
encoded, as multipart form data, with the size chosen by the difficulty:

| Difficulty | 1 | 2 | 3 | 4 | 5 |
| --- | --- | --- | --- | --- | --- |
| Bytes | 1 KiB | 10 KiB | 100 KiB | 1 MiB | 10 MiB |

Every solution is accompanied by a browser fingerprint: a JSON blob prefixed
with the CRC32 of its own serialisation and encrypted with an AES-GCM key
embedded in `challenge.js`. The same checksum is mixed into the proof-of-work
input.
-->
