# popi.wtf Security Findings

Recon + PoC for popi.wtf (Solana PvP gacha launchpad, private beta).

## Findings

### 1. WS RPC proxy allowlist bypass

`wss://popi.wtf/api/rpc-ws` has no method allowlist. The HTTP proxy `/api/rpc` blocks `getVersion`, `getProgramAccounts`, etc. The WS proxy allows all Solana subscription methods.

| Method | HTTP `/api/rpc` | WS `/api/rpc-ws` |
|--------|----------------|-----------------|
| getVersion | blocked | allowed |
| getProgramAccounts | blocked | bypassed via programSubscribe |
| logsSubscribe | N/A | streams all mainnet tx logs |
| accountSubscribe | N/A | monitors any account |

No auth. No rate limit. 50 concurrent connections confirmed. 10/10 validation runs reproduced.

`programSubscribe` streams full account data (pubkey, lamports, owner, data) — ~200 notifications/3s, ~77KB per run from a single subscription.

**PoC:** `poc_ws_allowlist_bypass.py`

**Fix:** Apply method allowlist to WS proxy matching HTTP restrictions. Add per-IP rate limiting and connection limits.

### 2. SIWS chain confusion + domain non-validation

`/api/auth/verify` does not validate the Chain or domain fields in the SIWS message.

- Chain: mainnet-beta → devnet: **accepted** (server doesn't check chain matches nonce request)
- Domain: popi.wtf → evil.com: **accepted** (first line of message not validated)
- URI: https://popi.wtf → https://evil.com: rejected (correct)
- Nonce: single-use (correct)
- Signature: validated (correct)

**PoC:** `poc_siws_chain_confusion.py`

**Fix:** Validate Chain field matches the chainId from the nonce request. Validate domain field matches the server's domain.

## Negative findings (server is secure)

- Nonce is single-use
- Signature replay blocked
- Message tampering (wallet field) blocked
- Cross-user nonce blocked
- Referral IDOR blocked (server uses session wallet, ignores query param)
- Cross-bind blocked (wallet_mismatch)
- JWT signed with EdDSA (Ed25519)
- Session cookie: HttpOnly, Secure, SameSite=lax
- CSRF token implemented for bind endpoint
- No SSRF via next/image (endpoint returns 400 for all URLs)
- No path traversal
- No .env/.git exposure
- CSP, HSTS, X-Frame-Options: DENY all set

## Run

```bash
pip install websockets solders base58
python3 poc_ws_allowlist_bypass.py
python3 poc_siws_chain_confusion.py
```
