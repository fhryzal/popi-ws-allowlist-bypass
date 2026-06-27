# popi.wtf WS RPC Proxy Allowlist Bypass

PoC for popi.wtf WebSocket RPC proxy allowing all Solana subscription methods without auth or rate limiting, bypassing the HTTP RPC allowlist.

## Finding

`/api/rpc` (HTTP) restricts methods via allowlist. `/api/rpc-ws` (WebSocket) has no allowlist.

| Method | HTTP | WS |
|--------|------|----|
| getVersion | blocked | allowed |
| getProgramAccounts | blocked | bypassed via programSubscribe |
| logsSubscribe | N/A | streams all mainnet logs |
| accountSubscribe | N/A | monitors any account |

No auth. No rate limit. 50 concurrent connections confirmed.

## Run

```bash
pip install websockets
python3 poc_ws_allowlist_bypass.py
```

## Sample output

```
[HTTP /api/rpc]
  getVersion: BLOCKED
  getProgramAccounts: BLOCKED

[WS /api/rpc-ws]
[WS] getVersion: {'feature-set': 2142755730, 'solana-core': '2.3.13'}
[WS] programSubscribe: subscription ID 87607
[WS] 196 notifications in 3s (76956 bytes)
[WS] First notification: pubkey=EjqJwquE57suQvaj... lamports=2039280 owner=TokenkegQfeZyiNw...
```
