#!/usr/bin/env python3
"""Generate and verify time-based one-time passwords without network access."""

import argparse
import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import time
from getpass import getpass
from urllib.parse import quote, urlencode


def decode_secret(secret: str) -> bytes:
    cleaned = "".join(secret.split()).upper()
    if not cleaned:
        raise ValueError("secret cannot be empty")
    padded = cleaned + "=" * ((8 - len(cleaned) % 8) % 8)
    try:
        return base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("secret must be a valid Base32 value") from exc


def generate_secret(size: int = 20) -> str:
    if size < 16:
        raise ValueError("use at least 16 random bytes for a new secret")
    return base64.b32encode(secrets.token_bytes(size)).decode("ascii").rstrip("=")


def totp(secret: str, timestamp: float | None = None, period: int = 30,
         digits: int = 6) -> str:
    if period < 1:
        raise ValueError("period must be at least one second")
    if digits not in (6, 7, 8):
        raise ValueError("digits must be 6, 7, or 8")
    key = decode_secret(secret)
    counter = int(time.time() if timestamp is None else timestamp) // period
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary_code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary_code % (10 ** digits)).zfill(digits)


def verify(secret: str, code: str, timestamp: float | None = None,
           period: int = 30, window: int = 1, digits: int = 6) -> bool:
    if window < 0:
        raise ValueError("window cannot be negative")
    if len(code) != digits or not code.isdigit():
        return False
    now = time.time() if timestamp is None else timestamp
    for offset in range(-window, window + 1):
        candidate = totp(secret, now + offset * period, period=period, digits=digits)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def provisioning_uri(secret: str, issuer: str, account: str,
                     period: int = 30, digits: int = 6) -> str:
    decode_secret(secret)
    if not issuer.strip() or not account.strip():
        raise ValueError("issuer and account are required")
    label = quote(f"{issuer}:{account}", safe="")
    query = urlencode({
        "secret": "".join(secret.split()).upper(),
        "issuer": issuer,
        "period": period,
        "digits": digits,
        "algorithm": "SHA1",
    })
    return f"otpauth://totp/{label}?{query}"


def ask_secret() -> str:
    return getpass("Base32 secret (input hidden): ").strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("new-secret", help="create a new random Base32 secret")

    code_parser = commands.add_parser("code", help="generate the current code")
    code_parser.add_argument("--period", type=int, default=30)
    code_parser.add_argument("--digits", type=int, choices=(6, 7, 8), default=6)

    check_parser = commands.add_parser("check", help="check a code near the current time")
    check_parser.add_argument("--period", type=int, default=30)
    check_parser.add_argument("--window", type=int, default=1)
    check_parser.add_argument("--digits", type=int, choices=(6, 7, 8), default=6)

    uri_parser = commands.add_parser("uri", help="print an otpauth URI for a QR-code tool")
    uri_parser.add_argument("--issuer", required=True)
    uri_parser.add_argument("--account", required=True)
    uri_parser.add_argument("--period", type=int, default=30)
    uri_parser.add_argument("--digits", type=int, choices=(6, 7, 8), default=6)

    args = parser.parse_args()
    try:
        if args.command == "new-secret":
            print(generate_secret())
            print("Save this once in your password manager. It cannot be recovered here.")
            return 0
        if args.command == "code":
            print(totp(ask_secret(), period=args.period, digits=args.digits))
            return 0
        if args.command == "check":
            secret = ask_secret()
            code = input(f"{args.digits}-digit code: ").strip()
            print("Code is valid." if verify(secret, code, period=args.period,
                                              window=args.window, digits=args.digits)
                  else "Code is not valid.")
            return 0
        if args.command == "uri":
            secret = ask_secret()
            print(provisioning_uri(secret, args.issuer, args.account,
                                   period=args.period, digits=args.digits))
            return 0
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
