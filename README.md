# TOTP Generator

A small command-line authenticator that creates and checks six-digit time-based one-time passwords. It uses the standard HMAC-SHA1 TOTP method and works offline.

This is a learning project. It is not a replacement for a maintained authenticator app or a secure enterprise identity system.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Make a secret

    python3 totp.py new-secret

The tool prints a random Base32 secret once. Save it in a password manager or another secure place. The program does not keep a copy.

## Generate a code

    python3 totp.py code

Paste the Base32 secret when prompted. The input is hidden. The current six-digit code is printed to the terminal.

## Check a code

    python3 totp.py check

The default check accepts the current time step and one step either side to allow for small clock differences. Use a narrower window where your clocks are well synchronised:

    python3 totp.py check --window 0

## Make an enrollment URI

Some QR-code tools can turn an otpauth URI into a QR code. This command prints the URI but does not create a QR image:

    python3 totp.py uri --issuer "Example Service" --account "alex@example.test"

Treat both the secret and the URI as passwords. Anyone who gets them can generate your codes.

## Security notes

- The secret is entered through a hidden prompt for code generation and verification.
- The program makes no network requests and does not save secrets or generated codes.
- Do not use a secret from an important account for experiments. Start with a test account.
- Keep your device clock set automatically; TOTP depends on the time being close.
- If you lose the secret, use the account's recovery process. This program cannot restore it.

## Checks

Run:

    python3 -m unittest -v

The tests include the published RFC 6238 SHA-1 examples and input-validation checks.

