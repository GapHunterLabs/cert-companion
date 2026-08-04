# Demo

All certificates/keys here are **self-signed, generated locally for this
demo only** (`openssl req -x509 -newkey rsa:2048 ...`) — no real
project, no real key material, never used for anything but a
screenshot.

- `acme-cert-bundle.pem` — 3 certificates for fictional `acme-corp.com`
  hosts, deliberately at different points in their lifecycle so a single
  screenshot shows all three states at once:
  - `api.acme-corp.com` — **expired** (notAfter 2025-01-01)
  - `payments.acme-corp.com` — **expiring soon** (notAfter 2026-08-15)
  - `www.acme-corp.com` — **valid** (notAfter 2028-01-01)
- `acme-payments.p12` — a password-protected PKCS12 keystore containing
  the `payments.acme-corp.com` key+cert, for the "Unlock Keystore" flow.
  Password: `DemoOnly123`.
