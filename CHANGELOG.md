<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Cert Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- `FileEditor` for `.pem`, `.crt`, `.cer`, `.der`, `.jks`, `.p12`, `.pfx`
  files, decoding subject, issuer, serial number, validity, signature
  algorithm, and SHA-256 fingerprint using only JDK `java.security` APIs.
- Multi-certificate PEM bundles render one certificate per card instead of
  an unreadable block.
- "Copy Raw PEM" button on every certificate card.
- Visual expiry warnings (`JBColor.RED` for expired, `JBColor.ORANGE` for
  expiring within 30 days) that stay readable in both dark and light
  themes.
- Keystore password prompt on demand only, via an explicit "Unlock
  Keystore" button; the password is never cached longer than the
  `KeyStore.load()` call that needs it.
- No telemetry, no license prompts, no network access.
