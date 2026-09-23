<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Cert Companion Changelog

## [Unreleased]

## [0.1.3]

### Fixed

- A certificate's serial number is now shown as unsigned hex even when
  the issuing CA encoded it without the DER padding byte that keeps it
  positive (a real, documented bug in some CAs' certificates, not
  hypothetical) -- matches the convention `openssl x509 -serial` and
  other tools use, instead of a literal minus sign.

### Added

- Review/star CTA: after 5 successfully decoded certificates/keystores,
  a one-time notification asks whether to rate the plugin on
  Marketplace, with a permanent "Don't ask again" option. Standard
  mechanism used catalog-wide; this plugin (built before the rollout)
  had been missed.

## [0.1.2]

### Changed

- Added a strict local `verifyPlugin` gate (catches
  `@ApiStatus.OverrideOnly`/`Internal`/`Experimental` API usage and
  compatibility problems before Marketplace's own verifier would) — no
  user-visible change, confirmed passing clean against all 6 target IDEs.

## [0.1.1]

### Added

- Gap Hunter Labs brand icon (`pluginIcon.svg` / `pluginIcon_dark.svg`).

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

[Unreleased]: https://github.com/GapHunterLabs/cert-companion/compare/0.1.3...HEAD
[0.1.3]: https://github.com/GapHunterLabs/cert-companion/compare/0.1.2...0.1.3
[0.1.2]: https://github.com/GapHunterLabs/cert-companion/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/GapHunterLabs/cert-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/cert-companion/commits/0.1.0
