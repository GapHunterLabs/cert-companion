# Cert Companion

IntelliJ-family plugin. A native, client-side viewer for X.509 certificates
and keystores — decode a `.pem`, `.crt`, `.cer`, `.der`, `.jks`, `.p12`, or
`.pfx` file without leaving the IDE.

## Why it exists

Born from real evidence in JetBrains Marketplace reviews of a paid
certificate/keystore explorer plugin (308K downloads, 83% of reviews at 3
stars or fewer), not assumptions:

- "This is the only plugin I pay for, and it never works properly...
  Details of the certs never get opened" — the plugin's core feature,
  broken, for a paying user.
- Multiple reviews compare it unfavorably to the free standalone
  KeyStore Explorer tool, saying the paid plugin offers only "10-20%" of
  that functionality and "no benefit at all" over it.
- "I have dark theme in IDE and the status bar is white and text there
  cannot be read" — an illegible UI in dark theme.
- "I can't copy the raw cert/key content" — a basic, expected feature,
  missing.
- Ugly rendering of PEM bundles with multiple certificates.
- A severe bug report of the plugin crashing the IDE, and complaints that
  it "hangs around under plugins" even after trying to uninstall it.

## Why built this way

- **JDK-only parsing, no bundled crypto library.** Every certificate and
  keystore is read with `java.security.cert.CertificateFactory`,
  `java.security.cert.X509Certificate`, and `java.security.KeyStore` —
  the same standard-library-first approach already used elsewhere in Gap
  Hunter Labs' plugins (see Ansible Companion's hand-rolled vault cipher).
  No network access, no dependency to go wrong.
- **Multi-certificate PEM bundles render one certificate at a time.** The
  JDK's own `CertificateFactory.generateCertificates` already reads a
  whole stream of concatenated PEM or DER certificates; each one becomes
  its own card with its own fields and its own copy button — the direct
  fix for the "ugly bundle rendering" complaint.
- **A real "Copy Raw PEM" button on every certificate card.** The direct
  fix for "I can't copy the raw cert/key content."
- **Every color comes from `JBColor`, never a hardcoded white or black.**
  Expired certificates are flagged in `JBColor.RED`, certificates expiring
  within 30 days in `JBColor.ORANGE`; everything else uses the theme's own
  default label color. Verified in both dark and light themes — the direct
  fix for the unreadable-status-bar-in-dark-theme complaint.
- **Keystore passwords are asked for on demand, never cached.** Opening a
  `.jks`/`.p12`/`.pfx` file shows an "Unlock Keystore" button first,
  instead of popping a password dialog the moment the tab opens. The
  password `CharArray` is wiped immediately after `KeyStore.load()`
  returns.
- **Registered as the file's primary editor** (`FileEditorPolicy.PLACE_BEFORE_DEFAULT_EDITOR`),
  the same choice made for the XLSX viewer in Spreadsheet Companion: for
  binary formats (`.der`/`.jks`/`.p12`/`.pfx`) the plain text editor is
  useless, and for PEM-family text files the decoded view is the entire
  reason to open the file — the raw text is still one click away via
  "Copy Raw PEM."

## Usage

Open any `.pem`, `.crt`, `.cer`, `.der`, `.jks`, `.p12`, or `.pfx` file. For
plain certificates and PEM bundles, the decoded view opens immediately. For
keystores, click "Unlock Keystore" and enter the password once; every alias
in the keystore is then listed with its own certificate card.

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin    # generates build/distributions/*.zip
./gradlew verifyPlugin   # checks compatibility against real IDEs
```

## License

Apache-2.0. See `LICENSE`.
