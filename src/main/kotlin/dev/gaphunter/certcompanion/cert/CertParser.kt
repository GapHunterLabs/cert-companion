package dev.gaphunter.certcompanion.cert

import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import java.util.Locale

data class CertInfo(
    val subject: String,
    val issuer: String,
    val serialNumber: String,
    val notBefore: Date,
    val notAfter: Date,
    val signatureAlgorithm: String,
    val sha256Fingerprint: String,
    val pem: String,
)

enum class ExpiryStatus { VALID, EXPIRING_SOON, EXPIRED }

data class KeystoreEntry(
    val alias: String,
    val isPrivateKeyEntry: Boolean,
    val cert: CertInfo,
)

class KeystorePasswordException(message: String, cause: Throwable?) : Exception(message, cause)

/**
 * Client-side only: java.security.KeyStore / java.security.cert.X509Certificate /
 * java.security.cert.CertificateFactory, nothing else. No network, no external
 * crypto library.
 */
object CertParser {

    private const val EXPIRING_SOON_DAYS = 30L
    private val KEYSTORE_EXTENSIONS = setOf("jks", "p12", "pfx")

    fun isKeystoreExtension(extension: String): Boolean = extension.lowercase(Locale.ROOT) in KEYSTORE_EXTENSIONS

    fun storeTypeForExtension(extension: String): String = when (extension.lowercase(Locale.ROOT)) {
        "jks" -> "JKS"
        "p12", "pfx" -> "PKCS12"
        else -> throw IllegalArgumentException("Not a keystore extension: $extension")
    }

    fun expiryStatus(info: CertInfo, now: Date = Date()): ExpiryStatus {
        if (info.notAfter.before(now)) return ExpiryStatus.EXPIRED
        val soonThreshold = Date(now.time + EXPIRING_SOON_DAYS * 24 * 60 * 60 * 1000)
        return if (info.notAfter.before(soonThreshold)) ExpiryStatus.EXPIRING_SOON else ExpiryStatus.VALID
    }

    /**
     * Handles a single DER certificate, a single PEM certificate, and a PEM
     * bundle with multiple concatenated certificates alike — the JDK's own
     * CertificateFactory.generateCertificates reads a whole stream of
     * concatenated certs, PEM or DER, one after another. That is the direct
     * fix for the competitor's "unreadable multi-cert bundle" complaint: each
     * certificate in the bundle is parsed and rendered as its own entry.
     */
    fun parseCertificateBundle(bytes: ByteArray): List<CertInfo> {
        val factory = CertificateFactory.getInstance("X.509")
        val certs = factory.generateCertificates(ByteArrayInputStream(bytes))
        if (certs.isEmpty()) {
            throw IllegalArgumentException("No X.509 certificates found in this file.")
        }
        return certs.map { toCertInfo(it as X509Certificate) }
    }

    fun parseKeystore(bytes: ByteArray, storeType: String, password: CharArray): List<KeystoreEntry> {
        val keyStore = KeyStore.getInstance(storeType)
        try {
            keyStore.load(ByteArrayInputStream(bytes), password)
        } catch (e: Exception) {
            throw KeystorePasswordException(
                "Could not open this $storeType keystore. The password may be incorrect.",
                e,
            )
        }
        val entries = mutableListOf<KeystoreEntry>()
        val aliases = keyStore.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            val cert = keyStore.getCertificate(alias) as? X509Certificate ?: continue
            entries.add(KeystoreEntry(alias, keyStore.isKeyEntry(alias), toCertInfo(cert)))
        }
        return entries
    }

    fun toCertInfo(cert: X509Certificate): CertInfo {
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
        return CertInfo(
            subject = cert.subjectX500Principal.name,
            issuer = cert.issuerX500Principal.name,
            serialNumber = cert.serialNumber.toString(16).uppercase(Locale.ROOT),
            notBefore = cert.notBefore,
            notAfter = cert.notAfter,
            signatureAlgorithm = cert.sigAlgName,
            sha256Fingerprint = fingerprint.joinToString(":") { "%02X".format(it) },
            pem = toPem(cert),
        )
    }

    fun toPem(cert: X509Certificate): String {
        val base64 = Base64.getEncoder().encodeToString(cert.encoded)
        val body = base64.chunked(64).joinToString("\n")
        return "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n"
    }
}
