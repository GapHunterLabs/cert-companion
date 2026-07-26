package dev.gaphunter.certcompanion.ui

import com.intellij.openapi.fileEditor.FileEditor
import com.intellij.openapi.fileEditor.FileEditorState
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.util.UserDataHolderBase
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBLabel
import dev.gaphunter.certcompanion.cert.CertInfo
import dev.gaphunter.certcompanion.cert.CertParser
import dev.gaphunter.certcompanion.cert.ExpiryStatus
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Font
import java.beans.PropertyChangeListener
import java.text.SimpleDateFormat
import java.util.Locale
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.SwingConstants
import javax.swing.Timer

class CertFileEditor(private val file: VirtualFile) : UserDataHolderBase(), FileEditor {

    private val rootPanel = JPanel(BorderLayout())

    init {
        val extension = file.extension?.lowercase(Locale.ROOT) ?: ""
        if (CertParser.isKeystoreExtension(extension)) {
            showLockedKeystore(extension)
        } else {
            loadCertificateBundle()
        }
    }

    private fun loadCertificateBundle() {
        val result = runCatching { CertParser.parseCertificateBundle(file.contentsToByteArray()) }
        result.fold(
            onSuccess = { infos ->
                val entries = infos.mapIndexed { i, info ->
                    val heading = if (infos.size > 1) "Certificate ${i + 1} of ${infos.size}" else "Certificate"
                    heading to info
                }
                showCertificates(entries)
            },
            onFailure = { showError(it.message ?: "Could not parse this file as an X.509 certificate.") },
        )
    }

    private fun showLockedKeystore(extension: String) {
        val unlockButton = JButton("Unlock Keystore")
        unlockButton.addActionListener { unlockKeystore(extension) }
        setCenter(centeredMessage("This is a password-protected keystore (${extension.uppercase(Locale.ROOT)}).", extra = unlockButton))
    }

    private fun unlockKeystore(extension: String) {
        val dialog = KeystorePasswordDialog("Unlock ${file.name}")
        if (!dialog.showAndGet()) return
        val password = dialog.password()
        try {
            val storeType = CertParser.storeTypeForExtension(extension)
            val entries = CertParser.parseKeystore(file.contentsToByteArray(), storeType, password)
            if (entries.isEmpty()) {
                showError("This keystore opened successfully but contains no certificate entries.")
            } else {
                val labeled = entries.map { entry ->
                    val kind = if (entry.isPrivateKeyEntry) "private key entry" else "trusted certificate entry"
                    "Alias \"${entry.alias}\" ($kind)" to entry.cert
                }
                showCertificates(labeled)
            }
        } catch (e: Exception) {
            showError(e.message ?: "Could not open this keystore.")
        } finally {
            password.fill(0.toChar())
        }
    }

    private fun showCertificates(entries: List<Pair<String, CertInfo>>) {
        val cardsPanel = JPanel()
        cardsPanel.layout = BoxLayout(cardsPanel, BoxLayout.Y_AXIS)
        cardsPanel.border = BorderFactory.createEmptyBorder(10, 10, 10, 10)
        for ((heading, info) in entries) {
            val card = buildCertCard(heading, info)
            card.alignmentX = JComponent.LEFT_ALIGNMENT
            cardsPanel.add(card)
            cardsPanel.add(Box.createVerticalStrut(10))
        }
        setCenter(JScrollPane(cardsPanel))
    }

    private fun showError(message: String) {
        setCenter(centeredMessage(message, color = JBColor.RED))
    }

    private fun setCenter(component: JComponent) {
        rootPanel.removeAll()
        rootPanel.add(component, BorderLayout.CENTER)
        rootPanel.revalidate()
        rootPanel.repaint()
    }

    private fun centeredMessage(text: String, color: Color? = null, extra: JComponent? = null): JComponent {
        val label = JBLabel(text, SwingConstants.CENTER)
        label.alignmentX = JComponent.CENTER_ALIGNMENT
        if (color != null) label.foreground = color

        val box = Box.createVerticalBox()
        box.add(Box.createVerticalGlue())
        box.add(label)
        if (extra != null) {
            box.add(Box.createVerticalStrut(10))
            val row = JPanel()
            row.alignmentX = JComponent.CENTER_ALIGNMENT
            row.add(extra)
            box.add(row)
        }
        box.add(Box.createVerticalGlue())
        return box
    }

    private fun buildCertCard(heading: String, info: CertInfo): JComponent {
        val card = JPanel()
        card.layout = BoxLayout(card, BoxLayout.Y_AXIS)
        card.border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(JBColor.border()),
            BorderFactory.createEmptyBorder(10, 12, 10, 12),
        )

        val title = JBLabel(heading)
        title.font = title.font.deriveFont(Font.BOLD)
        title.alignmentX = JComponent.LEFT_ALIGNMENT
        card.add(title)
        card.add(Box.createVerticalStrut(8))

        card.add(fieldRow("Subject", info.subject))
        card.add(fieldRow("Issuer", info.issuer))
        card.add(fieldRow("Serial Number", info.serialNumber, monospace = true))

        val status = CertParser.expiryStatus(info)
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.ROOT)
        val statusSuffix = when (status) {
            ExpiryStatus.EXPIRED -> "  (EXPIRED)"
            ExpiryStatus.EXPIRING_SOON -> "  (expiring soon)"
            ExpiryStatus.VALID -> ""
        }
        val validityColor = when (status) {
            ExpiryStatus.EXPIRED -> JBColor.RED
            ExpiryStatus.EXPIRING_SOON -> JBColor.ORANGE
            ExpiryStatus.VALID -> null
        }
        val validityText = "${dateFormat.format(info.notBefore)}  to  ${dateFormat.format(info.notAfter)}$statusSuffix"
        card.add(fieldRow("Validity", validityText, color = validityColor))
        card.add(fieldRow("Signature Algorithm", info.signatureAlgorithm))
        card.add(fieldRow("SHA-256 Fingerprint", info.sha256Fingerprint, monospace = true))

        card.add(Box.createVerticalStrut(8))
        val copyButton = JButton("Copy Raw PEM")
        copyButton.alignmentX = JComponent.LEFT_ALIGNMENT
        copyButton.addActionListener { copyPem(copyButton, info.pem) }
        val buttonRow = JPanel()
        buttonRow.alignmentX = JComponent.LEFT_ALIGNMENT
        buttonRow.add(copyButton)
        card.add(buttonRow)

        return card
    }

    private fun copyPem(button: JButton, pem: String) {
        CopyPasteManager.copyTextToClipboard(pem)
        val original = button.text
        button.text = "Copied"
        button.isEnabled = false
        val timer = Timer(1200) {
            button.text = original
            button.isEnabled = true
        }
        timer.isRepeats = false
        timer.start()
    }

    private fun fieldRow(label: String, value: String, color: Color? = null, monospace: Boolean = false): JComponent {
        val container = JPanel()
        container.layout = BoxLayout(container, BoxLayout.Y_AXIS)
        container.alignmentX = JComponent.LEFT_ALIGNMENT

        val labelComponent = JBLabel(label)
        labelComponent.font = labelComponent.font.deriveFont(Font.BOLD)
        labelComponent.alignmentX = JComponent.LEFT_ALIGNMENT
        container.add(labelComponent)

        val valueComponent = JBLabel(value)
        valueComponent.alignmentX = JComponent.LEFT_ALIGNMENT
        if (monospace) valueComponent.font = Font(Font.MONOSPACED, Font.PLAIN, valueComponent.font.size)
        if (color != null) valueComponent.foreground = color
        container.add(valueComponent)
        container.add(Box.createVerticalStrut(6))

        return container
    }

    override fun getComponent(): JComponent = rootPanel
    override fun getPreferredFocusedComponent(): JComponent = rootPanel
    override fun getName(): String = "Certificate"
    override fun setState(state: FileEditorState) {}
    override fun isModified(): Boolean = false
    override fun isValid(): Boolean = file.isValid
    override fun addPropertyChangeListener(listener: PropertyChangeListener) {}
    override fun removePropertyChangeListener(listener: PropertyChangeListener) {}
    override fun getFile(): VirtualFile = file
    override fun dispose() {}
}
