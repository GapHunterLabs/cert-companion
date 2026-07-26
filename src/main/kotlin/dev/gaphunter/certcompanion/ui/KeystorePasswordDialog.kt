package dev.gaphunter.certcompanion.ui

import com.intellij.openapi.ui.DialogWrapper
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPasswordField
import java.awt.GridLayout
import javax.swing.JComponent
import javax.swing.JPanel

/**
 * Never saves or caches the password between calls — every reopen of a
 * locked keystore asks again, and the caller clears the char array right
 * after KeyStore.load() runs. More friction, zero risk of leaving a secret
 * in memory longer than necessary.
 */
class KeystorePasswordDialog(title: String) : DialogWrapper(true) {
    private val field = JBPasswordField()

    init {
        this.title = title
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(GridLayout(2, 1, 0, 6))
        panel.add(JBLabel("Keystore password:"))
        panel.add(field)
        return panel
    }

    override fun getPreferredFocusedComponent(): JComponent = field

    fun password(): CharArray = field.password
}
