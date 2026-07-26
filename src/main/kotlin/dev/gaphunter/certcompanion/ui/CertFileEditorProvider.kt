package dev.gaphunter.certcompanion.ui

import com.intellij.openapi.fileEditor.FileEditor
import com.intellij.openapi.fileEditor.FileEditorPolicy
import com.intellij.openapi.fileEditor.FileEditorProvider
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.Locale

class CertFileEditorProvider : FileEditorProvider, DumbAware {

    override fun accept(project: Project, file: VirtualFile): Boolean =
        file.extension?.lowercase(Locale.ROOT) in SUPPORTED_EXTENSIONS

    override fun createEditor(project: Project, file: VirtualFile): FileEditor =
        CertFileEditor(file)

    override fun getEditorTypeId(): String = "cert-companion-viewer"

    // Every extension here is either binary (der/jks/p12/pfx, where the text
    // editor is useless) or exists only to be decoded (pem/crt/cer) — the
    // decoded view is the whole point of opening the file, so it goes first.
    override fun getPolicy(): FileEditorPolicy = FileEditorPolicy.PLACE_BEFORE_DEFAULT_EDITOR

    companion object {
        private val SUPPORTED_EXTENSIONS = setOf("pem", "crt", "cer", "der", "jks", "p12", "pfx")
    }
}
