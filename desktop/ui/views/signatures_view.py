import json
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, 
    QFileDialog, QTextEdit, QMessageBox
)
from desktop.ui.dialogs.password_dialog import ask_password, PasswordCancelled
from src.crypto.signature_manager import verify_container_with_registry, SignatureVerificationError
from src.crypto.key_lifecycle import KeyLifecycleError

class SignaturesView(QWidget):
    def __init__(self, context, parent=None):
        super().__init__(parent)
        self.context = context
        self.container_data = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        
        title = QLabel("Signature & D6 Registry Verification")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)

        self.btn_load = QPushButton("1. Load D5 Container (.json)")
        self.btn_load.clicked.connect(self.load_container)
        layout.addWidget(self.btn_load)

        self.lbl_file_status = QLabel("No container loaded.")
        layout.addWidget(self.lbl_file_status)

        self.btn_verify = QPushButton("2. Verify Signature & D6 Status")
        self.btn_verify.setEnabled(False)
        self.btn_verify.clicked.connect(self.verify_signature)
        layout.addWidget(self.btn_verify)

        layout.addWidget(QLabel("Verification Results:"))
        self.txt_results = QTextEdit()
        self.txt_results.setReadOnly(True)
        layout.addWidget(self.txt_results)

    def load_container(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open D5 Container", "", "JSON Files (*.json)")
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                self.container_data = json.load(f)
            self.lbl_file_status.setText(f"Loaded: {file_path.split('/')[-1]}")
            self.btn_verify.setEnabled(True)
            self.txt_results.clear()
            self.txt_results.append("Container loaded successfully. Ready to verify.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load file:\n{str(e)}")
            self.container_data = None
            self.btn_verify.setEnabled(False)

    def verify_signature(self):
        if not self.container_data:
            return

        # 1. Pedimos la contraseña del registro usando el diálogo de Yuki
        password = ask_password(
            self, 
            title="Registry Password", 
            message="Enter the password to unlock the D6 Registry and check the signer's status:"
        )
        
        if password is None:  # El usuario canceló
            return

        try:
            # 2. Creamos el servicio (esto valida la contraseña del registro)
            service = self.context.make_service(password)
            registry = service.registry()
            
            # 3. Verificamos firma y estado D6
            verify_container_with_registry(registry, self.container_data)
            
            signer_id = self.container_data.get("signer_id", "Unknown")
            self.txt_results.setHtml(f"""
                <h3 style='color: green;'>✅ Signature Valid</h3>
                <p><b>Signer ID:</b> {signer_id}</p>
                <p>The signature is authentic and the signer is active in the D6 registry.</p>
            """)
        except KeyLifecycleError as e:
            # Captura errores de llave revocada, expirada o contraseña incorrecta del registro
            msg = str(e)
            if "integrity check failed" in msg.lower() or "wrong password" in msg.lower():
                title = "❌ Registry Unlock Failed"
                desc = "Incorrect registry password or file was modified."
            else:
                title = "❌ Signer Rejected (D6 Policy)"
                desc = "The signer key may be revoked or expired."
            
            self.txt_results.setHtml(f"""
                <h3 style='color: red;'>{title}</h3>
                <p><b>Reason:</b> {msg}</p>
                <p>{desc}</p>
            """)
        except SignatureVerificationError as e:
            self.txt_results.setHtml(f"""
                <h3 style='color: red;'>❌ Invalid Signature</h3>
                <p><b>Reason:</b> {str(e)}</p>
                <p>The document has been tampered with or forged.</p>
            """)
        except Exception as e:
            self.txt_results.setHtml(f"<h3 style='color: orange;'>⚠ Error</h3><p>{str(e)}</p>")