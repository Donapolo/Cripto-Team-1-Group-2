import json
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QFileDialog, QLineEdit, QTextEdit, QMessageBox
)
from src.crypto.hybrid_vault import verify_container
from src.crypto.signature_manager import SignatureVerificationError

class SignaturesView(QWidget):
    def __init__(self):
        super().__init__()
        self.container_data = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Título
        title = QLabel("Signature Verification (D5/D6)")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)

        # Botón para cargar archivo
        self.btn_load = QPushButton("Load D5 Container (.json)")
        self.btn_load.clicked.connect(self.load_container)
        layout.addWidget(self.btn_load)

        # Etiqueta de estado del archivo
        self.lbl_file_status = QLabel("No container loaded.")
        layout.addWidget(self.lbl_file_status)

        # Input para la llave pública del firmante confiable (Trust Anchor)
        layout.addWidget(QLabel("Trusted Signer Public Key (Hex):"))
        self.txt_pubkey = QLineEdit()
        self.txt_pubkey.setPlaceholderText("Paste the trusted Ed25519 public key here...")
        layout.addWidget(self.txt_pubkey)

        # Botón para verificar
        self.btn_verify = QPushButton("Verify Signature")
        self.btn_verify.setEnabled(False)
        self.btn_verify.clicked.connect(self.verify_signature)
        layout.addWidget(self.btn_verify)

        # Área de resultados
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

        pubkey = self.txt_pubkey.text().strip()
        if not pubkey:
            QMessageBox.warning(self, "Warning", "Please provide the trusted signer public key.")
            return

        try:
            # Llamada al backend criptográfico existente
            verify_container(self.container_data, pubkey)
            
            signer_id = self.container_data.get("signer_id", "Unknown")
            self.txt_results.setHtml(f"""
                <h3 style='color: green;'>✅ Signature Valid</h3>
                <p><b>Signer ID:</b> {signer_id}</p>
                <p>The document signature is authentic and matches the provided public key.</p>
            """)
        except SignatureVerificationError as e:
            self.txt_results.setHtml(f"""
                <h3 style='color: red;'>❌ Signature Invalid</h3>
                <p><b>Reason:</b> {str(e)}</p>
                <p>The container may have been tampered with, or the public key is incorrect.</p>
            """)
        except Exception as e:
            self.txt_results.setHtml(f"<h3 style='color: orange;'>⚠ Error</h3><p>{str(e)}</p>")