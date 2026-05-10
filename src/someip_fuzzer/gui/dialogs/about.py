"""关于对话框。"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QVBoxLayout


class AboutDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("关于 VehSecLabs SomeIP Fuzzer")
        self.setFixedSize(400, 280)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 24, 24, 16)

        title = QLabel("<b>VehSecLabs SomeIP Fuzzer</b>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 18px; color: #89b4fa;")

        version = QLabel("版本 v0.5.0")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setStyleSheet("color: #a6adc8;")

        desc = QLabel(
            "面向车载以太网 SOME/IP 服务的自动化模糊测试工具\n"
            "科研课题：TECHKY202503\n"
            "研究方向：车联网安全 / 协议漏洞挖掘"
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #cdd6f4; line-height: 1.6;")

        org = QLabel("© 2025–2026 VehSecLabs")
        org.setAlignment(Qt.AlignmentFlag.AlignCenter)
        org.setStyleSheet("color: #585b70; font-size: 11px;")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)

        layout.addWidget(title)
        layout.addWidget(version)
        layout.addSpacing(8)
        layout.addWidget(desc)
        layout.addStretch()
        layout.addWidget(org)
        layout.addWidget(buttons)
