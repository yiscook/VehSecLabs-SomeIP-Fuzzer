"""Tab 3 状态机可视化 — 文本渲染 export_mermaid() 输出并高亮当前状态。"""

from __future__ import annotations

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QLabel, QPlainTextEdit, QVBoxLayout, QWidget


class StateViewWidget(QWidget):
    """状态机文本可视化面板。

    使用等宽字体显示 export_mermaid() 的输出，并在每次状态变化时高亮对应行。
    （Phase 8 联调时可升级为 graphviz SVG 渲染）
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._current_state: str = ""
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        layout.addWidget(QLabel("🔄  服务状态机"))

        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        mono = QFont("Consolas", 10)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self._text.setFont(mono)
        self._text.setMaximumHeight(220)
        self._text.setPlaceholderText("等待状态机数据…")
        layout.addWidget(self._text)

        self._lbl_current = QLabel("当前状态：—")
        self._lbl_current.setStyleSheet("font-weight: bold; color: #a6e3a1;")
        layout.addWidget(self._lbl_current)

    def update_mermaid(self, mermaid_str: str) -> None:
        """更新 Mermaid 图文本内容（由 state_machine.export_mermaid() 产生）。"""
        self._text.setPlainText(mermaid_str)

    def update_state(self, service_id: str, new_state: str) -> None:
        """高亮显示最新状态迁移。"""
        self._current_state = new_state
        self._lbl_current.setText(f"当前状态：{service_id}  →  {new_state}")

    def set_all_states(self, states: dict) -> None:
        """接收 get_all_states() 的字典，逐服务实例显示状态。"""
        if not states:
            return
        lines = [f"{str(inst)}: {state.value}" for inst, state in states.items()]
        self._lbl_current.setText("  |  ".join(lines))
