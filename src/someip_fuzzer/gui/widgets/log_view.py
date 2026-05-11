"""Tab 3 日志窗口 — 彩色分级，限制最多 500 行，支持暂停/继续刷新。"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

_MAX_LINES = 500

_LEVEL_COLORS: dict[str, str] = {
    "DEBUG":   "#8C959F",
    "INFO":    "#0969DA",
    "WARNING": "#9A6700",
    "WARN":    "#9A6700",
    "ERROR":   "#CF222E",
    "CRITICAL":"#CF222E",
}


class LogViewWidget(QWidget):
    """彩色日志窗口，最多保留 _MAX_LINES 行。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._paused = False
        self._pending: list[tuple[str, str]] = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("日志"))

        self.btn_pause = QPushButton("暂停")
        self.btn_pause.setCheckable(True)
        self.btn_pause.setFixedWidth(80)
        self.btn_pause.clicked.connect(self._toggle_pause)
        bar.addWidget(self.btn_pause)

        self.btn_clear = QPushButton("清空")
        self.btn_clear.setFixedWidth(60)
        self.btn_clear.clicked.connect(self._clear)
        bar.addWidget(self.btn_clear)
        bar.addStretch()
        layout.addLayout(bar)

        self._text = QTextEdit()
        self._text.setReadOnly(True)
        mono = QFont("Consolas", 10)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self._text.setFont(mono)
        self._text.setMaximumHeight(160)
        layout.addWidget(self._text)

    @pyqtSlot(str, str)
    def append(self, level: str, message: str) -> None:
        """接收一条日志，level 对应 INFO/WARN/ERROR 等。"""
        if self._paused:
            self._pending.append((level, message))
            return
        self._write(level, message)

    def _write(self, level: str, message: str) -> None:
        color_hex = _LEVEL_COLORS.get(level.upper(), "#cdd6f4")
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color_hex))

        cursor = self._text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(f"[{level}] {message}\n", fmt)

        # 超出最大行数时删除最旧的行
        doc = self._text.document()
        while doc.lineCount() > _MAX_LINES:
            cursor = QTextCursor(doc.begin())
            cursor.select(QTextCursor.SelectionType.LineUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()  # 删换行符

        self._text.verticalScrollBar().setValue(
            self._text.verticalScrollBar().maximum()
        )

    @pyqtSlot()
    def _toggle_pause(self) -> None:
        self._paused = self.btn_pause.isChecked()
        self.btn_pause.setText("继续" if self._paused else "暂停")
        if not self._paused:
            for level, msg in self._pending:
                self._write(level, msg)
            self._pending.clear()

    @pyqtSlot()
    def _clear(self) -> None:
        self._text.clear()
        self._pending.clear()
