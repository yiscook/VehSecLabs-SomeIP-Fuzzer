"""Tab 2 Hex View — 左侧字节流，右侧 ASCII，支持字段区间高亮。"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QTextCharFormat, QTextCursor, QColor
from PyQt6.QtWidgets import QHBoxLayout, QTextEdit, QWidget

_BYTES_PER_ROW = 16
_HIGHLIGHT_BG = QColor("#fab387")   # 橙色高亮（深色/亮色均可见）
_NORMAL_BG = QColor(0, 0, 0, 0)    # 透明（跟随主题）


class HexView(QWidget):
    """双栏 Hex 显示控件。

    左：``addr  XX XX XX ...``（每行 16 字节）
    右：ASCII 可见字符
    支持按字节范围高亮（与 PacketTreeWidget 联动）。
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        mono = QFont("Consolas", 10)
        mono.setStyleHint(QFont.StyleHint.Monospace)

        self._hex_edit = QTextEdit()
        self._hex_edit.setReadOnly(True)
        self._hex_edit.setFont(mono)
        self._hex_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self._hex_edit.setFixedWidth(540)

        self._ascii_edit = QTextEdit()
        self._ascii_edit.setReadOnly(True)
        self._ascii_edit.setFont(mono)
        self._ascii_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        layout.addWidget(self._hex_edit)
        layout.addWidget(self._ascii_edit)

        self._raw: bytes = b""

    def load(self, raw: bytes) -> None:
        """加载原始字节并渲染。"""
        self._raw = raw
        self._render()

    def highlight(self, start: int, length: int) -> None:
        """高亮 [start, start+length) 字节区间。"""
        if not self._raw:
            return
        self._render(highlight_start=start, highlight_len=length)

    def _render(self, highlight_start: int = -1, highlight_len: int = 0) -> None:
        raw = self._raw
        hex_lines: list[str] = []
        asc_lines: list[str] = []

        for row_start in range(0, len(raw), _BYTES_PER_ROW):
            chunk = raw[row_start:row_start + _BYTES_PER_ROW]
            addr = f"{row_start:04X}: "
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            hex_part = hex_part.ljust(_BYTES_PER_ROW * 3 - 1)
            asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_lines.append(addr + hex_part)
            asc_lines.append(asc_part)

        self._hex_edit.setPlainText("\n".join(hex_lines))
        self._ascii_edit.setPlainText("\n".join(asc_lines))

        if highlight_start >= 0 and highlight_len > 0:
            self._apply_highlight(highlight_start, highlight_len)

    def _apply_highlight(self, start: int, length: int) -> None:
        """在 hex 区域高亮对应字节（按行列位置计算字符偏移）。"""
        fmt_on = QTextCharFormat()
        fmt_on.setBackground(_HIGHLIGHT_BG)
        fmt_off = QTextCharFormat()
        fmt_off.setBackground(_NORMAL_BG)

        doc = self._hex_edit.document()
        cursor = QTextCursor(doc)

        # 先清除所有高亮
        cursor.select(QTextCursor.SelectionType.Document)
        cursor.setCharFormat(fmt_off)

        # 逐字节计算 hex 文本中的字符位置并高亮
        for byte_idx in range(start, min(start + length, len(self._raw))):
            row = byte_idx // _BYTES_PER_ROW
            col = byte_idx % _BYTES_PER_ROW
            # 每行格式："AAAA: XX XX ..."
            # 地址前缀 6 字符，每字节 3 字符（"XX "）
            line_start_char = row * (_BYTES_PER_ROW * 3 + 6)  # 包含换行符补偿
            # 计算该行在 document 中的实际起始
            block = doc.findBlockByLineNumber(row)
            if not block.isValid():
                continue
            block_pos = block.position()
            # 列偏移：地址(6) + col*3
            char_pos = block_pos + 6 + col * 3

            cursor.setPosition(char_pos)
            cursor.setPosition(char_pos + 2, QTextCursor.MoveMode.KeepAnchor)
            cursor.setCharFormat(fmt_on)
