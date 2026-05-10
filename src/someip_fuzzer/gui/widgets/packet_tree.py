"""Tab 2 报文字段树 — 将 SomeIpPacket 解析为可折叠树形视图。"""

from __future__ import annotations

from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem

from someip_fuzzer.core.protocol import SomeIpPacket
from someip_fuzzer.gui.widgets.packet_table import PacketRow

# (字段名, 起始字节, 长度字节) — 对应 SOME/IP 16 字节固定头
_HEADER_FIELDS = [
    ("Service ID",       0,  2),
    ("Method ID",        2,  2),
    ("Length",           4,  4),
    ("Client ID",        8,  2),
    ("Session ID",       10, 2),
    ("Protocol Version", 12, 1),
    ("Interface Version",13, 1),
    ("Message Type",     14, 1),
    ("Return Code",      15, 1),
]


class PacketTreeWidget(QTreeWidget):
    """报文字段树，选中报文后调用 show_row() / show_packet() 填充。"""

    # 选中字段时通知外部（用于 HexView 联动高亮）
    # emit: (start_byte, length)
    field_selected: tuple[int, int] | None = None

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setHeaderLabels(["字段", "值", "偏移", "长度"])
        self.setAlternatingRowColors(True)
        self.setColumnWidth(0, 160)
        self.setColumnWidth(1, 120)
        self.setColumnWidth(2, 50)
        self.setColumnWidth(3, 50)
        self.itemClicked.connect(self._on_item_clicked)
        self._hex_callback = None  # type: ignore

    def set_hex_highlight_callback(self, cb) -> None:
        """注册当字段被选中时调用的回调 cb(start, length)。"""
        self._hex_callback = cb

    def _on_item_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        start = item.data(0, 100)   # UserRole+0 存 start
        length = item.data(0, 101)  # UserRole+1 存 length
        if start is not None and self._hex_callback:
            self._hex_callback(start, length)

    def show_row(self, row: PacketRow) -> None:
        """用 PacketRow.raw 填充字段树。"""
        self.clear()
        raw = row.raw
        if not raw:
            return
        self._populate(raw)

    def show_packet(self, pkt: SomeIpPacket) -> None:
        """用 SomeIpPacket 填充字段树（调试用）。"""
        self.show_row_bytes(pkt.to_bytes())

    def show_row_bytes(self, raw: bytes) -> None:
        self.clear()
        self._populate(raw)

    def _populate(self, raw: bytes) -> None:
        root_header = QTreeWidgetItem(self, ["SOME/IP Header", "", "0", "16"])
        root_header.setExpanded(True)

        for name, start, length in _HEADER_FIELDS:
            end = start + length
            chunk = raw[start:end] if len(raw) >= end else b""
            hex_val = chunk.hex().upper()
            dec_val = int.from_bytes(chunk, "big") if chunk else 0
            display = f"0x{hex_val}  ({dec_val})"
            item = QTreeWidgetItem(root_header, [name, display, str(start), str(length)])
            item.setData(0, 100, start)
            item.setData(0, 101, length)

        if len(raw) > 16:
            payload = raw[16:]
            payload_item = QTreeWidgetItem(self, ["Payload", f"{len(payload)} bytes", "16", str(len(payload))])
            payload_item.setData(0, 100, 16)
            payload_item.setData(0, 101, len(payload))
            payload_item.setExpanded(False)

            # 每行 8 字节展示
            for i in range(0, min(len(payload), 64), 8):
                chunk = payload[i:i+8]
                hex_str = " ".join(f"{b:02X}" for b in chunk)
                QTreeWidgetItem(payload_item, [f"+{i}", hex_str, str(16 + i), str(len(chunk))])
