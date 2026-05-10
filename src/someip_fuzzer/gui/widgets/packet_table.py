"""Tab 2 虚拟报文列表模型 — QAbstractTableModel + 环形缓冲区。"""

from __future__ import annotations

import collections
import time
from dataclasses import dataclass
from typing import Any

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QColor

from someip_fuzzer.core.protocol import SomeIpPacket

_COL_NO = 0
_COL_TIME = 1
_COL_DIR = 2
_COL_SRV = 3
_COL_METHOD = 4
_COL_LEN = 5
_COL_TYPE = 6
_COLUMNS = ["#", "时间", "方向", "Service ID", "Method ID", "长度", "类型"]

_COLOR_SENT = QColor("#89dceb")      # 发出（cyan）
_COLOR_RECV = QColor("#a6e3a1")      # 收到（green）
_COLOR_CRASH = QColor("#f38ba8")     # 崩溃（red）


@dataclass
class PacketRow:
    no: int
    timestamp: float
    direction: str          # "→" 发送 / "←" 接收
    service_id: int
    method_id: int
    length: int
    msg_type: str
    is_crash: bool = False
    raw: bytes = b""


def _fmt_hex(val: int) -> str:
    return f"0x{val:04X}"


class PacketTableModel(QAbstractTableModel):
    """虚拟表格模型，仅渲染可视区域，缓冲最近 capacity 条记录。"""

    def __init__(self, capacity: int = 10000, parent=None) -> None:
        super().__init__(parent)
        self._buf: collections.deque[PacketRow] = collections.deque(maxlen=capacity)
        self._counter = 0
        self._start_time = time.monotonic()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._buf)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(_COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return _COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or index.row() >= len(self._buf):
            return None
        row = self._buf[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            match col:
                case _ if col == _COL_NO:    return str(row.no)
                case _ if col == _COL_TIME:  return f"{row.timestamp:.3f}"
                case _ if col == _COL_DIR:   return row.direction
                case _ if col == _COL_SRV:   return _fmt_hex(row.service_id)
                case _ if col == _COL_METHOD: return _fmt_hex(row.method_id)
                case _ if col == _COL_LEN:   return str(row.length)
                case _ if col == _COL_TYPE:  return row.msg_type
            return None

        if role == Qt.ItemDataRole.BackgroundRole:
            if row.is_crash:
                return _COLOR_CRASH
            return _COLOR_SENT if row.direction == "→" else _COLOR_RECV

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (_COL_NO, _COL_LEN):
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.UserRole:
            return row

        return None

    def get_row(self, row_index: int) -> PacketRow | None:
        if 0 <= row_index < len(self._buf):
            return self._buf[row_index]
        return None

    def append_batch(self, rows: list[PacketRow]) -> None:
        if not rows:
            return
        first = len(self._buf)
        self.beginInsertRows(QModelIndex(), first, first + len(rows) - 1)
        self._buf.extend(rows)
        self.endInsertRows()

    def add_packet(self, pkt: SomeIpPacket, direction: str = "→", is_crash: bool = False) -> PacketRow:
        self._counter += 1
        elapsed = time.monotonic() - self._start_time
        row = PacketRow(
            no=self._counter,
            timestamp=elapsed,
            direction=direction,
            service_id=pkt.service_id,
            method_id=pkt.method_id,
            length=len(pkt.to_bytes()),
            msg_type=pkt.message_type.name,
            is_crash=is_crash,
            raw=pkt.to_bytes(),
        )
        self.append_batch([row])
        return row

    def add_raw(self, raw: bytes, direction: str = "→", is_crash: bool = False) -> PacketRow:
        self._counter += 1
        elapsed = time.monotonic() - self._start_time
        row = PacketRow(
            no=self._counter,
            timestamp=elapsed,
            direction=direction,
            service_id=0,
            method_id=0,
            length=len(raw),
            msg_type="RAW",
            is_crash=is_crash,
            raw=raw,
        )
        self.append_batch([row])
        return row

    def clear(self) -> None:
        self.beginResetModel()
        self._buf.clear()
        self._counter = 0
        self.endResetModel()
