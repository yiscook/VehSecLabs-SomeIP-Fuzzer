"""Tab 3 高性能实时报文流 — 5 层机制叠加，1000 pps 下 GUI 不卡顿。

机制：
  1. QAbstractTableModel 虚拟渲染（只绘可视行）
  2. deque(maxlen=5000) 环形缓冲
  3. BatchedUpdater：100 ms 批量刷新
  4. 暂停标志位：停显示不停发包
  5. 颜色编码：蓝发送 / 绿正常 / 黄超时 / 红崩溃
"""

from __future__ import annotations

import collections
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QObject, QTimer, Qt, pyqtSlot
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from someip_fuzzer.gui.widgets.packet_table import PacketRow


class PacketStatus(Enum):
    SENT = "发送"
    OK = "正常"
    TIMEOUT = "超时"
    CRASH = "崩溃"


_COLOR_MAP = {
    PacketStatus.SENT:    QBrush(QColor("#DBEAFE")),  # 淡蓝
    PacketStatus.OK:      QBrush(QColor("#DCFCE7")),  # 淡绿
    PacketStatus.TIMEOUT: QBrush(QColor("#FEF9C3")),  # 淡黄
    PacketStatus.CRASH:   QBrush(QColor("#FEE2E2")),  # 淡红
}

_COLUMNS = ["#", "时间", "方向", "Service ID", "Method ID", "长度", "状态"]


@dataclass
class StreamRow:
    no: int
    timestamp: float
    status: PacketStatus
    service_id: int
    method_id: int
    length: int
    raw: bytes = field(default=b"", repr=False)


def _fmt_hex(v: int) -> str:
    return f"0x{v:04X}"


class PacketStreamModel(QAbstractTableModel):
    """虚拟表格模型，维护最近 capacity 条报文。"""

    def __init__(self, capacity: int = 5000, parent=None) -> None:
        super().__init__(parent)
        self._buf: collections.deque[StreamRow] = collections.deque(maxlen=capacity)
        self._counter = 0
        self._start = time.monotonic()

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
                case 0: return str(row.no)
                case 1: return f"{row.timestamp:.3f}"
                case 2: return row.status.value
                case 3: return _fmt_hex(row.service_id)
                case 4: return _fmt_hex(row.method_id)
                case 5: return str(row.length)
                case 6: return row.status.name
            return None

        if role == Qt.ItemDataRole.BackgroundRole:
            return _COLOR_MAP.get(row.status)

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 5):
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.UserRole:
            return row

        return None

    def get_row(self, row_index: int) -> StreamRow | None:
        if 0 <= row_index < len(self._buf):
            return self._buf[row_index]
        return None

    def append_batch(self, rows: list[StreamRow]) -> None:
        if not rows:
            return
        n_before = len(self._buf)
        self._buf.extend(rows)
        n_after = len(self._buf)
        if n_before == self._buf.maxlen:
            # deque 已满，旧条目被淘汰，总行数不变 — 用 resetModel 避免行计数失步
            self.beginResetModel()
            self.endResetModel()
        else:
            self.beginInsertRows(QModelIndex(), n_before, n_after - 1)
            self.endInsertRows()

    def make_row(self, status: PacketStatus, service_id: int, method_id: int,
                 length: int, raw: bytes = b"") -> StreamRow:
        self._counter += 1
        return StreamRow(
            no=self._counter,
            timestamp=time.monotonic() - self._start,
            status=status,
            service_id=service_id,
            method_id=method_id,
            length=length,
            raw=raw,
        )

    def clear(self) -> None:
        self.beginResetModel()
        self._buf.clear()
        self._counter = 0
        self.endResetModel()

    @property
    def total(self) -> int:
        return self._counter


class BatchedUpdater(QObject):
    """将零散的 StreamRow 攒成批次，每 interval_ms 毫秒刷新一次模型。"""

    def __init__(self, model: PacketStreamModel, interval_ms: int = 100, parent=None) -> None:
        super().__init__(parent)
        self._model = model
        self._pending: list[StreamRow] = []
        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self.flush)
        self._timer.start()

    def add(self, row: StreamRow) -> None:
        self._pending.append(row)

    @pyqtSlot()
    def flush(self) -> None:
        if self._pending:
            self._model.append_batch(self._pending)
            self._pending.clear()

    def stop(self) -> None:
        self._timer.stop()


class PacketStreamWidget(QWidget):
    """Tab 3 实时报文流区域。

    公开 API：
    - add_sent(service_id, method_id, length, raw) — 发送报文
    - add_received(service_id, method_id, length, is_timeout) — 收到响应/超时
    - add_crash(service_id, method_id, length) — 崩溃报文
    - is_paused() — 当前是否暂停显示
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._model = PacketStreamModel(capacity=5000)
        self._updater = BatchedUpdater(self._model, interval_ms=100, parent=self)
        self._paused = False
        self._auto_scroll = True
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # 工具栏
        bar = QHBoxLayout()
        self.btn_pause = QPushButton("暂停显示")
        self.btn_pause.setCheckable(True)
        self.btn_pause.clicked.connect(self._toggle_pause)
        bar.addWidget(self.btn_pause)

        self.chk_autoscroll = QCheckBox("自动滚动")
        self.chk_autoscroll.setChecked(True)
        self.chk_autoscroll.toggled.connect(self._on_autoscroll_toggled)
        bar.addWidget(self.chk_autoscroll)

        bar.addWidget(QLabel("过滤："))
        self.edit_filter = QLineEdit()
        self.edit_filter.setPlaceholderText("关键字 / 状态（crash/timeout）")
        self.edit_filter.setFixedWidth(180)
        self.edit_filter.textChanged.connect(self._apply_filter)
        bar.addWidget(self.edit_filter)

        bar.addStretch()
        self.lbl_total = QLabel("共 0 条")
        bar.addWidget(self.lbl_total)
        layout.addLayout(bar)

        # 表格
        self.table = QTableView()
        self.table.setModel(self._model)
        self.table.setAlternatingRowColors(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setShowGrid(False)
        layout.addWidget(self.table)

        # 当模型行数变化时更新计数并自动滚动
        self._model.rowsInserted.connect(self._on_rows_inserted)

    # ── 槽函数 ────────────────────────────────────────────────────────────────

    @pyqtSlot()
    def _toggle_pause(self) -> None:
        self._paused = self.btn_pause.isChecked()
        self.btn_pause.setText("继续显示" if self._paused else "暂停显示")

    def _on_autoscroll_toggled(self, checked: bool) -> None:
        self._auto_scroll = checked

    def _on_rows_inserted(self, _parent, first: int, last: int) -> None:
        self.lbl_total.setText(f"共 {self._model.total} 条")
        if self._auto_scroll and not self._paused:
            self.table.scrollToBottom()

    def _apply_filter(self, kw: str) -> None:
        kw = kw.strip().lower()
        for i in range(len(self._model._buf)):
            row = self._model.get_row(i)
            if row is None:
                continue
            show = (
                not kw
                or kw in f"0x{row.service_id:04x}"
                or kw in f"0x{row.method_id:04x}"
                or kw in row.status.name.lower()
            )
            self.table.setRowHidden(i, not show)

    # ── 公开 API ─────────────────────────────────────────────────────────────

    def add_sent(self, service_id: int, method_id: int, length: int, raw: bytes = b"") -> None:
        if self._paused:
            return
        row = self._model.make_row(PacketStatus.SENT, service_id, method_id, length, raw)
        self._updater.add(row)

    def add_received(self, service_id: int, method_id: int, length: int,
                     is_timeout: bool = False) -> None:
        if self._paused:
            return
        status = PacketStatus.TIMEOUT if is_timeout else PacketStatus.OK
        row = self._model.make_row(status, service_id, method_id, length)
        self._updater.add(row)

    def add_crash(self, service_id: int, method_id: int, length: int, raw: bytes = b"") -> None:
        # 崩溃即使暂停也要显示
        row = self._model.make_row(PacketStatus.CRASH, service_id, method_id, length, raw)
        self._updater.add(row)
        self._updater.flush()  # 立即刷新，不等下一个 100ms 周期

    def clear(self) -> None:
        self._updater.flush()
        self._model.clear()

    def is_paused(self) -> bool:
        return self._paused
