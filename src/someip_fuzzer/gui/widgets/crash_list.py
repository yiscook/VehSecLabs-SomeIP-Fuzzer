"""崩溃列表 QTableView + 虚拟 model，按 CVSS 颜色标注。"""

from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from someip_fuzzer.data.crash_store import CrashRecord

_COLUMNS = ["#", "时间", "严重度", "策略", "CVSS", "检测方式"]

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_COLORS = {
    "critical": QColor("#f38ba8"),
    "high":     QColor("#fab387"),
    "medium":   QColor("#f9e2af"),
    "low":      QColor("#a6e3a1"),
}


class CrashListModel(QAbstractTableModel):
    """崩溃记录虚拟表格模型。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._records: list[CrashRecord] = []

    def load(self, records: list[CrashRecord]) -> None:
        self.beginResetModel()
        self._records = list(records)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._records)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(_COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role=Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return _COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or index.row() >= len(self._records):
            return None
        rec = self._records[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            match col:
                case 0: return str(index.row() + 1)
                case 1: return rec.timestamp[:19].replace("T", " ")
                case 2: return rec.severity.upper()
                case 3: return rec.mutator_name
                case 4: return f"{rec.cvss_score:.1f}"
                case 5: return rec.detection_method
            return None

        if role == Qt.ItemDataRole.BackgroundRole:
            return _SEVERITY_COLORS.get(rec.severity)

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 4):
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.UserRole:
            return rec

        return None

    def get_record(self, row: int) -> CrashRecord | None:
        if 0 <= row < len(self._records):
            return self._records[row]
        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        self.beginResetModel()
        reverse = order == Qt.SortOrder.DescendingOrder
        match column:
            case 1: key = lambda r: r.timestamp
            case 2: key = lambda r: _SEVERITY_ORDER.get(r.severity, 99)
            case 3: key = lambda r: r.mutator_name
            case 4: key = lambda r: r.cvss_score
            case _: key = lambda r: r.timestamp
        self._records.sort(key=key, reverse=reverse)
        self.endResetModel()


class CrashListWidget(QWidget):
    """崩溃列表面板，选中时发出 crash_selected 信号。"""

    crash_selected = pyqtSignal(object)  # CrashRecord

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._model = CrashListModel()
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableView()
        self.table.setModel(self._model)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setShowGrid(False)
        self.table.selectionModel().currentRowChanged.connect(self._on_row_changed)
        layout.addWidget(self.table)

    def _on_row_changed(self, current, _prev) -> None:
        rec = self._model.get_record(current.row())
        if rec:
            self.crash_selected.emit(rec)

    def load(self, records: list[CrashRecord]) -> None:
        self._model.load(records)

    @property
    def model(self) -> CrashListModel:
        return self._model
