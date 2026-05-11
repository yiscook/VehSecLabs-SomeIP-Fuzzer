"""左侧项目树 Dock — 显示历史会话列表。"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDockWidget,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)


class ProjectTreeDock(QDockWidget):
    """左侧可折叠项目树，列出历史测试会话。"""

    session_selected = pyqtSignal(str)  # session_id

    def __init__(self, parent=None) -> None:
        super().__init__("项目 / 历史会话", parent)
        self.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)
        self.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetClosable
            | QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable
        )

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setAlternatingRowColors(True)
        self._tree.itemClicked.connect(self._on_item_clicked)

        self._btn_clear = QPushButton("清空历史")
        self._btn_clear.clicked.connect(self._clear_history)

        layout.addWidget(QLabel("历史会话"))
        layout.addWidget(self._tree)
        layout.addWidget(self._btn_clear)
        self.setWidget(content)

        self._populate_placeholder()

    def _populate_placeholder(self) -> None:
        sessions = QTreeWidgetItem(self._tree, ["测试会话"])
        sessions.setExpanded(True)
        QTreeWidgetItem(sessions, ["（暂无历史记录）"])

    def add_session(self, session_id: str, label: str) -> None:
        root = self._tree.topLevelItem(0)
        if root is None:
            return
        if root.child(0) and root.child(0).text(0) == "（暂无历史记录）":
            root.takeChild(0)
        item = QTreeWidgetItem(root, [label])
        item.setData(0, Qt.ItemDataRole.UserRole, session_id)
        root.setExpanded(True)

    def _on_item_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        session_id = item.data(0, Qt.ItemDataRole.UserRole)
        if session_id:
            self.session_selected.emit(session_id)

    def _clear_history(self) -> None:
        self._tree.clear()
        self._populate_placeholder()
