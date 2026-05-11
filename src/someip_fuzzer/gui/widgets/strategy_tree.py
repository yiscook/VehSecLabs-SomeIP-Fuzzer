"""Tab 3 变异策略树 — 从 MUTATOR_REGISTRY 动态加载，按 Layer/Field 分组多选。"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)


class StrategyTreeWidget(QWidget):
    """变异策略选择树。

    信号 selection_changed(list[str]) 在勾选状态变化时发出，携带当前启用的变异器名列表。
    """

    selection_changed = pyqtSignal(list)  # list[str] 已启用的变异器名

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._tree = QTreeWidget()
        self._lbl_count = QLabel("启用: 0 / 0")
        self._build_ui()
        self._load_mutators()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        layout.addWidget(QLabel("变异策略"))
        layout.addWidget(self._tree)

        btn_row = QHBoxLayout()
        btn_all = QPushButton("全选")
        btn_all.clicked.connect(self._check_all)
        btn_none = QPushButton("全不选")
        btn_none.clicked.connect(self._uncheck_all)
        btn_row.addWidget(btn_all)
        btn_row.addWidget(btn_none)
        layout.addLayout(btn_row)
        layout.addWidget(self._lbl_count)

        self._tree.setHeaderHidden(True)
        self._tree.setAlternatingRowColors(True)
        self._tree.itemChanged.connect(self._on_item_changed)

    def _load_mutators(self) -> None:
        """从 MUTATOR_REGISTRY 读取所有变异器，按 (layer, target_field) 分组。"""
        try:
            from someip_fuzzer.core.mutators import (  # noqa: F401 — 触发注册
                layer1_fields, layer1_payload, layer2_semantic, layer2_sd, layer3_state,
            )
            from someip_fuzzer.core.mutator import MUTATOR_REGISTRY
        except ImportError:
            return

        # 按 (layer, target_field) 分组
        groups: dict[tuple[int, str], list] = {}
        for cls in MUTATOR_REGISTRY.values():
            key = (cls.layer, cls.target_field)
            groups.setdefault(key, []).append(cls)

        self._tree.blockSignals(True)
        for (layer, field), mutator_classes in sorted(groups.items()):
            group_item = QTreeWidgetItem(self._tree)
            group_item.setText(0, f"Layer {layer}  —  {field}")
            group_item.setFlags(group_item.flags() | Qt.ItemFlag.ItemIsAutoTristate | Qt.ItemFlag.ItemIsUserCheckable)
            group_item.setCheckState(0, Qt.CheckState.Checked)
            group_item.setExpanded(False)

            for cls in sorted(mutator_classes, key=lambda c: c.name):
                child = QTreeWidgetItem(group_item)
                child.setText(0, cls.name)
                child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                child.setCheckState(0, Qt.CheckState.Checked)
                child.setData(0, Qt.ItemDataRole.UserRole, cls.name)
                child.setToolTip(0, f"strategy: {cls.strategy}")

        self._tree.blockSignals(False)
        self._update_count_label()

    def _on_item_changed(self, item: QTreeWidgetItem, _col: int) -> None:
        self._update_count_label()
        self.selection_changed.emit(self.enabled_names())

    def _check_all(self) -> None:
        self._set_all(Qt.CheckState.Checked)

    def _uncheck_all(self) -> None:
        self._set_all(Qt.CheckState.Unchecked)

    def _set_all(self, state: Qt.CheckState) -> None:
        self._tree.blockSignals(True)
        root = self._tree.invisibleRootItem()
        for i in range(root.childCount()):
            grp = root.child(i)
            grp.setCheckState(0, state)
            for j in range(grp.childCount()):
                grp.child(j).setCheckState(0, state)
        self._tree.blockSignals(False)
        self._update_count_label()
        self.selection_changed.emit(self.enabled_names())

    def _update_count_label(self) -> None:
        enabled = self.enabled_names()
        total = sum(
            self._tree.invisibleRootItem().child(i).childCount()
            for i in range(self._tree.invisibleRootItem().childCount())
        )
        self._lbl_count.setText(f"启用: {len(enabled)} / {total}")

    def enabled_names(self) -> list[str]:
        """返回当前勾选的变异器名列表。"""
        result: list[str] = []
        root = self._tree.invisibleRootItem()
        for i in range(root.childCount()):
            grp = root.child(i)
            for j in range(grp.childCount()):
                child = grp.child(j)
                if child.checkState(0) == Qt.CheckState.Checked:
                    name = child.data(0, Qt.ItemDataRole.UserRole)
                    if name:
                        result.append(name)
        return result
