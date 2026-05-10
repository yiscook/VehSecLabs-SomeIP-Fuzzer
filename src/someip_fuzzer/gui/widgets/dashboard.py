"""崩溃统计仪表盘 — PyQtGraph 条形图（Layer 分布 + 高频字段 Top 5）。"""

from __future__ import annotations

import collections
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget

try:
    import pyqtgraph as pg
    _PG = True
except ImportError:
    _PG = False

from someip_fuzzer.data.crash_store import CrashRecord


class DashboardWidget(QWidget):
    """统计仪表盘，接受 CrashRecord 列表后渲染两个条形图。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(QLabel("📊  崩溃统计"))

        if not _PG:
            layout.addWidget(QLabel("（需安装 pyqtgraph）"))
            return

        pg.setConfigOption("background", "#1e1e2e")
        pg.setConfigOption("foreground", "#cdd6f4")

        self._win = pg.GraphicsLayoutWidget()
        self._win.setMinimumHeight(240)

        # 上：Layer 分布
        self._plot_layer = self._win.addPlot(title="按 Layer 分布")
        self._plot_layer.setLabel("left", "崩溃数")
        self._bars_layer = pg.BarGraphItem(x=[], height=[], width=0.6, brush="#89b4fa")
        self._plot_layer.addItem(self._bars_layer)
        self._plot_layer.getAxis("bottom").setTicks([])

        self._win.nextRow()

        # 下：高频字段 Top 5
        self._plot_field = self._win.addPlot(title="高频触发字段 Top 5")
        self._plot_field.setLabel("left", "次数")
        self._bars_field = pg.BarGraphItem(x=[], height=[], width=0.6, brush="#f38ba8")
        self._plot_field.addItem(self._bars_field)
        self._plot_field.getAxis("bottom").setTicks([])

        layout.addWidget(self._win)

        # 数字摘要标签
        self.lbl_summary = QLabel("暂无数据")
        self.lbl_summary.setStyleSheet("font-size: 10pt; color: #a6adc8;")
        self.lbl_summary.setWordWrap(True)
        layout.addWidget(self.lbl_summary)

    def refresh(self, crashes: list[CrashRecord]) -> None:
        """用崩溃列表刷新图表。"""
        if not crashes:
            self.lbl_summary.setText("暂无崩溃记录")
            return

        # Layer 分布（从 mutator_name 前缀提取）
        layer_counts: dict[str, int] = collections.Counter()
        field_counts: dict[str, int] = collections.Counter()
        for rec in crashes:
            name = rec.mutator_name  # e.g. "L1-S01.boundary_min"
            if name.startswith("L"):
                layer = name.split("-")[0]  # "L1"
                layer_counts[layer] += 1
            parts = name.split(".")
            if len(parts) >= 1:
                field = parts[0].split("-")[-1] if "-" in parts[0] else parts[0]
                field_counts[field] += 1

        # Layer 图
        layers = sorted(layer_counts.keys())
        y_layer = [layer_counts[l] for l in layers]
        if _PG and layers:
            self._bars_layer.setOpts(
                x=list(range(len(layers))),
                height=y_layer, width=0.6,
            )
            ticks = [list(enumerate(layers))]
            self._plot_layer.getAxis("bottom").setTicks(ticks)

        # 高频字段 Top 5
        top5 = field_counts.most_common(5)
        if _PG and top5:
            fields, counts = zip(*top5)
            self._bars_field.setOpts(
                x=list(range(len(fields))),
                height=list(counts), width=0.6,
            )
            ticks = [[(i, f) for i, f in enumerate(fields)]]
            self._plot_field.getAxis("bottom").setTicks(ticks)

        # 摘要文字
        sev_summary = "  |  ".join(
            f"{s.upper()}: {sum(1 for r in crashes if r.severity == s)}"
            for s in ("critical", "high", "medium", "low")
        )
        self.lbl_summary.setText(f"共 {len(crashes)} 个崩溃  |  {sev_summary}")
