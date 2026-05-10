"""Tab 3 实时统计图表 — PyQtGraph 双曲线（发送速率 + 崩溃时间线）。"""

from __future__ import annotations

import collections
import time

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget

try:
    import pyqtgraph as pg
    _PG_AVAILABLE = True
except ImportError:
    _PG_AVAILABLE = False

_MAX_POINTS = 120   # 保留最近 120 个采样点（约 60 秒）
_INTERVAL_MS = 500  # 每 500 ms 采样一次


class StatsChartsWidget(QWidget):
    """实时统计图表。

    每 500 ms 更新一次，绘制：
    - 上图：发包速率曲线（pps）
    - 下图：崩溃时间线（柱状）
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._sent_counts: collections.deque[float] = collections.deque(maxlen=_MAX_POINTS)
        self._crash_flags: collections.deque[int] = collections.deque(maxlen=_MAX_POINTS)
        self._last_sent = 0
        self._total_sent = 0
        self._total_crashes = 0
        self._start = time.monotonic()
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(_INTERVAL_MS)
        self._timer.timeout.connect(self._tick)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        if _PG_AVAILABLE:
            pg.setConfigOption("background", "#1e1e2e")
            pg.setConfigOption("foreground", "#cdd6f4")

            self._win = pg.GraphicsLayoutWidget()
            self._win.setMinimumHeight(200)

            # 上：速率
            self._plot_rate = self._win.addPlot(title="发包速率 (pps)")
            self._plot_rate.setLabel("left", "pps")
            self._plot_rate.showGrid(x=False, y=True, alpha=0.3)
            self._curve_rate = self._plot_rate.plot(pen=pg.mkPen("#89b4fa", width=2))

            self._win.nextRow()

            # 下：崩溃时间线
            self._plot_crash = self._win.addPlot(title="崩溃时间线")
            self._plot_crash.setLabel("left", "崩溃")
            self._plot_crash.showGrid(x=False, y=True, alpha=0.3)
            self._bars = pg.BarGraphItem(x=[], height=[], width=0.4, brush="#f38ba8")
            self._plot_crash.addItem(self._bars)

            layout.addWidget(self._win)
        else:
            layout.addWidget(QLabel("（需安装 pyqtgraph）"))

        # 数字摘要
        self._lbl_rate = QLabel("速率: 0 pps")
        self._lbl_total = QLabel("总发送: 0")
        self._lbl_crash = QLabel("崩溃: 0")
        for lbl in (self._lbl_rate, self._lbl_total, self._lbl_crash):
            lbl.setStyleSheet("font-weight: bold;")
            layout.addWidget(lbl)

    def start(self) -> None:
        self._last_sent = self._total_sent
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def record_sent(self, count: int = 1) -> None:
        self._total_sent += count

    def record_crash(self) -> None:
        self._total_crashes += 1
        if self._crash_flags:
            self._crash_flags[-1] += 1

    def _tick(self) -> None:
        delta = self._total_sent - self._last_sent
        pps = delta / (_INTERVAL_MS / 1000.0)
        self._last_sent = self._total_sent
        self._sent_counts.append(pps)
        self._crash_flags.append(0)

        self._lbl_rate.setText(f"速率: {pps:.0f} pps")
        self._lbl_total.setText(f"总发送: {self._total_sent}")
        self._lbl_crash.setText(f"崩溃: {self._total_crashes}")

        if not _PG_AVAILABLE:
            return

        x = list(range(len(self._sent_counts)))
        y_rate = list(self._sent_counts)
        self._curve_rate.setData(x, y_rate)

        y_crash = list(self._crash_flags)
        self._bars.setOpts(x=x, height=y_crash, width=0.6)
