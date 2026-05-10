"""应用入口 — 启动 PyQt6 + qasync 事件循环。"""

from __future__ import annotations

import asyncio
import sys

import qasync
from PyQt6.QtWidgets import QApplication

from someip_fuzzer.gui.main_window import MainWindow


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("VehSecLabs SomeIP Fuzzer")
    app.setApplicationVersion("0.5.0")

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    window = MainWindow()
    window.show()

    with loop:
        loop.run_forever()


if __name__ == "__main__":
    main()
