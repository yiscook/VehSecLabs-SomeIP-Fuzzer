#!/usr/bin/env python3
"""VehSecLabs SomeIP Fuzzer — VM 内进程监控 Agent（SPEC §4.10-4.11）。

独立 HTTP 服务，运行在靶机 VM 内，监控 vsomeipd 进程状态和 ASan 日志。
无需安装 someip_fuzzer 包，仅依赖 Python 标准库 + psutil。

用法：
    python agent.py [--port PORT] [--process PROCESS_NAME] [--asan-log LOG_PATH]

API：
    GET /ping    → {"ok": true}
    GET /status  → {"alive": bool, "pid": int, "memory_mb": float,
                    "cpu_percent": float, "asan_log": str | null}

环境变量：
    AGENT_PORT        HTTP 监听端口（默认 9999）
    AGENT_PROCESS     监控的进程名（默认 "vsomeipd"）
    ASAN_LOG_PATH     ASan 日志路径（默认 /tmp/vsomeip_asan.log）
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# psutil 是可选依赖，Agent 在没有 psutil 时降级为"进程总是存活"
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False
    print("[agent] 警告：psutil 未安装，进程监控将不可用", file=sys.stderr)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [agent] %(levelname)s %(message)s",
)
logger = logging.getLogger("agent")

# ── 全局配置（由命令行参数或环境变量覆盖）─────────────────────────────────────

_CONFIG = {
    "port": int(os.environ.get("AGENT_PORT", "9999")),
    "process": os.environ.get("AGENT_PROCESS", "vsomeipd"),
    "asan_log": os.environ.get("ASAN_LOG_PATH", "/tmp/vsomeip_asan.log"),
}


# ── 进程监控逻辑 ──────────────────────────────────────────────────────────────


def _find_process(name: str) -> "psutil.Process | None":
    """按进程名查找第一个匹配的进程。"""
    if not _PSUTIL_AVAILABLE:
        return None
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            if proc.info["name"] == name:
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def _get_asan_log(path: str, tail_lines: int = 100) -> str | None:
    """读取 ASan 日志文件的最后 N 行。文件不存在或为空时返回 None。"""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if not lines:
            return None
        return "".join(lines[-tail_lines:])
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.warning("读取 ASan 日志失败：%s", e)
        return None


def _build_status() -> dict:
    """构建 /status 响应字典。"""
    process_name = _CONFIG["process"]
    proc = _find_process(process_name)

    if proc is None:
        return {
            "alive": False,
            "pid": -1,
            "memory_mb": 0.0,
            "cpu_percent": 0.0,
            "asan_log": _get_asan_log(_CONFIG["asan_log"]),
        }

    try:
        mem_mb = proc.memory_info().rss / 1024 / 1024
        cpu = proc.cpu_percent(interval=0.1)
        return {
            "alive": True,
            "pid": proc.pid,
            "memory_mb": round(mem_mb, 2),
            "cpu_percent": round(cpu, 2),
            "asan_log": _get_asan_log(_CONFIG["asan_log"]),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {
            "alive": False,
            "pid": -1,
            "memory_mb": 0.0,
            "cpu_percent": 0.0,
            "asan_log": _get_asan_log(_CONFIG["asan_log"]),
        }


# ── HTTP 处理器 ───────────────────────────────────────────────────────────────


class AgentHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器，提供 /ping 和 /status 两个端点。"""

    def log_message(self, fmt: str, *args: object) -> None:
        logger.debug(fmt, *args)

    def _send_json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/ping":
            self._send_json({"ok": True})
        elif self.path == "/status":
            self._send_json(_build_status())
        else:
            self._send_json({"error": "not found"}, code=404)


# ── 入口 ──────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="VehSecLabs SomeIP Fuzzer VM Agent")
    parser.add_argument("--port", type=int, default=_CONFIG["port"],
                        help="HTTP 监听端口（默认 9999）")
    parser.add_argument("--process", default=_CONFIG["process"],
                        help="监控的进程名（默认 vsomeipd）")
    parser.add_argument("--asan-log", default=_CONFIG["asan_log"],
                        help="ASan 日志路径（默认 /tmp/vsomeip_asan.log）")
    args = parser.parse_args()

    _CONFIG["port"] = args.port
    _CONFIG["process"] = args.process
    _CONFIG["asan_log"] = args.asan_log

    server = HTTPServer(("0.0.0.0", args.port), AgentHandler)
    logger.info("Agent 启动：http://0.0.0.0:%d（监控进程：%s）", args.port, args.process)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Agent 停止")


if __name__ == "__main__":
    main()
