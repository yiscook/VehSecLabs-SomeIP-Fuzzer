"""E2E 8.9 — 模糊测试稳定性（200 包不崩）。

验证：
1. FuzzingEngine 向真实 VM 发 200 个变异包，不抛异常
2. 发包数 >= 100（排除网络阻断）
3. 测试结束后 VM 仍然存活（agent alive=true）
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from unittest.mock import MagicMock

import pytest
import pytest_asyncio

from someip_fuzzer.core.engine import FuzzingEngine
from someip_fuzzer.utils.config import AppConfig, ServiceDef, SdConfig, TargetConfig
from tests.e2e.conftest import AGENT_URL, VM_IP, VM_PORT

TARGET_PACKETS = 200
TIMEOUT_SEC = 90


def _make_config() -> AppConfig:
    return AppConfig(
        target=TargetConfig(
            name="e2e-test",
            ip=VM_IP,
            port=VM_PORT,
            transport="udp",
        ),
        sd=SdConfig(multicast="224.224.224.245", port=30490),
        services=[
            ServiceDef(
                service_id=0x1111,
                instance_id=0x2222,
                major_version=0,
                minor_version=0,
                methods=[0x3333],
            )
        ],
    )


def _make_bridge_mock() -> MagicMock:
    bridge = MagicMock()
    bridge.packet_sent = MagicMock()
    bridge.packet_sent.emit = MagicMock()
    bridge.packet_received = MagicMock()
    bridge.packet_received.emit = MagicMock()
    bridge.crash_detected = MagicMock()
    bridge.crash_detected.emit = MagicMock()
    bridge.stats_updated = MagicMock()
    bridge.stats_updated.emit = MagicMock()
    bridge.log_message = MagicMock()
    bridge.log_message.emit = MagicMock()
    return bridge


@pytest.mark.asyncio
async def test_fuzz_200_packets_no_crash() -> None:
    """发 200 个包，VM 不崩溃，sent >= 100。"""
    config = _make_config()
    bridge = _make_bridge_mock()
    stop_event = asyncio.Event()
    sent_count: list[int] = [0]

    original_emit = bridge.stats_updated.emit

    def track_stats(stats: dict) -> None:
        sent_count[0] = stats.get("sent", 0)
        if sent_count[0] >= TARGET_PACKETS:
            stop_event.set()

    bridge.stats_updated.emit.side_effect = track_stats

    engine = FuzzingEngine()
    try:
        await asyncio.wait_for(
            engine.run(config, bridge, stop_event, recv_timeout=0.3),
            timeout=TIMEOUT_SEC,
        )
    except asyncio.TimeoutError:
        stop_event.set()

    # 验证发包数量
    assert sent_count[0] >= 100, f"发包数太少：{sent_count[0]}（可能网络阻断）"

    # 验证 VM 仍存活
    raw = urllib.request.urlopen(AGENT_URL + "/status", timeout=3).read()
    status = json.loads(raw)
    assert status.get("alive") is True, f"VM 发包后崩溃！{status}"

    # 验证无意外崩溃检测（hello_world 服务对畸形包健壮）
    # 允许有 crash_detected（vsomeip 可能返回 ERROR 响应码），但 VM 必须存活
    print(f"发包 {sent_count[0]} 包，崩溃检测 {bridge.crash_detected.emit.call_count} 次")
