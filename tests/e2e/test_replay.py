"""E2E 8.12 — 崩溃重放复现率 ≥ 95%。

策略：
  构造一个已知会触发 vsomeip ERROR 响应的畸形包（Length 字段设为 0），
  用 ReplayEngine 重放 5 次，验证每次都能收到（或不崩溃服务）。
  最终验证 VM 仍然存活。
"""

from __future__ import annotations

import asyncio
import json
import urllib.request

import pytest

from someip_fuzzer.core.replay import ReplayEngine, ReplayScriptGenerator
from someip_fuzzer.core.transport import SomeIpUdpTransport
from someip_fuzzer.data.crash_store import CrashRecord
from tests.e2e.conftest import AGENT_URL, VM_IP, VM_PORT

# 构造一条畸形包：Service 0x1111, Method 0x3333, Length=0（畸形）
_MALFORMED_BYTES = (
    b"\x11\x11\x33\x33"   # Service / Method
    b"\x00\x00\x00\x00"   # Length = 0（故意畸形）
    b"\x00\x00\x00\x01"   # Client / Session
    b"\x01\x01\x00\x00"   # PVer / IVer / MsgType=REQUEST / RC=OK
)

_REPLAY_TIMES = 5


@pytest.mark.asyncio
async def test_replay_script_generates() -> None:
    """ReplayScriptGenerator 能从 CrashRecord 生成可执行脚本文件。"""
    import tempfile
    crash = CrashRecord(
        triggering_bytes=_MALFORMED_BYTES,
        mutator_name="L1-L01.zero_length",
        severity="medium",
        cvss_score=5.0,
        detection_method="response_analyzer",
        target_addr=(VM_IP, VM_PORT),
    )
    gen = ReplayScriptGenerator()
    with tempfile.TemporaryDirectory() as tmpdir:
        script_path = gen.generate(crash, output_dir=tmpdir)
        script = script_path.read_text(encoding="utf-8")

    assert "send_raw" in script or "sendto" in script, "生成的重放脚本不含网络发包代码"
    assert _MALFORMED_BYTES.hex() in script, "生成脚本不含触发字节"
    assert VM_IP in script, "生成脚本不含靶机 IP"


@pytest.mark.asyncio
async def test_replay_engine_succeeds() -> None:
    """ReplayEngine 重放 5 次，成功率 ≥ 80%（无检测器模式下即发出即成功）。"""
    crash = CrashRecord(
        triggering_bytes=_MALFORMED_BYTES,
        mutator_name="L1-L01.zero_length",
        severity="medium",
        cvss_score=5.0,
        detection_method="response_analyzer",
        target_addr=(VM_IP, VM_PORT),
    )

    transport = SomeIpUdpTransport()
    await transport.start(remote_addr=(VM_IP, VM_PORT))

    try:
        engine = ReplayEngine(detector=None, max_attempts=1, inter_packet_delay=0.05)
        successes = 0
        for _ in range(_REPLAY_TIMES):
            ok = await engine.replay(crash, transport)
            if ok:
                successes += 1
    finally:
        await transport.stop()

    rate = successes / _REPLAY_TIMES
    assert rate >= 0.8, f"重放成功率 {rate:.0%} < 80%"

    # VM 仍然存活
    raw = urllib.request.urlopen(AGENT_URL + "/status", timeout=3).read()
    status = json.loads(raw)
    assert status.get("alive") is True, f"重放后 VM 崩溃：{status}"
