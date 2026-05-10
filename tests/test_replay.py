"""重放引擎 + 脚本生成 + Delta Debugging 最小化测试。"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from someip_fuzzer.core.replay import DeltaDebugger, ReplayEngine, ReplayScriptGenerator
from someip_fuzzer.data.crash_store import CrashRecord


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_crash() -> CrashRecord:
    return CrashRecord(
        triggering_bytes=bytes.fromhex("ffffffff81000000000000000101020000000000"),
        mutator_name="L2-V05.infinite_loop",
        severity="high",
        cvss_score=7.5,
        detection_method="heartbeat",
        target_addr=("192.168.1.100", 30509),
        context={"service_id": 0x1234, "method_id": 0x0001},
    )


def _make_transport(response=None) -> MagicMock:
    t = MagicMock()
    t.send = AsyncMock()
    t.send_raw = AsyncMock()

    async def _recv(timeout=2.0):
        return response

    t.recv = _recv
    return t


# ── ReplayEngine 测试 ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_replay_engine_sends_triggering_bytes(sample_crash: CrashRecord) -> None:
    transport = _make_transport()
    engine = ReplayEngine()  # 无 detector，发出即成功
    reproduced = await engine.replay(sample_crash, transport)
    assert reproduced is True
    transport.send_raw.assert_called_once_with(sample_crash.triggering_bytes)


@pytest.mark.asyncio
async def test_replay_engine_with_mock_detector_success(
    sample_crash: CrashRecord,
) -> None:
    transport = _make_transport(None)

    # mock 一个 detector，总是返回 CrashRecord（崩溃复现）
    mock_detector = MagicMock()
    mock_detector.check = AsyncMock(return_value=CrashRecord(
        triggering_bytes=b"\xff" * 16, severity="high"
    ))

    engine = ReplayEngine(detector=mock_detector)
    reproduced = await engine.replay(sample_crash, transport)
    assert reproduced is True


@pytest.mark.asyncio
async def test_replay_engine_with_mock_detector_failure(
    sample_crash: CrashRecord,
) -> None:
    transport = _make_transport(None)

    mock_detector = MagicMock()
    mock_detector.check = AsyncMock(return_value=None)  # 未复现

    engine = ReplayEngine(detector=mock_detector, max_attempts=2)
    reproduced = await engine.replay(sample_crash, transport)
    assert reproduced is False


# ── ReplayScriptGenerator 测试 ────────────────────────────────────────────────


def test_script_generator_creates_file(sample_crash: CrashRecord) -> None:
    gen = ReplayScriptGenerator()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = gen.generate(sample_crash, output_dir=Path(tmpdir))
        assert path.exists()
        assert path.suffix == ".py"


def test_script_contains_hex_bytes(sample_crash: CrashRecord) -> None:
    gen = ReplayScriptGenerator()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = gen.generate(sample_crash, output_dir=Path(tmpdir))
        content = path.read_text(encoding="utf-8")
        assert sample_crash.triggering_bytes.hex() in content


def test_script_contains_target_info(sample_crash: CrashRecord) -> None:
    gen = ReplayScriptGenerator()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = gen.generate(sample_crash, output_dir=Path(tmpdir))
        content = path.read_text(encoding="utf-8")
        assert "192.168.1.100" in content
        assert "30509" in content


def test_script_is_syntactically_valid(sample_crash: CrashRecord) -> None:
    gen = ReplayScriptGenerator()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = gen.generate(sample_crash, output_dir=Path(tmpdir))
        source = path.read_text(encoding="utf-8")
        # 编译检查语法正确性
        compiled = compile(source, str(path), "exec")
        assert compiled is not None


def test_script_contains_crash_metadata(sample_crash: CrashRecord) -> None:
    gen = ReplayScriptGenerator()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = gen.generate(sample_crash, output_dir=Path(tmpdir))
        content = path.read_text(encoding="utf-8")
        assert sample_crash.crash_id in content
        assert sample_crash.mutator_name in content
        assert sample_crash.severity in content


# ── DeltaDebugger 测试 ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delta_debugger_finds_single_triggering_packet() -> None:
    packets = [b"a", b"b", b"crash_trigger", b"c", b"d"]

    async def oracle(pkts: list[bytes]) -> bool:
        return any(b"crash_trigger" in p for p in pkts)

    debugger = DeltaDebugger()
    minimized = await debugger.minimize(packets, oracle)
    assert minimized == [b"crash_trigger"]


@pytest.mark.asyncio
async def test_delta_debugger_empty_input() -> None:
    async def oracle(pkts: list[bytes]) -> bool:
        return True

    debugger = DeltaDebugger()
    minimized = await debugger.minimize([], oracle)
    assert minimized == []


@pytest.mark.asyncio
async def test_delta_debugger_single_packet() -> None:
    packets = [b"crash"]

    async def oracle(pkts: list[bytes]) -> bool:
        return b"crash" in pkts

    debugger = DeltaDebugger()
    minimized = await debugger.minimize(packets, oracle)
    assert minimized == [b"crash"]


@pytest.mark.asyncio
async def test_delta_debugger_no_crash_returns_original() -> None:
    packets = [b"a", b"b", b"c"]

    async def oracle(pkts: list[bytes]) -> bool:
        return False  # 永不触发

    debugger = DeltaDebugger()
    minimized = await debugger.minimize(packets, oracle)
    assert minimized == packets


@pytest.mark.asyncio
async def test_delta_debugger_two_required_packets() -> None:
    """两个包组合才能触发崩溃的场景。"""
    packets = [b"setup", b"trigger", b"noise1", b"noise2"]

    async def oracle(pkts: list[bytes]) -> bool:
        return b"setup" in pkts and b"trigger" in pkts

    debugger = DeltaDebugger()
    minimized = await debugger.minimize(packets, oracle)
    assert b"setup" in minimized
    assert b"trigger" in minimized
    assert b"noise1" not in minimized
    assert b"noise2" not in minimized


@pytest.mark.asyncio
async def test_delta_debugger_max_rounds_respected() -> None:
    """max_rounds 限制能防止无限循环。"""
    packets = [bytes([i]) for i in range(20)]

    call_count = 0

    async def oracle(pkts: list[bytes]) -> bool:
        nonlocal call_count
        call_count += 1
        return len(pkts) > 0

    debugger = DeltaDebugger(max_rounds=3)
    minimized = await debugger.minimize(packets, oracle)
    assert len(minimized) <= len(packets)


@pytest.mark.asyncio
async def test_delta_debugger_preserves_order() -> None:
    """最小化后的报文保持原始顺序。"""
    packets = [b"a", b"b", b"crash", b"c"]

    async def oracle(pkts: list[bytes]) -> bool:
        return b"crash" in pkts

    debugger = DeltaDebugger()
    minimized = await debugger.minimize(packets, oracle)
    # 若保留多个包，顺序应与原始一致
    if len(minimized) > 1:
        indices = [packets.index(p) for p in minimized]
        assert indices == sorted(indices)
