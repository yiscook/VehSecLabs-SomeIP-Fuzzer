"""E2E 8.11 — 攻击链端到端执行。

验证：
1. dos.yaml（DoS 资源耗尽）能完整执行，所有步骤 completed
2. 攻击链执行后 VM 仍存活（对 hello_world_service 的 DoS 不会实际崩溃）
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from pathlib import Path

import pytest

import someip_fuzzer.core.mutators  # noqa: F401 — 注册变异器
from someip_fuzzer.core.attack_chain import AttackChainEngine, AttackChainLoader
from someip_fuzzer.core.mutator import MutationScheduler
from someip_fuzzer.core.transport import SomeIpUdpTransport
from tests.e2e.conftest import AGENT_URL, VM_IP, VM_PORT

CHAINS_DIR = Path(__file__).parent.parent.parent / "configs" / "attack_chains"


@pytest.mark.asyncio
async def test_dos_chain_executes() -> None:
    """DoS 攻击链能完整执行，所有必需步骤 completed。"""
    chain = AttackChainLoader.load(CHAINS_DIR / "dos.yaml")

    transport = SomeIpUdpTransport()
    await transport.start(remote_addr=(VM_IP, VM_PORT))

    try:
        engine = AttackChainEngine(transport=transport, scheduler=MutationScheduler())
        result = await engine.execute(chain)
    finally:
        await transport.stop()

    assert result is not None, "攻击链执行返回 None"
    # DoS 链的 success_criteria 要求 flood_register 和 mutate_payload_flood 完成
    assert result.success, (
        f"攻击链未达成成功条件。completed={result.completed_steps}"
    )


@pytest.mark.asyncio
async def test_dos_chain_vm_survives() -> None:
    """执行 DoS 链后 VM 仍存活（hello_world_service 对此 DoS 有足够健壮性）。"""
    chain = AttackChainLoader.load(CHAINS_DIR / "dos.yaml")

    transport = SomeIpUdpTransport()
    await transport.start(remote_addr=(VM_IP, VM_PORT))

    try:
        engine = AttackChainEngine(transport=transport, scheduler=MutationScheduler())
        await engine.execute(chain)
    finally:
        await transport.stop()

    raw = urllib.request.urlopen(AGENT_URL + "/status", timeout=3).read()
    status = json.loads(raw)
    assert status.get("alive") is True, f"DoS 后 VM 崩溃：{status}"
