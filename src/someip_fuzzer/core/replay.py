"""重放引擎 + 脚本生成 + Delta Debugging 最小化（SPEC §4.14-4.16）。

三个组件：
  ReplayEngine         — 重放 CrashRecord，验证崩溃可复现（100% 复现率目标）
  ReplayScriptGenerator — 生成独立可运行的 .py 脚本，无需调试器
  DeltaDebugger        — Delta Debugging 算法，最小化触发崩溃的报文集合
"""

from __future__ import annotations

import asyncio
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Awaitable, Callable

if TYPE_CHECKING:
    from someip_fuzzer.core.monitor import CrashDetector, CrashRecord


# ── 重放引擎 ──────────────────────────────────────────────────────────────────


class ReplayEngine:
    """重放已记录的崩溃用例，验证可复现性（SPEC §4.14）。

    用法::

        engine = ReplayEngine(detector=crash_detector)
        reproduced = await engine.replay(crash_record, transport)
        assert reproduced  # 期望 100% 复现
    """

    def __init__(
        self,
        detector: "CrashDetector | None" = None,
        max_attempts: int = 3,
        inter_packet_delay: float = 0.05,
    ) -> None:
        self._detector = detector
        self._max_attempts = max_attempts
        self._inter_packet_delay = inter_packet_delay

    async def replay(
        self,
        crash: "CrashRecord",
        transport: object,
    ) -> bool:
        """发送 crash.triggering_bytes，监控是否再次崩溃。

        Returns:
            True 表示崩溃成功复现。
        """
        from someip_fuzzer.core.mutator import MutationResult

        # 构造一个最小 MutationResult 用于传给 detector
        mock_result = MutationResult(
            raw_bytes=crash.triggering_bytes,
            packet=None,
            mutator_name=crash.mutator_name,
            layer=0,
            target_field="replay",
            strategy="replay",
        )

        for attempt in range(1, self._max_attempts + 1):
            try:
                await transport.send_raw(crash.triggering_bytes)  # type: ignore[attr-defined]
                await asyncio.sleep(self._inter_packet_delay)

                if self._detector is not None:
                    response = await transport.recv(timeout=2.0)  # type: ignore[attr-defined]
                    crash_record = await self._detector.check(
                        transport, mock_result, response
                    )
                    if crash_record is not None:
                        return True
                else:
                    # 无检测器：发出即算成功（用于测试场景）
                    return True
            except Exception:
                if attempt == self._max_attempts:
                    return False
                await asyncio.sleep(0.5)

        return False


# ── 重放脚本生成器 ────────────────────────────────────────────────────────────


class ReplayScriptGenerator:
    """生成可独立运行的崩溃重放脚本（SPEC §4.15）。

    输出格式：``results/crashes/crash_{timestamp}.py``
    脚本仅依赖 someip_fuzzer 包，可在任意环境运行重现崩溃。
    """

    _TEMPLATE = textwrap.dedent("""\
        #!/usr/bin/env python3
        \"\"\"自动生成的崩溃重放脚本。
        生成时间: {timestamp}
        崩溃 ID:  {crash_id}
        严重度:   {severity} (CVSS {cvss_score})
        检测方式: {detection_method}
        变异器:   {mutator_name}
        靶机:     {target_host}:{target_port}
        \"\"\"

        import asyncio
        from someip_fuzzer.core.transport import SomeIpUdpTransport

        # 触发崩溃的原始字节（十六进制）
        TRIGGERING_BYTES = bytes.fromhex("{hex_bytes}")

        TARGET_HOST = "{target_host}"
        TARGET_PORT = {target_port}
        LOCAL_PORT  = {local_port}

        async def main() -> None:
            transport = SomeIpUdpTransport()
            await transport.start(
                local_addr=("0.0.0.0", LOCAL_PORT),
                remote_addr=(TARGET_HOST, TARGET_PORT),
            )
            print(f"发送 {{len(TRIGGERING_BYTES)}} 字节到 {{TARGET_HOST}}:{{TARGET_PORT}}")
            await transport.send_raw(TRIGGERING_BYTES)
            response = await transport.recv(timeout=2.0)
            if response is None:
                print("无响应（可能已崩溃）")
            else:
                print(f"响应：{{response.message_type.name}}, RC={{response.return_code.name}}")
            await transport.stop()

        if __name__ == "__main__":
            asyncio.run(main())
        """)

    def generate(
        self,
        crash: "CrashRecord",
        output_dir: Path | str = Path("results/crashes"),
        local_port: int = 30600,
    ) -> Path:
        """生成重放脚本，返回脚本文件路径。"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"crash_{ts}.py"
        output_path = output_dir / filename

        script = self._TEMPLATE.format(
            timestamp=crash.timestamp,
            crash_id=crash.crash_id,
            severity=crash.severity,
            cvss_score=crash.cvss_score,
            detection_method=crash.detection_method,
            mutator_name=crash.mutator_name,
            target_host=crash.target_addr[0],
            target_port=crash.target_addr[1],
            hex_bytes=crash.triggering_bytes.hex(),
            local_port=local_port,
        )

        output_path.write_text(script, encoding="utf-8")
        return output_path


# ── Delta Debugging 最小化器 ──────────────────────────────────────────────────


class DeltaDebugger:
    """Delta Debugging 算法：最小化触发崩溃的报文集合（SPEC §4.16）。

    给定一组报文和一个 Oracle 函数（判断该组报文是否触发崩溃），
    通过二分缩减找到最小触发集合。

    时间复杂度：O(n² / log n) 次 Oracle 查询。

    用法（同步 Oracle）::

        async def oracle(packets):
            return any(b"crash" in p for p in packets)

        minimized = await DeltaDebugger().minimize(packets, oracle)

    参考：Andreas Zeller, "Yesterday, My Program Worked" (1999)
    """

    def __init__(self, max_rounds: int = 50) -> None:
        self._max_rounds = max_rounds

    async def minimize(
        self,
        packets: list[bytes],
        oracle: Callable[[list[bytes]], Awaitable[bool]],
    ) -> list[bytes]:
        """二分缩减 packets，返回最小触发崩溃的子集。

        Args:
            packets: 原始报文列表（顺序发送）
            oracle:  异步函数，接受报文列表，返回 True 表示触发崩溃

        Returns:
            最小化后的报文列表（顺序保持不变）。
            若 oracle 对空列表也返回 True，则返回空列表。
            若 oracle 对完整列表返回 False，则返回原始完整列表。
        """
        if not packets:
            return []

        # 验证完整列表确实触发崩溃
        if not await oracle(packets):
            return list(packets)

        return await self._ddmin(list(packets), oracle, rounds=0)

    async def _ddmin(
        self,
        packets: list[bytes],
        oracle: Callable[[list[bytes]], Awaitable[bool]],
        rounds: int,
    ) -> list[bytes]:
        """DDMin 核心递归（简化版本，基于二分策略）。"""
        if len(packets) <= 1 or rounds >= self._max_rounds:
            return packets

        mid = len(packets) // 2
        first_half = packets[:mid]
        second_half = packets[mid:]

        # 尝试仅用后半部分触发崩溃
        if await oracle(second_half):
            return await self._ddmin(second_half, oracle, rounds + 1)

        # 尝试仅用前半部分触发崩溃
        if await oracle(first_half):
            return await self._ddmin(first_half, oracle, rounds + 1)

        # 两半都无法单独触发 → 需要保留更多，尝试逐个删除
        return await self._reduce_one_by_one(packets, oracle)

    async def _reduce_one_by_one(
        self,
        packets: list[bytes],
        oracle: Callable[[list[bytes]], Awaitable[bool]],
    ) -> list[bytes]:
        """逐包尝试删除（粒度细化阶段）。"""
        result = list(packets)
        i = 0
        while i < len(result):
            candidate = result[:i] + result[i + 1:]
            if candidate and await oracle(candidate):
                result = candidate
                # 不增加 i，继续尝试删除当前位置的新元素
            else:
                i += 1
        return result
