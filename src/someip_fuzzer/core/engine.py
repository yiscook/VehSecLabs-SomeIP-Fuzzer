"""模糊测试引擎 —— 三协程并行架构（send / recv / watchdog）。

架构：
  _send_loop   — 持续变异发包，不等响应，目标 ≥1000 pps
  _recv_loop   — 后台收包，10ms 轮询，不阻塞发包
  _watchdog    — 每 2s 查 agent HTTP /status，发现崩溃即上报

用法（在 qasync 事件循环中）::

    engine = FuzzingEngine()
    await engine.run(config, bridge, stop_event, pause_event)
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING, Any

from someip_fuzzer.core.monitor import AgentClient
from someip_fuzzer.core.mutator import MutationScheduler
import someip_fuzzer.core.mutators  # noqa: F401 — 触发 @register_mutator 完成注册
from someip_fuzzer.core.protocol import SomeIpPacket
from someip_fuzzer.core.transport import SomeIpUdpTransport
from someip_fuzzer.data.crash_store import CrashRecord, CrashStorage
from someip_fuzzer.utils.config import AppConfig
from someip_fuzzer.utils.logger import logger

if TYPE_CHECKING:
    from someip_fuzzer.core.mutator import MutationResult
    from someip_fuzzer.gui.bridge import GuiBridge

_STATS_INTERVAL = 100           # 每发 N 包推一次 stats
_WATCHDOG_INTERVAL = 2.0        # watchdog 检查间隔（秒）
_RECV_TIMEOUT = 0.01            # recv 轮询超时（秒），不阻塞发包
_DEFAULT_DB = Path.home() / ".someip_fuzzer" / "crashes.db"


class FuzzingEngine:
    """三协程并行模糊测试引擎。

    send_loop + recv_loop + watchdog_loop 并发运行，stop_event.set() 后全部退出。
    """

    async def run(
        self,
        config: AppConfig,
        bridge: "GuiBridge",
        stop_event: asyncio.Event,
        pause_event: asyncio.Event | None = None,
        enabled_mutators: list[str] | None = None,
        db_path: Path | str = _DEFAULT_DB,
    ) -> None:
        target = (config.target.ip, config.target.port)
        logger.info(f"FuzzingEngine 启动 → {target[0]}:{target[1]}")
        bridge.log_message.emit("INFO", f"引擎初始化… 目标 {target[0]}:{target[1]}")

        # ── 初始化 ────────────────────────────────────────────────────────────
        transport = SomeIpUdpTransport()
        await transport.start(remote_addr=target)

        scheduler = MutationScheduler()
        if enabled_mutators is not None:
            for m in scheduler.list_all():
                if m.name not in enabled_mutators:
                    scheduler.disable(m.name)

        agent = AgentClient(f"http://{config.target.ip}:9999")
        seeds = self._build_seeds(config)
        rng = random.Random()

        _DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)
        crash_store = CrashStorage(db_path)

        # 协程间共享状态（asyncio 单线程，无需锁）
        shared: dict[str, Any] = {
            "sent": 0,
            "crashes": 0,
            "t0": time.perf_counter(),
            "last_result": None,   # 最近一条 MutationResult（watchdog 用于关联崩溃）
        }

        bridge.log_message.emit(
            "INFO",
            f"▶ 并行发包，种子 {len(seeds)} 颗，变异器 {len(scheduler)} 个"
        )

        # ── 三协程并发 ────────────────────────────────────────────────────────
        try:
            await asyncio.gather(
                self._send_loop(transport, scheduler, seeds, rng, bridge,
                                stop_event, pause_event, shared),
                self._recv_loop(transport, stop_event, bridge),
                self._watchdog_loop(agent, bridge, crash_store, stop_event,
                                    shared, target),
                return_exceptions=True,
            )
        finally:
            await transport.stop()
            elapsed = time.perf_counter() - shared["t0"]
            pps = shared["sent"] / elapsed if elapsed > 0 else 0.0
            bridge.stats_updated.emit({
                "sent": shared["sent"],
                "crashes": shared["crashes"],
                "pps": round(pps, 1),
            })
            logger.info(
                f"FuzzingEngine 停止：sent={shared['sent']}, "
                f"crashes={shared['crashes']}, pps={pps:.1f}"
            )

    # ── 发包协程 ──────────────────────────────────────────────────────────────

    async def _send_loop(
        self,
        transport: SomeIpUdpTransport,
        scheduler: MutationScheduler,
        seeds: list[SomeIpPacket],
        rng: random.Random,
        bridge: "GuiBridge",
        stop_event: asyncio.Event,
        pause_event: asyncio.Event | None,
        shared: dict,
    ) -> None:
        try:
            while not stop_event.is_set():
                if pause_event and pause_event.is_set():
                    await asyncio.sleep(0.05)
                    continue

                seed = rng.choice(seeds)
                try:
                    mutator = scheduler.select(rng=rng)
                except LookupError:
                    bridge.log_message.emit("ERROR", "无可用变异器，检查策略配置")
                    break

                result = mutator.mutate(seed, rng)
                shared["last_result"] = result

                try:
                    if result.packet is not None:
                        await transport.send(result.packet)
                        bridge.packet_sent.emit(result.packet)
                    else:
                        await transport.send_raw(result.raw_bytes)
                        try:
                            bridge.packet_sent.emit(
                                SomeIpPacket.from_bytes(result.raw_bytes)
                            )
                        except Exception:
                            pass
                except Exception as exc:
                    logger.warning(f"发包失败：{exc}")
                    await asyncio.sleep(0.01)
                    continue

                shared["sent"] += 1

                if shared["sent"] % _STATS_INTERVAL == 0:
                    elapsed = time.perf_counter() - shared["t0"]
                    pps = shared["sent"] / elapsed if elapsed > 0 else 0.0
                    bridge.stats_updated.emit({
                        "sent": shared["sent"],
                        "crashes": shared["crashes"],
                        "pps": round(pps, 1),
                    })

                await asyncio.sleep(0)  # 让出事件循环，保持 GUI 响应

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.exception(f"send_loop 异常：{exc}")
            bridge.log_message.emit("ERROR", f"发包协程异常：{exc}")

    # ── 收包协程 ──────────────────────────────────────────────────────────────

    async def _recv_loop(
        self,
        transport: SomeIpUdpTransport,
        stop_event: asyncio.Event,
        bridge: "GuiBridge",
    ) -> None:
        try:
            while not stop_event.is_set():
                response = await transport.recv(timeout=_RECV_TIMEOUT)
                if response is not None:
                    bridge.packet_received.emit(response)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning(f"recv_loop 异常：{exc}")

    # ── 看门狗协程 ────────────────────────────────────────────────────────────

    async def _watchdog_loop(
        self,
        agent: AgentClient,
        bridge: "GuiBridge",
        crash_store: CrashStorage,
        stop_event: asyncio.Event,
        shared: dict,
        target: tuple[str, int],
    ) -> None:
        try:
            while not stop_event.is_set():
                await asyncio.sleep(_WATCHDOG_INTERVAL)

                # 周期推送 stats（补充 send_loop 的固定间隔推送）
                elapsed = time.perf_counter() - shared["t0"]
                pps = shared["sent"] / elapsed if elapsed > 0 else 0.0
                bridge.stats_updated.emit({
                    "sent": shared["sent"],
                    "crashes": shared["crashes"],
                    "pps": round(pps, 1),
                })

                # Agent 存活检查
                alive = await agent.is_alive()
                if not alive:
                    asan_log = await agent.get_asan_log()
                    severity = "critical" if asan_log else "high"
                    last_result: "MutationResult | None" = shared.get("last_result")

                    if last_result is not None:
                        ctx: dict = {}
                        if last_result.packet is not None:
                            pkt = last_result.packet
                            ctx = {
                                "service_id": pkt.service_id,
                                "method_id": pkt.method_id,
                                "session_id": pkt.session_id,
                                "message_type": (
                                    pkt.message_type.name
                                    if hasattr(pkt.message_type, "name")
                                    else f"0x{int(pkt.message_type):02X}"
                                ),
                            }
                        crash = CrashRecord(
                            triggering_bytes=last_result.raw_bytes,
                            mutator_name=last_result.mutator_name,
                            severity=severity,
                            cvss_score=9.0 if asan_log else 7.5,
                            detection_method="agent",
                            asan_log=asan_log,
                            target_addr=target,
                            context=ctx,
                        )
                        saved = crash_store.save(crash)
                        if saved:
                            shared["crashes"] += 1
                            logger.warning(
                                f"崩溃！severity={severity} "
                                f"mutator={crash.mutator_name}"
                            )
                            bridge.crash_detected.emit({
                                "crash_id": crash.crash_id,
                                "severity": crash.severity,
                                "cvss_score": crash.cvss_score,
                                "mutator_name": crash.mutator_name,
                                "detection_method": crash.detection_method,
                                "triggering_bytes": crash.triggering_bytes.hex(),
                                "timestamp": crash.timestamp,
                            })

                    bridge.log_message.emit(
                        "ERROR", f"⚠️ 靶机崩溃！severity={severity}"
                    )

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.exception(f"watchdog 异常：{exc}")

    # ── 种子生成 ──────────────────────────────────────────────────────────────

    @staticmethod
    def _build_seeds(config: AppConfig) -> list[SomeIpPacket]:
        seeds: list[SomeIpPacket] = []
        for svc in config.services:
            methods = svc.methods if svc.methods else [0x0001]
            for method_id in methods:
                seeds.append(SomeIpPacket.request(
                    service_id=svc.service_id,
                    method_id=method_id,
                    payload=b"\x00\x00\x00\x00",
                ))
        if not seeds:
            seeds.append(SomeIpPacket.request(
                service_id=0x1111,
                method_id=0x3333,
                payload=b"\x00\x00\x00\x00",
            ))
        return seeds
