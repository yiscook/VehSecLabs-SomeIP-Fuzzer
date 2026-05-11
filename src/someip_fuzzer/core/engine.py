"""模糊测试引擎 —— 把 transport / mutator / monitor 串联成主循环。

用法（在 qasync 事件循环中）::

    engine = FuzzingEngine()
    stop = asyncio.Event()
    pause = asyncio.Event()
    await engine.run(config, bridge, stop, pause)
"""

from __future__ import annotations

import asyncio
import random
import time
from pathlib import Path
from typing import TYPE_CHECKING

from someip_fuzzer.core.monitor import AgentClient, CrashDetector, HeartbeatMonitor, ResponseAnalyzer
from someip_fuzzer.core.mutator import MutationScheduler
import someip_fuzzer.core.mutators  # noqa: F401 — 触发 @register_mutator 完成注册
from someip_fuzzer.core.protocol import SomeIpPacket
from someip_fuzzer.core.transport import SomeIpUdpTransport
from someip_fuzzer.data.crash_store import CrashStorage
from someip_fuzzer.utils.config import AppConfig
from someip_fuzzer.utils.logger import logger

if TYPE_CHECKING:
    from someip_fuzzer.gui.bridge import GuiBridge

# 状态更新间隔（每发 N 包向 GUI 推一次 stats）
_STATS_INTERVAL = 50
# 默认崩溃数据库路径
_DEFAULT_DB = Path.home() / ".someip_fuzzer" / "crashes.db"


class FuzzingEngine:
    """异步模糊测试主循环。

    每次调用 ``run()`` 都是独立生命周期；stop_event.set() 后优雅退出。
    """

    async def run(
        self,
        config: AppConfig,
        bridge: "GuiBridge",
        stop_event: asyncio.Event,
        pause_event: asyncio.Event | None = None,
        enabled_mutators: list[str] | None = None,
        db_path: Path | str = _DEFAULT_DB,
        recv_timeout: float = 0.5,
    ) -> None:
        target = (config.target.ip, config.target.port)
        logger.info(f"FuzzingEngine 启动 → {target[0]}:{target[1]}")
        bridge.log_message.emit("INFO", f"引擎初始化中… 目标 {target[0]}:{target[1]}")

        # ── 初始化各组件 ─────────────────────────────────────────────────────
        transport = SomeIpUdpTransport()
        await transport.start(remote_addr=target)

        scheduler = MutationScheduler()
        if enabled_mutators is not None:
            for m in scheduler.list_all():
                if m.name not in enabled_mutators:
                    scheduler.disable(m.name)

        # 选第一个服务第一个方法的 service_id 作为心跳服务
        hb_svc = config.services[0].service_id if config.services else 0x1111
        hb_mth = (config.services[0].methods[0]
                  if config.services and config.services[0].methods else 0x3333)
        heartbeat = HeartbeatMonitor(
            interval=100,
            heartbeat_service_id=hb_svc,
            heartbeat_method_id=hb_mth,
        )
        agent = AgentClient(f"http://{config.target.ip}:9999")
        detector = CrashDetector(
            heartbeat=heartbeat,
            analyzer=ResponseAnalyzer(),
            agent=agent,
            target_addr=target,
        )

        _DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)
        crash_store = CrashStorage(db_path)

        seeds = self._build_seeds(config)
        rng = random.Random()

        sent = 0
        crashes = 0
        t0 = time.perf_counter()

        bridge.log_message.emit("INFO", f"▶ 开始发包，种子 {len(seeds)} 颗，变异器 {len(scheduler)} 个")

        # ── 主循环 ────────────────────────────────────────────────────────────
        try:
            while not stop_event.is_set():
                # 暂停检查
                if pause_event and pause_event.is_set():
                    await asyncio.sleep(0.1)
                    continue

                seed = rng.choice(seeds)
                try:
                    mutator = scheduler.select(rng=rng)
                except LookupError:
                    bridge.log_message.emit("ERROR", "无可用变异器，请检查策略配置")
                    break

                result = mutator.mutate(seed, rng)

                # 发送（畸形包用 send_raw，合法包用 send 触发 on_sent 回调）
                try:
                    if result.packet is not None:
                        await transport.send(result.packet)
                        bridge.packet_sent.emit(result.packet)
                    else:
                        await transport.send_raw(result.raw_bytes)
                        # 尝试解析以便展示，解析失败则不展示
                        try:
                            display_pkt = SomeIpPacket.from_bytes(result.raw_bytes)
                            bridge.packet_sent.emit(display_pkt)
                        except Exception:
                            pass
                except Exception as exc:
                    logger.warning(f"发包失败：{exc}")
                    await asyncio.sleep(0.1)
                    continue

                sent += 1

                # 接收响应
                response = await transport.recv(timeout=recv_timeout)
                if response is not None:
                    bridge.packet_received.emit(response)

                # 崩溃检测
                crash = await detector.check(transport, result, response)
                if crash:
                    crashes += 1
                    saved = crash_store.save(crash)
                    if saved:
                        logger.warning(
                            f"崩溃！severity={crash.severity} "
                            f"mutator={crash.mutator_name} "
                            f"bytes={crash.triggering_bytes.hex()[:32]}…"
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

                # 统计推送
                if sent % _STATS_INTERVAL == 0:
                    elapsed = time.perf_counter() - t0
                    pps = sent / elapsed if elapsed > 0 else 0.0
                    bridge.stats_updated.emit({
                        "sent": sent,
                        "crashes": crashes,
                        "pps": round(pps, 1),
                    })

                await asyncio.sleep(0)  # 让出事件循环，保持 GUI 响应

        except asyncio.CancelledError:
            logger.info("FuzzingEngine 被取消")
        except Exception as exc:
            logger.exception(f"FuzzingEngine 意外异常：{exc}")
            bridge.log_message.emit("ERROR", f"引擎异常：{exc}")
            raise
        finally:
            await transport.stop()
            elapsed = time.perf_counter() - t0
            pps = sent / elapsed if elapsed > 0 else 0.0
            bridge.stats_updated.emit({"sent": sent, "crashes": crashes, "pps": round(pps, 1)})
            logger.info(f"FuzzingEngine 停止：sent={sent}, crashes={crashes}, pps={pps:.1f}")

    # ── 内部工具 ──────────────────────────────────────────────────────────────

    @staticmethod
    def _build_seeds(config: AppConfig) -> list[SomeIpPacket]:
        """从 AppConfig.services 生成种子报文列表。"""
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
            # 配置为空时的默认种子（hello_world 服务）
            seeds.append(SomeIpPacket.request(
                service_id=0x1111,
                method_id=0x3333,
                payload=b"\x00\x00\x00\x00",
            ))
        return seeds
