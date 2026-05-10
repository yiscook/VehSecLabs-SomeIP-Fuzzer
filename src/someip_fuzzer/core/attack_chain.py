"""多报文攻击链编排引擎（创新点 C3）。

支持从 YAML 文件加载攻击链描述，异步按步骤执行；
步骤间通过 context 字典传递变量（支持 "${var}" 占位符替换），
并在每步记录执行结果和发包统计。

设计要点：
- YAML → dataclass（AttackChain/ChainStep）完全解耦，加载与执行分离。
- wait_for 步骤非阻塞轮询 transport.recv()，超时后按 required 决定是否中止。
- 变量替换支持点路径："${step1.service_id}" → context["step1"]["service_id"]。
- 不依赖真实网络：传入 mock transport 即可单元测试。
"""

from __future__ import annotations

import asyncio
import dataclasses
import re
import struct
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import yaml  # type: ignore[import]
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from someip_fuzzer.core.protocol import (
    MessageType,
    SomeIpPacket,
    SD_SERVICE_ID,
    build_sd_find,
    build_sd_offer,
    build_sd_subscribe,
)

if TYPE_CHECKING:
    from someip_fuzzer.core.mutator import MutationScheduler
    from someip_fuzzer.core.state_machine import ServiceStateMachine
    from someip_fuzzer.data.corpus import SeedCorpus


# ── 数据模型 ──────────────────────────────────────────────────────────────────


@dataclasses.dataclass
class ChainStep:
    """攻击链单步描述。"""
    id: str
    action: str           # "send" | "wait_for" | "mutate" | "delay" | "repeat"
    template: str | None = None          # "sd_offer" | "request" | "subscribe" | "notification"
    params: dict = dataclasses.field(default_factory=dict)
    filter: dict = dataclasses.field(default_factory=dict)
    timeout: float = 5.0
    delay_ms: int = 0
    repeat: int = 1
    required: bool = True                # False = 失败时跳过而非中止整链


@dataclasses.dataclass
class AttackChain:
    """攻击链完整描述（对应一个 YAML 文件）。"""
    id: str
    name: str
    description: str
    severity: str        # "low" | "medium" | "high" | "critical"
    cvss: float
    steps: list[ChainStep]
    success_criteria: dict = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ChainResult:
    """单次攻击链执行结果。"""
    chain_id: str
    success: bool
    completed_steps: list[str]
    failed_at: str | None
    context: dict               # 各 step 输出（变量绑定）
    duration_ms: float
    packets_sent: int


# ── YAML 解析器 ───────────────────────────────────────────────────────────────


class AttackChainLoader:
    """从 YAML 文件加载攻击链定义。"""

    @staticmethod
    def load(path: Path | str) -> AttackChain:
        """加载单个 YAML 文件，返回 AttackChain。"""
        if not _YAML_AVAILABLE:
            raise ImportError("需要安装 pyyaml：uv add pyyaml")
        path = Path(path)
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return AttackChainLoader._parse(data)

    @staticmethod
    def load_all(directory: Path | str) -> list[AttackChain]:
        """扫描目录下所有 *.yaml 文件，按文件名排序返回列表。"""
        directory = Path(directory)
        chains = []
        for yaml_file in sorted(directory.glob("*.yaml")):
            chains.append(AttackChainLoader.load(yaml_file))
        return chains

    @staticmethod
    def _parse(data: dict) -> AttackChain:
        steps = [
            ChainStep(
                id=s["id"],
                action=s["action"],
                template=s.get("template"),
                params=s.get("params", {}),
                filter=s.get("filter", {}),
                timeout=float(s.get("timeout", 5.0)),
                delay_ms=int(s.get("delay_ms", 0)),
                repeat=int(s.get("repeat", 1)),
                required=bool(s.get("required", True)),
            )
            for s in data.get("steps", [])
        ]
        return AttackChain(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            cvss=float(data.get("cvss", 5.0)),
            steps=steps,
            success_criteria=data.get("success_criteria", {}),
        )


# ── 变量替换工具 ──────────────────────────────────────────────────────────────

_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _resolve(value: Any, context: dict) -> Any:
    """递归替换 value 中的 "${path.key}" 占位符。

    支持：
    - 字符串中的单个或多个占位符
    - 字典/列表递归替换
    - 点路径："${step1.service_id}" → context["step1"]["service_id"]
    """
    if isinstance(value, str):
        def _sub(m: re.Match) -> str:
            keys = m.group(1).split(".")
            node: Any = context
            for k in keys:
                if isinstance(node, dict):
                    node = node.get(k, m.group(0))
                else:
                    return m.group(0)
            return str(node)
        return _VAR_PATTERN.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _resolve(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, context) for v in value]
    return value


# ── 报文过滤工具 ──────────────────────────────────────────────────────────────


def _matches_filter(pkt: SomeIpPacket, filter_dict: dict) -> bool:
    """检查报文是否满足过滤条件字典。

    支持字段：
    - ``message_type``：MessageType 枚举名（如 "SD"、"REQUEST"）或整数
    - ``service_id``：整数或十六进制字符串
    - ``method_id``：整数或十六进制字符串
    - ``sd_entry_type``：字符串 "FindService"/"OfferService"/"Subscribe" 等
    """
    if not filter_dict:
        return True

    for key, expected in filter_dict.items():
        if key == "message_type":
            # "SD" 匹配 service_id=SD_SERVICE_ID；其余按 MessageType name 匹配
            if expected == "SD":
                if pkt.service_id != SD_SERVICE_ID:
                    return False
            else:
                try:
                    mt = MessageType[expected] if isinstance(expected, str) else MessageType(expected)
                    if pkt.message_type != mt:
                        return False
                except (KeyError, ValueError):
                    return False

        elif key == "service_id":
            sid = int(str(expected), 0) if isinstance(expected, str) else int(expected)
            if pkt.service_id != sid:
                return False

        elif key == "method_id":
            mid = int(str(expected), 0) if isinstance(expected, str) else int(expected)
            if pkt.method_id != mid:
                return False

        elif key == "sd_entry_type":
            if pkt.service_id != SD_SERVICE_ID or len(pkt.payload) < 24:
                return False
            entry_type_byte = pkt.payload[8]   # Entry Array 从 offset 8 开始
            ttl = int.from_bytes(pkt.payload[8 + 9: 8 + 12], "big")
            type_map = {
                "FindService": (0x00, None),
                "OfferService": (0x01, True),    # TTL > 0
                "StopOfferService": (0x01, False),  # TTL == 0
                "Subscribe": (0x06, None),
                "SubscribeAck": (0x07, None),
            }
            if expected not in type_map:
                return False
            exp_type, exp_ttl_nonzero = type_map[expected]
            if entry_type_byte != exp_type:
                return False
            if exp_ttl_nonzero is True and ttl == 0:
                return False
            if exp_ttl_nonzero is False and ttl != 0:
                return False

    return True


# ── 报文模板工厂 ──────────────────────────────────────────────────────────────


def _build_from_template(template: str, params: dict) -> SomeIpPacket:
    """根据 template 名和 params 构造 SomeIpPacket。"""

    def _int(key: str, default: int = 0) -> int:
        v = params.get(key, default)
        return int(str(v), 0) if isinstance(v, str) else int(v)

    def _bytes(key: str) -> bytes:
        v = params.get(key, "")
        if isinstance(v, bytes):
            return v
        s = str(v)
        # 尝试十六进制解析
        try:
            return bytes.fromhex(s.replace(" ", ""))
        except ValueError:
            return s.encode()

    if template == "sd_find":
        return build_sd_find(
            service_id=_int("service_id", 0x1234),
            instance_id=_int("instance_id", 0x0001),
        )
    if template == "sd_offer":
        return build_sd_offer(
            service_id=_int("service_id", 0x1234),
            instance_id=_int("instance_id", 0x0001),
            addr=params.get("addr", "192.168.1.1"),
            port=_int("port", 30509),
            ttl=_int("ttl", 3),
            major_ver=_int("major_ver", 1),
            minor_ver=_int("minor_ver", 0),
        )
    if template == "sd_subscribe":
        return build_sd_subscribe(
            service_id=_int("service_id", 0x1234),
            instance_id=_int("instance_id", 0x0001),
            eventgroup_id=_int("eventgroup_id", 0x0001),
            addr=params.get("addr", "127.0.0.1"),
            port=_int("port", 30509),
        )
    if template == "request":
        return SomeIpPacket.request(
            service_id=_int("service_id", 0x1234),
            method_id=_int("method_id", 0x0001),
            payload=_bytes("payload"),
            client_id=_int("client_id", 0x0001),
            session_id=_int("session_id", 1),
        )
    if template == "notification":
        return SomeIpPacket.notification(
            service_id=_int("service_id", 0x1234),
            event_id=_int("event_id", 0x8001),
            payload=_bytes("payload"),
        )
    raise ValueError(f"未知 template: {template!r}")


# ── 编排引擎 ──────────────────────────────────────────────────────────────────


class AttackChainEngine:
    """异步攻击链执行引擎。

    用法（测试模式，mock transport）::

        engine = AttackChainEngine(transport=mock_transport)
        chain = AttackChainLoader.load("configs/attack_chains/hijack.yaml")
        result = asyncio.run(engine.execute(chain, attacker_ip="192.168.1.100"))
    """

    def __init__(
        self,
        transport: Any,                          # SomeIpUdpTransport / mock
        scheduler: "MutationScheduler | None" = None,
        corpus: "SeedCorpus | None" = None,
        state_machine: "ServiceStateMachine | None" = None,
    ) -> None:
        self._transport = transport
        self._scheduler = scheduler
        self._corpus = corpus
        self._sm = state_machine
        # 统计（任务 3.18）
        self._total_executions = 0
        self._total_success = 0
        self._total_duration_ms = 0.0

    # ── 公共接口 ──────────────────────────────────────────────────────────────

    async def execute(self, chain: AttackChain, **env_vars: Any) -> ChainResult:
        """顺序执行攻击链，返回 ChainResult。"""
        self._total_executions += 1
        t0 = time.perf_counter()
        context: dict = dict(env_vars)
        completed: list[str] = []
        packets_sent = 0
        failed_at: str | None = None

        for step in chain.steps:
            resolved_step = self._resolve_step(step, context)
            try:
                step_output, sent = await self._execute_step(resolved_step)
                context[step.id] = step_output
                context[f"{step.id}_completed"] = True
                completed.append(step.id)
                packets_sent += sent
            except asyncio.TimeoutError:
                context[f"{step.id}_completed"] = False
                if step.required:
                    failed_at = step.id
                    break
            except Exception:
                context[f"{step.id}_completed"] = False
                if step.required:
                    failed_at = step.id
                    break

        duration_ms = (time.perf_counter() - t0) * 1000
        # 若有 required step 失败（failed_at 非 None），整链必定失败
        success = (failed_at is None) and self._evaluate_criteria(
            chain.success_criteria, context
        )

        if success:
            self._total_success += 1
        self._total_duration_ms += duration_ms

        return ChainResult(
            chain_id=chain.id,
            success=success,
            completed_steps=completed,
            failed_at=failed_at,
            context=context,
            duration_ms=duration_ms,
            packets_sent=packets_sent,
        )

    def get_stats(self) -> dict:
        """返回历次执行的聚合统计（任务 3.18）。"""
        total = self._total_executions
        return {
            "total_executions": total,
            "total_success": self._total_success,
            "success_rate": self._total_success / total if total else 0.0,
            "avg_duration_ms": self._total_duration_ms / total if total else 0.0,
        }

    # ── 步骤执行分派 ──────────────────────────────────────────────────────────

    async def _execute_step(
        self, step: ChainStep
    ) -> tuple[dict, int]:
        """分派到具体动作处理器，返回 (output_dict, packets_sent)。"""
        if step.action == "send":
            return await self._do_send(step)
        if step.action == "wait_for":
            return await self._do_wait_for(step)
        if step.action == "mutate":
            return await self._do_mutate(step)
        if step.action == "delay":
            await asyncio.sleep(step.delay_ms / 1000.0)
            return {"delayed_ms": step.delay_ms}, 0
        raise ValueError(f"未知 action: {step.action!r}")

    async def _do_send(self, step: ChainStep) -> tuple[dict, int]:
        template = step.template or "request"
        pkt = _build_from_template(template, step.params)
        sent = 0
        for _ in range(step.repeat):
            if step.delay_ms > 0:
                await asyncio.sleep(step.delay_ms / 1000.0)
            await self._transport.send(pkt)
            sent += 1
            if self._sm is not None:
                self._sm.on_packet(pkt)
        return {
            "service_id": pkt.service_id,
            "method_id": pkt.method_id,
            "payload": pkt.payload.hex(),
            "sent": sent,
        }, sent

    async def _do_wait_for(self, step: ChainStep) -> tuple[dict, int]:
        deadline = asyncio.get_event_loop().time() + step.timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            pkt = await self._transport.recv(timeout=min(remaining, 1.0))
            if pkt is None:
                continue
            if _matches_filter(pkt, step.filter):
                if self._sm is not None:
                    self._sm.on_packet(pkt)
                return {
                    "service_id": pkt.service_id,
                    "method_id": pkt.method_id,
                    "message_type": pkt.message_type.name,
                    "payload": pkt.payload.hex(),
                    "source_addr": list(pkt.source_addr) if pkt.source_addr else None,
                }, 0

    async def _do_mutate(self, step: ChainStep) -> tuple[dict, int]:
        if self._scheduler is None:
            raise RuntimeError("mutate 步骤需要传入 scheduler")
        import random
        seed_pkt: SomeIpPacket | None = None
        if self._corpus is not None:
            records = self._corpus.sample(1)
            if records:
                seed_pkt = records[0].to_packet()
        if seed_pkt is None:
            seed_pkt = SomeIpPacket.request(
                service_id=int(str(step.params.get("service_id", "0x1234")), 0),
                method_id=int(str(step.params.get("method_id", "0x0001")), 0),
            )
        rng = random.Random()
        layer = step.params.get("layer")
        mutator = self._scheduler.select(
            layer=int(layer) if layer is not None else None, rng=rng
        )
        result = mutator.mutate(seed_pkt, rng)
        for _ in range(step.repeat):
            if step.delay_ms > 0:
                await asyncio.sleep(step.delay_ms / 1000.0)
            await self._transport.send_raw(result.raw_bytes)
        return {
            "mutator_name": result.mutator_name,
            "layer": result.layer,
            "raw_bytes_len": len(result.raw_bytes),
            "sent": step.repeat,
        }, step.repeat

    # ── 辅助方法 ──────────────────────────────────────────────────────────────

    def _resolve_step(self, step: ChainStep, context: dict) -> ChainStep:
        """返回变量替换后的 step 副本。"""
        return dataclasses.replace(
            step,
            params=_resolve(step.params, context),
            filter=_resolve(step.filter, context),
        )

    @staticmethod
    def _evaluate_criteria(criteria: dict, context: dict) -> bool:
        """评估 success_criteria 字典，所有条件均满足才返回 True。"""
        if not criteria:
            return True
        for key, expected in criteria.items():
            actual = context.get(key)
            if isinstance(expected, bool):
                if bool(actual) != expected:
                    return False
            elif actual != expected:
                return False
        return True
