"""反馈优化引擎（创新点 C4）。

三路反馈算法动态调整 MutationScheduler 权重，使高价值变异策略被更高频率选中：

  GA（遗传算法）   → 根据响应新颖度和崩溃事件打分，调整变异器权重
  Markov（马尔可夫）→ 学习字段值转移概率，为"符合真实流量分布"的变异加分
  Entropy（熵值分析）→ 高熵响应（异常代码路径）触发加分

三路合成（CompositeFeedback）= 0.5×GA + 0.3×Markov + 0.2×Entropy

本阶段使用"简化版"算法，保留 DL 接口（DLModelInterface）供未来扩展。
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from someip_fuzzer.core.mutator import MutationResult, MutationScheduler
    from someip_fuzzer.core.protocol import SomeIpPacket


# ── 反馈结果容器 ──────────────────────────────────────────────────────────────


@dataclass
class MutationFeedback:
    """单次变异的反馈评分结果。"""
    mutator_name: str
    score: float            # 合成得分（≥ 0），传入 MutationScheduler.update_weight()
    is_new_response: bool   # 响应内容与历史不同（新代码路径代理指标）
    crash_triggered: bool
    entropy: float          # 响应字节熵值（bits，0-8）
    raw_score_ga: float = 0.0
    raw_score_markov: float = 0.0
    raw_score_entropy: float = 0.0


# ── 抽象基类 ──────────────────────────────────────────────────────────────────


class FeedbackEngine(ABC):
    """反馈引擎抽象基类。

    子类实现 ``analyze()``，计算 MutationFeedback；
    ``apply()`` 自动将得分写入 MutationScheduler。
    """

    @abstractmethod
    def analyze(
        self,
        result: "MutationResult",
        response: "SomeIpPacket | None",
        crash_detected: bool,
    ) -> MutationFeedback:
        """分析一次变异的反馈，返回评分结果。"""
        ...

    def apply(
        self,
        scheduler: "MutationScheduler",
        feedback: MutationFeedback,
    ) -> None:
        """将反馈得分写入调度器权重。"""
        try:
            current = scheduler.get_weight(feedback.mutator_name)
            new_weight = max(0.1, current * 0.95 + feedback.score * 0.1)
            scheduler.update_weight(feedback.mutator_name, new_weight)
        except KeyError:
            pass  # 未注册的变异器，跳过


# ── 工具函数 ──────────────────────────────────────────────────────────────────


def _response_sha(response: "SomeIpPacket | None") -> str:
    """返回响应的简单指纹（用于判断是否新响应）。"""
    if response is None:
        return "TIMEOUT"
    import hashlib
    return hashlib.md5(response.to_bytes(), usedforsecurity=False).hexdigest()[:8]


def _byte_entropy(data: bytes) -> float:
    """计算字节序列的 Shannon 熵（bits，0-8）。"""
    if not data:
        return 0.0
    counts: dict[int, int] = defaultdict(int)
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ── GA 反馈 ───────────────────────────────────────────────────────────────────


class GAFeedback(FeedbackEngine):
    """简化遗传算法反馈引擎（SPEC §4.2）。

    打分规则：
    - 触发崩溃：+20
    - 响应内容新颖（未见过的响应指纹）：+10
    - 响应超时（None）：+5
    - 普通响应：+1

    权重调整：new_w = old_w * decay + score * lr
    """

    SCORE_CRASH = 20.0
    SCORE_NEW_RESPONSE = 10.0
    SCORE_TIMEOUT = 5.0
    SCORE_NORMAL = 1.0

    def __init__(self, decay: float = 0.95, lr: float = 0.1) -> None:
        self._decay = decay
        self._lr = lr
        self._seen_responses: set[str] = set()
        # Elite 种子池：保留得分最高的 10 个 mutator name
        self._elite: dict[str, float] = {}  # {mutator_name: cumulative_score}
        self._elite_max = 10

    def analyze(
        self,
        result: "MutationResult",
        response: "SomeIpPacket | None",
        crash_detected: bool,
    ) -> MutationFeedback:
        resp_key = _response_sha(response)
        is_new = resp_key not in self._seen_responses
        self._seen_responses.add(resp_key)

        if crash_detected:
            score = self.SCORE_CRASH
        elif is_new:
            score = self.SCORE_NEW_RESPONSE
        elif response is None:
            score = self.SCORE_TIMEOUT
        else:
            score = self.SCORE_NORMAL

        self._update_elite(result.mutator_name, score)

        entropy = _byte_entropy(response.to_bytes() if response else b"")
        return MutationFeedback(
            mutator_name=result.mutator_name,
            score=score,
            is_new_response=is_new,
            crash_triggered=crash_detected,
            entropy=entropy,
            raw_score_ga=score,
        )

    def _update_elite(self, name: str, score: float) -> None:
        self._elite[name] = self._elite.get(name, 0.0) + score
        if len(self._elite) > self._elite_max:
            # 淘汰得分最低的
            min_name = min(self._elite, key=lambda k: self._elite[k])
            del self._elite[min_name]

    @property
    def elite_mutators(self) -> list[str]:
        """按累计得分降序排列的 Elite 变异器名称列表。"""
        return sorted(self._elite, key=lambda k: -self._elite[k])


# ── Markov 字段学习 ───────────────────────────────────────────────────────────


class MarkovFieldLearner(FeedbackEngine):
    """简化马尔可夫链字段转移学习（SPEC §4.3）。

    从合法流量（响应报文）学习字段值的转移概率：
        (field_name, prev_value) → {next_value: count}

    对于变异结果中字段值符合学习到的"高概率转移"的变异器，给予加分。
    对于产生"从未出现过的值"的变异器，也视为有价值（触达未知路径）。
    """

    # 跟踪的字段名
    TRACKED_FIELDS = ("service_id", "method_id", "session_id", "return_code")
    SCORE_CONFORMING = 3.0    # 符合已知转移模式
    SCORE_NOVEL = 8.0         # 产生从未见过的字段值组合

    def __init__(self) -> None:
        # {field: {prev_val: {next_val: count}}}
        self._transitions: dict[str, dict[int, dict[int, int]]] = {
            f: defaultdict(lambda: defaultdict(int)) for f in self.TRACKED_FIELDS
        }
        self._prev_values: dict[str, int] = {}  # {field: last_seen_value}

    def learn(self, packet: "SomeIpPacket") -> None:
        """从报文学习字段转移（用合法响应喂给 learner）。"""
        current: dict[str, int] = {
            "service_id": packet.service_id,
            "method_id": packet.method_id,
            "session_id": packet.session_id,
            "return_code": int(packet.return_code),
        }
        for field_name, cur_val in current.items():
            prev_val = self._prev_values.get(field_name)
            if prev_val is not None:
                self._transitions[field_name][prev_val][cur_val] += 1
            self._prev_values[field_name] = cur_val

    def suggest_value(
        self, field_name: str, prev_value: int, rng: random.Random | None = None
    ) -> int | None:
        """按学习到的概率分布建议下一个字段值。未见过的组合返回 None。"""
        if field_name not in self._transitions:
            return None
        candidates = self._transitions[field_name].get(prev_value, {})
        if not candidates:
            return None
        vals = list(candidates.keys())
        weights = [candidates[v] for v in vals]
        if rng:
            return rng.choices(vals, weights=weights)[0]
        return max(candidates, key=lambda v: candidates[v])

    def analyze(
        self,
        result: "MutationResult",
        response: "SomeIpPacket | None",
        crash_detected: bool,
    ) -> MutationFeedback:
        # 如果有响应，先学习
        if response is not None:
            self.learn(response)

        # 评估本次变异的字段值是否符合或超出已知分布
        score = self.SCORE_NOVEL  # 默认视为"产生新颖值"
        if result.packet is not None:
            pkt = result.packet
            for field_name in self.TRACKED_FIELDS:
                val = getattr(pkt, field_name, None)
                if val is None:
                    continue
                prev = self._prev_values.get(field_name)
                if prev is not None:
                    known = self._transitions[field_name].get(prev, {})
                    if int(val) in known:
                        score = self.SCORE_CONFORMING
                        break

        entropy = _byte_entropy(response.to_bytes() if response else b"")
        return MutationFeedback(
            mutator_name=result.mutator_name,
            score=score,
            is_new_response=response is None,
            crash_triggered=crash_detected,
            entropy=entropy,
            raw_score_markov=score,
        )


# ── 熵值分析 ──────────────────────────────────────────────────────────────────


class EntropyAnalyzer:
    """响应字节熵值分析（SPEC §4.4）。

    高熵响应（>4.0 bits）说明触达了异常/复杂的代码路径，值得加分。
    正常 SOME/IP 响应熵值通常在 2-3 bits（字段较规律）。
    """

    THRESHOLD_HIGH = 4.0      # 高熵阈值
    THRESHOLD_VERY_HIGH = 6.0 # 极高熵阈值

    SCORE_VERY_HIGH = 8.0
    SCORE_HIGH = 4.0
    SCORE_NORMAL = 1.0

    def compute(self, data: bytes) -> float:
        return _byte_entropy(data)

    def score_from_entropy(self, entropy: float) -> float:
        if entropy >= self.THRESHOLD_VERY_HIGH:
            return self.SCORE_VERY_HIGH
        if entropy >= self.THRESHOLD_HIGH:
            return self.SCORE_HIGH
        return self.SCORE_NORMAL


# ── 三路合成反馈 ──────────────────────────────────────────────────────────────


class CompositeFeedback(FeedbackEngine):
    """三路反馈合成引擎（SPEC §4.4）。

    合成公式：score = w_ga × ga_score + w_markov × markov_score + w_entropy × entropy_score
    默认权重：w_ga=0.5, w_markov=0.3, w_entropy=0.2
    """

    def __init__(
        self,
        w_ga: float = 0.5,
        w_markov: float = 0.3,
        w_entropy: float = 0.2,
    ) -> None:
        self._ga = GAFeedback()
        self._markov = MarkovFieldLearner()
        self._entropy_analyzer = EntropyAnalyzer()
        self._w_ga = w_ga
        self._w_markov = w_markov
        self._w_entropy = w_entropy

    def analyze(
        self,
        result: "MutationResult",
        response: "SomeIpPacket | None",
        crash_detected: bool,
    ) -> MutationFeedback:
        ga_fb = self._ga.analyze(result, response, crash_detected)
        markov_fb = self._markov.analyze(result, response, crash_detected)

        entropy_val = _byte_entropy(response.to_bytes() if response else b"")
        entropy_score = self._entropy_analyzer.score_from_entropy(entropy_val)

        composite = (
            self._w_ga * ga_fb.raw_score_ga
            + self._w_markov * markov_fb.raw_score_markov
            + self._w_entropy * entropy_score
        )

        return MutationFeedback(
            mutator_name=result.mutator_name,
            score=composite,
            is_new_response=ga_fb.is_new_response,
            crash_triggered=crash_detected,
            entropy=entropy_val,
            raw_score_ga=ga_fb.raw_score_ga,
            raw_score_markov=markov_fb.raw_score_markov,
            raw_score_entropy=entropy_score,
        )

    @property
    def ga(self) -> GAFeedback:
        return self._ga

    @property
    def markov(self) -> MarkovFieldLearner:
        return self._markov


# ── 种子能量调度器 ────────────────────────────────────────────────────────────


class SeedEnergyScheduler:
    """高价值种子优先调度（SPEC §4.5）。

    每次变异触发崩溃或产生新颖响应，对应种子的 energy 值 +1。
    采样时按 energy 加权，确保高价值种子被更频繁选中变异。
    """

    def __init__(self) -> None:
        self._energy: dict[int, float] = {}  # {seed_id: energy}
        self._default_energy = 1.0

    def reward(self, seed_id: int, feedback: MutationFeedback) -> None:
        """根据反馈给种子增加能量。"""
        base = self._energy.get(seed_id, self._default_energy)
        bonus = 5.0 if feedback.crash_triggered else (2.0 if feedback.is_new_response else 0.0)
        self._energy[seed_id] = base + bonus

    def sample(
        self,
        seed_ids: list[int],
        n: int,
        rng: random.Random | None = None,
    ) -> list[int]:
        """按能量加权采样 n 个种子 ID（允许重复）。"""
        if not seed_ids:
            return []
        weights = [self._energy.get(sid, self._default_energy) for sid in seed_ids]
        _rng = rng or random.Random()
        return _rng.choices(seed_ids, weights=weights, k=n)

    def get_energy(self, seed_id: int) -> float:
        return self._energy.get(seed_id, self._default_energy)


# ── DL 模型接口（预留）───────────────────────────────────────────────────────


class DLModelInterface:
    """深度学习模型接口（SPEC §4.6，预留 Demo 级实现）。

    当前实现返回固定分数 1.0（不干预权重），
    未来可替换为调用 ONNX/TorchServe 模型端点的实现。
    """

    def predict_score(self, result: "MutationResult") -> float:
        """预测变异的价值得分（当前为 placeholder）。"""
        return 1.0

    def is_available(self) -> bool:
        """返回 DL 模型是否可用（当前始终返回 False）。"""
        return False
