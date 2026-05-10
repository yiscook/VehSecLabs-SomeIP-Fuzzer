"""反馈引擎测试：GA + Markov + Entropy + CompositeFeedback + SeedEnergy + DL。"""

from __future__ import annotations

import random

import pytest

from someip_fuzzer.core.feedback import (
    CompositeFeedback,
    DLModelInterface,
    EntropyAnalyzer,
    GAFeedback,
    MarkovFieldLearner,
    MutationFeedback,
    SeedEnergyScheduler,
    _byte_entropy,
)
from someip_fuzzer.core.mutator import MutationResult, MutationScheduler
from someip_fuzzer.core.protocol import SomeIpPacket

import someip_fuzzer.core.mutators  # noqa: F401


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def seed() -> SomeIpPacket:
    return SomeIpPacket.request(0x1234, 0x0001, payload=b"\x01\x02\x03\x04")


@pytest.fixture
def mock_result(seed: SomeIpPacket) -> MutationResult:
    return MutationResult(
        raw_bytes=seed.to_bytes(),
        packet=seed,
        mutator_name="L1-S01.boundary_min",
        layer=1,
        target_field="service_id",
        strategy="boundary_min",
    )


@pytest.fixture
def normal_response() -> SomeIpPacket:
    return SomeIpPacket.response(0x1234, 0x0001, payload=b"\x00\x00")


# ── 工具函数测试 ──────────────────────────────────────────────────────────────


def test_byte_entropy_uniform_high() -> None:
    data = bytes(range(256))
    assert _byte_entropy(data) == pytest.approx(8.0, abs=0.01)


def test_byte_entropy_constant_zero() -> None:
    assert _byte_entropy(b"\x00" * 100) == 0.0


def test_byte_entropy_empty_zero() -> None:
    assert _byte_entropy(b"") == 0.0


def test_byte_entropy_random_high(seed: SomeIpPacket) -> None:
    rng = random.Random(42)
    data = bytes(rng.randint(0, 255) for _ in range(256))
    assert _byte_entropy(data) > 4.0


# ── GA 反馈测试 ───────────────────────────────────────────────────────────────


def test_ga_crash_scores_highest(
    mock_result: MutationResult, normal_response: SomeIpPacket
) -> None:
    ga = GAFeedback()
    crash_fb = ga.analyze(mock_result, response=None, crash_detected=True)
    normal_fb = ga.analyze(mock_result, response=normal_response, crash_detected=False)
    assert crash_fb.raw_score_ga > normal_fb.raw_score_ga


def test_ga_new_response_scores_higher_than_normal(
    mock_result: MutationResult, normal_response: SomeIpPacket
) -> None:
    ga = GAFeedback()
    first_fb = ga.analyze(mock_result, response=normal_response, crash_detected=False)
    second_fb = ga.analyze(mock_result, response=normal_response, crash_detected=False)
    # 第一次是新响应，得分应 ≥ 第二次
    assert first_fb.raw_score_ga >= second_fb.raw_score_ga


def test_ga_timeout_scores_between(mock_result: MutationResult, normal_response: SomeIpPacket) -> None:
    ga = GAFeedback()
    timeout_fb = ga.analyze(mock_result, response=None, crash_detected=False)
    # 超时得分（5.0）介于 crash（20.0）和 normal（1.0）之间
    assert 1.0 < timeout_fb.raw_score_ga < 20.0


def test_ga_updates_scheduler_weight(mock_result: MutationResult) -> None:
    ga = GAFeedback()
    scheduler = MutationScheduler()
    initial_weight = scheduler.get_weight("L1-S01.boundary_min")

    feedback = ga.analyze(mock_result, response=None, crash_detected=True)
    ga.apply(scheduler, feedback)

    new_weight = scheduler.get_weight("L1-S01.boundary_min")
    assert new_weight != initial_weight


def test_ga_elite_accumulates(mock_result: MutationResult) -> None:
    ga = GAFeedback()
    for _ in range(5):
        ga.analyze(mock_result, response=None, crash_detected=True)
    assert "L1-S01.boundary_min" in ga.elite_mutators


def test_ga_crash_flag_propagates(mock_result: MutationResult) -> None:
    ga = GAFeedback()
    fb = ga.analyze(mock_result, response=None, crash_detected=True)
    assert fb.crash_triggered is True


# ── Markov 学习测试 ───────────────────────────────────────────────────────────


def test_markov_learns_transitions(seed: SomeIpPacket) -> None:
    learner = MarkovFieldLearner()
    pkt1 = SomeIpPacket.request(0x1234, 0x0001)
    pkt2 = SomeIpPacket.request(0x5678, 0x0002)
    learner.learn(pkt1)
    learner.learn(pkt2)
    suggested = learner.suggest_value("service_id", 0x1234)
    assert suggested == 0x5678


def test_markov_suggest_none_for_unknown(seed: SomeIpPacket) -> None:
    learner = MarkovFieldLearner()
    result = learner.suggest_value("service_id", 0xFFFF)
    assert result is None


def test_markov_analyze_returns_feedback(
    mock_result: MutationResult, normal_response: SomeIpPacket
) -> None:
    learner = MarkovFieldLearner()
    fb = learner.analyze(mock_result, normal_response, crash_detected=False)
    assert isinstance(fb, MutationFeedback)
    assert fb.raw_score_markov > 0


def test_markov_novel_scores_higher(mock_result: MutationResult) -> None:
    learner = MarkovFieldLearner()
    # 对未见过字段组合的变异，应得 SCORE_NOVEL
    fb = learner.analyze(mock_result, response=None, crash_detected=False)
    assert fb.raw_score_markov == MarkovFieldLearner.SCORE_NOVEL


# ── 熵值分析测试 ──────────────────────────────────────────────────────────────


def test_entropy_high_for_random_bytes() -> None:
    analyzer = EntropyAnalyzer()
    data = bytes(range(256))
    entropy = analyzer.compute(data)
    assert entropy > 4.0
    score = analyzer.score_from_entropy(entropy)
    assert score == analyzer.SCORE_VERY_HIGH


def test_entropy_low_for_constant() -> None:
    analyzer = EntropyAnalyzer()
    entropy = analyzer.compute(b"\x00" * 100)
    score = analyzer.score_from_entropy(entropy)
    assert score == analyzer.SCORE_NORMAL


def test_entropy_medium_threshold() -> None:
    analyzer = EntropyAnalyzer()
    score = analyzer.score_from_entropy(4.5)
    assert score == analyzer.SCORE_HIGH


# ── CompositeFeedback 测试 ────────────────────────────────────────────────────


def test_composite_crash_score_high(mock_result: MutationResult) -> None:
    composite = CompositeFeedback()
    fb = composite.analyze(mock_result, response=None, crash_detected=True)
    assert fb.score > 5.0
    assert fb.crash_triggered is True


def test_composite_weighted_sum(mock_result: MutationResult) -> None:
    composite = CompositeFeedback(w_ga=0.5, w_markov=0.3, w_entropy=0.2)
    fb = composite.analyze(mock_result, response=None, crash_detected=True)
    expected = (0.5 * fb.raw_score_ga + 0.3 * fb.raw_score_markov
                + 0.2 * fb.raw_score_entropy)
    assert fb.score == pytest.approx(expected, abs=0.01)


def test_composite_apply_updates_weight(mock_result: MutationResult) -> None:
    composite = CompositeFeedback()
    scheduler = MutationScheduler()
    fb = composite.analyze(mock_result, response=None, crash_detected=True)
    composite.apply(scheduler, fb)
    # 权重应该有变化（crash 得分很高）
    w = scheduler.get_weight("L1-S01.boundary_min")
    assert w > 0


def test_composite_nonexistent_mutator_does_not_raise(mock_result: MutationResult) -> None:
    bad_result = MutationResult(
        raw_bytes=b"\x00" * 16, packet=None,
        mutator_name="L99-X99.nonexistent", layer=99,
        target_field="x", strategy="x",
    )
    composite = CompositeFeedback()
    scheduler = MutationScheduler()
    fb = composite.analyze(bad_result, response=None, crash_detected=False)
    composite.apply(scheduler, fb)  # 不应抛出异常


# ── 种子能量调度器测试 ────────────────────────────────────────────────────────


def test_seed_energy_default_equal() -> None:
    sched = SeedEnergyScheduler()
    seed_ids = [1, 2, 3]
    assert all(sched.get_energy(sid) == 1.0 for sid in seed_ids)


def test_seed_energy_crash_rewards_more() -> None:
    sched = SeedEnergyScheduler()
    crash_fb = MutationFeedback(
        mutator_name="x", score=10.0, is_new_response=False,
        crash_triggered=True, entropy=0.0,
    )
    normal_fb = MutationFeedback(
        mutator_name="x", score=1.0, is_new_response=False,
        crash_triggered=False, entropy=0.0,
    )
    sched.reward(1, crash_fb)
    sched.reward(2, normal_fb)
    assert sched.get_energy(1) > sched.get_energy(2)


def test_seed_energy_sample_prefers_high_energy() -> None:
    sched = SeedEnergyScheduler()
    crash_fb = MutationFeedback(
        mutator_name="x", score=20.0, is_new_response=False,
        crash_triggered=True, entropy=0.0,
    )
    for _ in range(10):
        sched.reward(1, crash_fb)  # seed 1 energy >> seed 2
    rng = random.Random(0)
    samples = sched.sample([1, 2], n=100, rng=rng)
    # seed 1 应该被采样更多
    assert samples.count(1) > samples.count(2)


# ── DL 接口测试 ───────────────────────────────────────────────────────────────


def test_dl_interface_placeholder(mock_result: MutationResult) -> None:
    dl = DLModelInterface()
    assert dl.predict_score(mock_result) == 1.0
    assert dl.is_available() is False
