"""Couverture de branches des modules héritage (swarm + RL).

Les tests qui exercent ``BioCybeRLAgent`` sans TensorFlow sont placés avant
l'injection d'un faux ``tensorflow`` et le ``reload`` du module. Le faux
paquet est retiré en fin de test pour ne pas laisser l'interpréteur dans un
état incohérent.

Aucun fixture n'est un binaire réel : graphes et signaux sont synthétiques.
"""

from __future__ import annotations

import builtins
import importlib
import os
import sys
import types
from datetime import datetime

import matplotlib
import numpy as np
import pytest

import biocybe.learning.reinforcement_learning as rl
import biocybe.swarm_intelligence as swarm_pkg
from biocybe.swarm_intelligence import legacy_swarm

matplotlib.use("Agg")

_TF_MODULE_NAMES = (
    "tensorflow",
    "tensorflow.keras",
    "tensorflow.keras.layers",
    "tensorflow.keras.models",
    "tensorflow.keras.optimizers",
)


class _Dense:
    def __init__(self, units, activation=None, **kwargs):
        self.units = units
        self.activation = activation

    def __call__(self, other):
        return self


def _input_layer(shape=None, **kwargs):
    return ("input", shape)


class _Adam:
    def __init__(self, learning_rate=0.001, **kwargs):
        self.learning_rate = learning_rate


class _Model:
    def __init__(self, inputs=None, outputs=None, **kwargs):
        self.inputs = inputs
        self.outputs = outputs
        self.units = getattr(outputs, "units", 1)
        self.compiled = None
        self.fitted = 0
        self.saved_to = None

    def compile(self, *args, **kwargs):
        self.compiled = kwargs.get("loss")
        self.optimizer = kwargs.get("optimizer")

    def predict(self, state, verbose=0):
        rows = np.asarray(state).shape[0]
        return np.full((rows, self.units), 1.0 / self.units, dtype=np.float32)

    def fit(self, *args, **kwargs):
        self.fitted += 1

    def save(self, path, *args, **kwargs):
        self.saved_to = path


def _load_model(path, *args, **kwargs):
    units = 1 if "value" in os.path.basename(str(path)) else 6
    return _Model(outputs=_Dense(units))


def _purge_tensorflow() -> None:
    for name in list(sys.modules):
        if name == "tensorflow" or name.startswith("tensorflow."):
            del sys.modules[name]


def _install_fake_tensorflow() -> None:
    """Injecte un keras minimal dans ``sys.modules`` (TensorFlow n'est pas installé)."""
    _purge_tensorflow()
    tf = types.ModuleType("tensorflow")
    keras = types.ModuleType("tensorflow.keras")
    layers = types.ModuleType("tensorflow.keras.layers")
    models = types.ModuleType("tensorflow.keras.models")
    optimizers = types.ModuleType("tensorflow.keras.optimizers")
    layers.Dense = _Dense
    layers.Input = _input_layer
    models.Model = _Model
    models.load_model = _load_model
    optimizers.Adam = _Adam
    keras.layers = layers
    keras.models = models
    keras.optimizers = optimizers
    tf.keras = keras
    sys.modules["tensorflow"] = tf
    sys.modules["tensorflow.keras"] = keras
    sys.modules["tensorflow.keras.layers"] = layers
    sys.modules["tensorflow.keras.models"] = models
    sys.modules["tensorflow.keras.optimizers"] = optimizers


def _ensure_tensorflow_absent() -> None:
    if rl._TF_AVAILABLE:
        _purge_tensorflow()
        importlib.reload(rl)


def test_rl_core_without_tensorflow(monkeypatch):
    """Signaux, récompenses, buffer, et ImportError réel tant que TF est absent."""
    _ensure_tensorflow_absent()
    assert rl._TF_AVAILABLE is False

    signals = rl.DangerSignals()
    assert signals.update("cpu_usage", 0.4) is True
    assert signals.signals["cpu_usage"] == pytest.approx(0.4)
    assert signals.update("file_operations", 5.0) is True
    assert signals.signals["file_operations"] == pytest.approx(1.0)
    assert signals.update("network_anomalies", -0.2) is True
    assert signals.signals["network_anomalies"] == pytest.approx(0.0)
    assert signals.update("not_a_signal", 0.5) is False

    state = signals.get_state()
    assert state.shape == (9,)
    assert state.dtype == np.float32
    assert 0.0 <= signals.get_total_danger() <= 1.0

    assert rl.DefenseAction.get_action_space() == 6
    assert rl.DefenseAction.get_action_name(rl.DefenseAction.MONITOR) == "MONITOR"
    assert rl.DefenseAction.get_action_name(rl.DefenseAction.PATCH_SYSTEM) == "PATCH_SYSTEM"
    assert rl.DefenseAction.get_action_name(99) == "UNKNOWN"

    failed = rl.Reward.calculate(1.0, 0.2, rl.DefenseAction.TERMINATE, success=False)
    assert failed == pytest.approx(-1.0)
    clean = rl.Reward.calculate(1.0, 0.5, rl.DefenseAction.TERMINATE, success=True)
    assert clean == pytest.approx(7.5)
    penalized = rl.Reward.calculate(
        1.0,
        0.5,
        rl.DefenseAction.QUARANTINE_FILE,
        success=True,
        collateral_damage=0.2,
    )
    assert penalized == pytest.approx(2.5 * 0.5 * 10 - 1.0)

    buffer = rl.ReplayBuffer(capacity=2)
    assert buffer.size() == 0
    assert buffer.sample(3) == []
    buffer.add(0, 0, 0.1, 1, False)
    buffer.add(1, 1, 0.2, 2, False)
    buffer.add(2, 2, 0.3, 3, True)
    assert buffer.size() == 2
    assert len(buffer.sample(1)) == 1
    assert len(buffer.sample(8)) == 2

    with pytest.raises(ImportError, match="TensorFlow"):
        rl.BioCybeRLAgent(9, rl.DefenseAction.get_action_space())

    monkeypatch.setattr(rl, "np", None)
    with pytest.raises(ImportError, match="numpy"):
        rl._require_numpy()
    with pytest.raises(ImportError, match="numpy"):
        rl._require_tf()
    with pytest.raises(ImportError, match="numpy"):
        rl.DangerSignals().get_state()


def test_swarm_node_peers_findings_and_exchange():
    bare = legacy_swarm.SwarmNode("n0")
    assert bare.config == {}
    node = legacy_swarm.SwarmNode("n1", {"role": "sensor"})
    assert node.config["role"] == "sensor"

    node.add_peer("n2", 0.8)
    node.add_peer("n2", 0.1)
    assert node.peers.count("n2") == 1
    assert node.trust_scores["n2"] == pytest.approx(0.8)

    node.add_local_finding(
        "f1",
        {"threat_id": "alpha", "confidence": 0.8, "evidence": ["trace-a", "trace-b"]},
    )
    node.add_local_finding("f2", {"hash": "hash-demo", "evidence": []})
    shared = node.share_information()
    assert set(shared) == {"f1", "f2"}
    assert shared["f1"]["source"] == "n1"
    assert node.local_findings["f1"]["shared"] is True
    assert 0.0 < shared["f1"]["confidence"] <= 1.0

    assert node.share_information(["n2"]) == {}
    node.add_local_finding("f3", {"signature": "sig-demo"})
    assert set(node.share_information()) == {"f3"}

    node.receive_information("stranger", {"x": {"data": {"target": "disk"}}})
    assert "x" not in node.shared_data

    stamp = datetime(2024, 5, 1)
    later = datetime(2024, 6, 1)
    node.receive_information(
        "n2",
        {
            "ext": {
                "data": {"target": "disk", "confidence": 0.6},
                "source": "n2",
                "timestamp": stamp,
                "confidence": 0.6,
            },
            "nocred": {
                "data": {"target": "mem"},
                "source": "n2",
                "timestamp": stamp,
            },
        },
    )
    assert node.shared_data["ext"]["confidence"] == pytest.approx(0.6 * 0.8)
    assert node.shared_data["ext"]["trust_weight"] == pytest.approx(0.8)
    assert "confidence" not in node.shared_data["nocred"]

    node.receive_information(
        "n2",
        {
            "ext": {
                "data": {"target": "disk", "extra": 1},
                "source": "n2",
                "timestamp": later,
                "confidence": 0.9,
            }
        },
    )
    assert node.shared_data["ext"]["data"]["extra"] == 1
    node.receive_information("n2", {})

    node.remove_peer("n2")
    assert "n2" not in node.peers
    node.remove_peer("absent")
    node.peers.append("ghost")
    node.remove_peer("ghost")
    assert "ghost" not in node.peers
    assert "ghost" not in node.trust_scores


def test_swarm_similarity_merge_trust_and_decisions():
    node = legacy_swarm.SwarmNode("logic")
    similar = node._are_findings_similar

    assert similar({"data": {"threat_id": "a"}}, {"data": {"threat_id": "a"}})
    assert not similar({"data": {"threat_id": "a"}}, {"data": {"threat_id": "b"}})
    assert similar({"data": {"threat_id": "a", "hash": "h"}}, {"data": {"hash": "h"}})
    assert not similar({"data": {"hash": "h1"}}, {"data": {"hash": "h2"}})
    assert similar({"hash": "h"}, {"hash": "h"})
    assert similar(
        {"data": {"hash": "h", "signature": "s"}},
        {"data": {"signature": "s"}},
    )
    assert similar({"data": {"signature": "s"}}, {"data": {"signature": "s"}})
    assert not similar({"data": {"signature": "s1"}}, {"data": {"signature": "s2"}})
    assert similar(
        {"data": {"signature": "s", "target": "disk"}},
        {"data": {"target": "disk"}},
    )
    assert similar({"data": {"target": "disk"}}, {"data": {"target": "disk"}})
    assert not similar({"data": {"target": "disk"}}, {"data": {"target": "net"}})
    assert not similar({"data": {"target": "disk"}}, {"data": {"other": 1}})
    assert not similar({"data": {"foo": 1}}, {"data": {"bar": 2}})
    assert not similar({"data": {"foo": 1}}, {"data": {"hash": "h", "signature": "s"}})

    early = datetime(2024, 1, 1)
    late = datetime(2024, 6, 1)
    merged = node._merge_findings(
        {
            "data": {"a": 1, "b": 1},
            "confidence": 0.4,
            "trust_weight": 1.0,
            "source": "s1",
            "timestamp": early,
        },
        {
            "data": {"a": 9, "c": 3},
            "confidence": 0.8,
            "trust_weight": 1.0,
            "source": "s2",
            "timestamp": late,
        },
    )
    assert merged["data"]["a"] == 9
    assert merged["data"]["b"] == 1
    assert merged["data"]["c"] == 3
    assert merged["sources"] == ["s1", "s2"]
    assert merged["timestamp"] == late
    assert merged["confidence"] == pytest.approx(0.6)

    kept = node._merge_findings(
        {
            "data": {"a": 1},
            "timestamp": late,
            "source": "s1",
            "confidence": 0.5,
            "trust_weight": 1.0,
            "sources": ["s1", "s2"],
        },
        {
            "data": {"a": 7},
            "timestamp": early,
            "source": "s2",
            "confidence": 0.5,
            "trust_weight": 1.0,
        },
    )
    assert kept["data"]["a"] == 1
    assert kept["sources"] == ["s1", "s2"]

    same_source = node._merge_findings({"source": "s1"}, {"source": "s1"})
    assert same_source["sources"] == ["s1"]

    no_data = node._merge_findings(
        {"source": "s1", "confidence": 0.2, "timestamp": early},
        {"source": "s3"},
    )
    assert no_data["sources"] == ["s1", "s3"]

    partial = node._merge_findings(
        {"source": "s1", "sources": ["s1"]},
        {
            "data": {"k": 1},
            "confidence": 0.2,
            "timestamp": early,
            "source": "s9",
        },
    )
    assert partial["sources"] == ["s1", "s9"]
    assert "confidence" not in partial or partial.get("confidence") == 0.2

    node.trust_scores["src"] = 0.5
    weighted = node._apply_trust_weight("src", {"confidence": 0.8, "data": {}})
    assert weighted["confidence"] == pytest.approx(0.4)
    assert weighted["trust_weight"] == pytest.approx(0.5)
    plain = node._apply_trust_weight("unknown-src", {"data": {"k": 1}})
    assert "confidence" not in plain
    assert plain["trust_weight"] == pytest.approx(0.5)

    assert node._calculate_confidence({}) == pytest.approx(0.25)
    assert node._calculate_confidence({"confidence": 1.0, "evidence": ["e"] * 10}) == pytest.approx(
        1.0
    )

    trust = legacy_swarm.SwarmNode("trust")
    trust.trust_scores["p"] = 0.1
    trust._update_trust_score("p", {})
    assert trust.trust_scores["p"] == pytest.approx(0.1)

    trust.shared_data["both"] = {"x": 1}
    trust.shared_data["shared_only"] = {"x": 1}
    trust.local_findings["both"] = {"x": 1}
    trust.local_findings["local_only"] = {"x": 1}
    trust.trust_scores["p"] = 0.4
    trust._update_trust_score(
        "p",
        {"both": {}, "shared_only": {}, "local_only": {}, "neither": {}},
    )
    assert trust.trust_scores["p"] == pytest.approx(0.325)

    assert trust._aggregate_group_data([]) == {}

    t0 = datetime(2024, 3, 1)
    t1 = datetime(2024, 8, 1)
    t_old = datetime(2023, 1, 1)
    decider = legacy_swarm.SwarmNode("decider")
    decider.local_findings = {
        "f1": {
            "data": {
                "threat_id": "alpha",
                "tags": ["a"],
                "meta": {"k": 1},
                "score": 1,
                "label": "text",
                "mixed": "s",
            },
            "confidence": 0.9,
            "source": "decider",
            "timestamp": t0,
        },
        "f2": {
            "data": {
                "threat_id": "alpha",
                "tags": ["b"],
                "meta": {"z": 2},
                "score": 5,
                "label": {"summary": "L"},
                "mixed": ["q"],
                "note": "added",
            },
            "confidence": 0.8,
            "source": "peer",
            "timestamp": t1,
        },
        "fold": {
            "data": {
                "threat_id": "alpha",
                "tags": "nope",
                "meta": "nope",
                "score": 0,
                "fresh_old": 1,
            },
            "confidence": 0.7,
            "source": "archive",
            "timestamp": t_old,
        },
        "low": {
            "data": {"threat_id": "beta", "score": 1},
            "confidence": 0.1,
            "source": "other",
            "timestamp": t1,
        },
    }
    decisions = decider.collective_decision(threshold=0.7)
    assert len(decisions) == 1
    decision = next(iter(decisions.values()))
    data = decision["data"]
    assert set(data["tags"]) == {"a", "b"}
    assert data["meta"] == {"k": 1, "z": 2}
    assert data["score"] == 5
    assert data["label"]["summary"] == "L"
    assert data["mixed"] == ["q"]
    assert data["note"] == "added"
    assert data["fresh_old"] == 1
    assert data["aggregated"] is True
    assert data["sources_count"] == 3
    assert decision["confidence"] == pytest.approx(0.8)

    decision_id = next(iter(decisions))
    text = decider.explain_decision(decision_id, decisions)
    assert "Décision collective" in text
    assert "L" in text
    assert "Aucune décision" in decider.explain_decision("absent", decisions)
    again = decider.explain_decision(decision_id)
    assert "confiance" in again
    lonely = legacy_swarm.SwarmNode("lonely")
    assert "Aucune décision" in lonely.explain_decision("missing")


def test_ant_colony_paths_visualize_and_factory(tmp_path, monkeypatch):
    matplotlib.use("Agg", force=True)
    assert legacy_swarm.AntColonyDetector().config == {}
    detector = legacy_swarm.AntColonyDetector(
        {
            "evaporation_rate": 0.05,
            "alpha": 1.0,
            "beta": 1.0,
            "initial_pheromone": 0.4,
        }
    )
    for node_id in ("A", "B", "C", "E", "F", "T"):
        attrs = {"kind": "host"} if node_id == "A" else None
        detector.add_node(node_id, attrs)
    detector.add_edge("A", "B", 1.0, {"rel": "lien"})
    detector.add_edge("B", "T", 1.0, {"rel": "lien"})
    detector.add_edge("B", "A", 1.0)
    detector.add_edge("A", "C", 1.0)
    detector.add_edge("C", "T", 1.0)
    detector.add_edge("A", "E", 3.0)
    detector.add_edge("E", "T", 3.0)
    detector.add_edge("A", "F", 1.0)
    assert detector.pheromones[("A", "B")] == pytest.approx(0.4)

    plan = ["A", "B", "T", "A", "C", "T", "A", "E", "T", "A", "F"]

    def choice(options, size=None, replace=True, p=None):
        if not plan:
            raise AssertionError(f"choix imprévu sur {list(options)}")
        return plan.pop(0)

    monkeypatch.setattr(legacy_swarm.np.random, "choice", choice)
    paths = detector.detect_paths(["A"], ["T"], n_ants=4, max_iterations=1)
    assert plan == []
    assert [score for _path, score in paths] == [2.0, 2.0]

    explanation = detector.explain_path(paths[0][0], paths[0][1])
    assert "Chemin de propagation" in explanation
    assert "lien" in explanation
    assert "phéromones" in explanation

    out = tmp_path / "paths.png"
    detector.visualize_paths(paths, output_file=str(out))
    assert out.is_file() and out.stat().st_size > 0
    assert detector.visualize_paths(paths) is None

    node = legacy_swarm.SwarmNode("viz")
    node.add_peer("peer-a", 0.7)
    node.add_peer("peer-b", 0.3)
    graph = node.visualize_network()
    assert set(graph.nodes) == {"viz", "peer-a", "peer-b"}
    net = tmp_path / "network.png"
    saved = node.visualize_network(output_file=str(net))
    assert net.is_file() and net.stat().st_size > 0
    assert "viz" in saved.nodes

    def boom(*args, **kwargs):
        raise RuntimeError("visualisation indisponible")

    monkeypatch.setattr("matplotlib.pyplot.figure", boom)
    assert "viz" in node.visualize_network(output_file=str(tmp_path / "bad-net.png")).nodes
    assert detector.visualize_paths(paths, output_file=str(tmp_path / "bad-paths.png")) is None

    cells = legacy_swarm.create_cells()
    assert len(cells) == 4
    assert all(isinstance(cell, legacy_swarm.SwarmNode) for cell in cells[:3])
    assert isinstance(cells[3], legacy_swarm.AntColonyDetector)
    assert set(cells[0].peers) == {"swarm_node_1", "swarm_node_2"}

    assert len(legacy_swarm.create_cells(None)) == 4
    only_detector = legacy_swarm.create_cells({"swarm_intelligence": {"enable_swarm_nodes": False}})
    assert len(only_detector) == 1
    assert isinstance(only_detector[0], legacy_swarm.AntColonyDetector)
    solo = legacy_swarm.create_cells(
        {"swarm_intelligence": {"enable_ant_colony": False, "node_count": 1}}
    )
    assert len(solo) == 1 and solo[0].peers == []
    assert (
        legacy_swarm.create_cells(
            {"swarm_intelligence": {"enable_swarm_nodes": False, "enable_ant_colony": False}}
        )
        == []
    )
    assert len(legacy_swarm.create_cells({"autre": 1})) == 4


def test_lazy_swarm_import_success_and_attribute_error():
    assert swarm_pkg.AntColonyDetector is legacy_swarm.AntColonyDetector
    assert swarm_pkg.SwarmNode is legacy_swarm.SwarmNode
    assert swarm_pkg.create_cells is legacy_swarm.create_cells
    with pytest.raises(AttributeError, match="no attribute 'missing_cell'"):
        missing = swarm_pkg.missing_cell
        assert missing is None


def test_lazy_swarm_import_error_restores_sys_modules(monkeypatch):
    key = "biocybe.swarm_intelligence.legacy_swarm"
    saved_mod = sys.modules[key]
    saved_attr = swarm_pkg.__dict__.get("legacy_swarm")
    real_import = builtins.__import__

    def blocked(name, globals=None, locals=None, fromlist=(), level=0):
        full = name if isinstance(name, str) else ""
        items = fromlist or ()
        if "legacy_swarm" in items or full.endswith("legacy_swarm"):
            raise ImportError("simulated missing legacy_swarm")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked)
    sys.modules.pop(key, None)
    swarm_pkg.__dict__.pop("legacy_swarm", None)
    try:
        with pytest.raises(ImportError, match=r"numpy \+ networkx") as raised:
            loaded = swarm_pkg.create_cells
            assert loaded is None
        assert "biocybe.swarm" in str(raised.value)
        assert isinstance(raised.value.__cause__, ImportError)
    finally:
        sys.modules[key] = saved_mod
        if saved_attr is not None:
            swarm_pkg.__dict__["legacy_swarm"] = saved_attr
        monkeypatch.undo()

    assert swarm_pkg.SwarmNode is legacy_swarm.SwarmNode
    assert key in sys.modules


class _OneStepEnv:
    def __init__(self, state_size: int):
        self.state_size = state_size
        self.renders = 0

    def reset(self):
        return np.zeros(self.state_size, dtype=np.float32)

    def step(self, action):
        return np.zeros(self.state_size, dtype=np.float32), 0.5, True, {}

    def render(self):
        self.renders += 1


def test_rl_agent_with_fake_tensorflow(tmp_path, monkeypatch):
    """Exécute le vrai agent après reload, avec un keras factice (pas d'install TF)."""
    _ensure_tensorflow_absent()
    assert rl._TF_AVAILABLE is False
    _install_fake_tensorflow()
    try:
        importlib.reload(rl)
        assert rl._TF_AVAILABLE is True

        config_path = tmp_path / "learning.yaml"
        config_path.write_text(
            "\n".join(
                [
                    "reinforcement_learning:",
                    "  training:",
                    "    learning_rate: 0.001",
                    "    discount_factor: 0.95",
                    "    episodes: 2",
                    "    batch_size: 2",
                    "    replay_buffer_size: 32",
                    "  exploration:",
                    "    strategy: epsilon_greedy",
                    "    initial_epsilon: 1.0",
                    "    final_epsilon: 0.1",
                    "    decay_steps: 10",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        state_size = 9
        action_size = rl.DefenseAction.get_action_space()
        agent = rl.BioCybeRLAgent(state_size, action_size, config_path=str(config_path))
        assert agent.learning_rate == pytest.approx(0.001)
        assert agent.episodes == 2
        assert agent.batch_size == 2
        assert agent.policy_model.units == action_size
        assert agent.value_model.units == 1
        assert agent.policy_model.compiled == "categorical_crossentropy"
        assert agent.value_model.compiled == "mse"
        assert agent.policy_model.optimizer.learning_rate == pytest.approx(0.001)

        state = np.zeros(state_size, dtype=np.float32)
        agent.exploration_strategy = "epsilon_greedy"
        agent.epsilon = 1.0
        assert 0 <= agent.act(state) < action_size
        agent.epsilon = -1.0
        assert agent.act(state) == 0
        agent.epsilon = 1.0
        agent.exploration_strategy = "boltzmann"
        assert 0 <= agent.act(state) < action_size
        agent.exploration_strategy = "default"
        assert agent.act(state) == 0
        assert agent.act(state, evaluate=True) == 0
        agent.exploration_strategy = "epsilon_greedy"
        agent.epsilon = 1.0

        assert agent.replay(2) is None
        agent.remember(state, 1, 0.5, state, False)
        agent.remember(state, 3, 1.0, state, True)
        assert agent.memory.size() == 2
        agent.replay(2)
        assert agent.policy_model.fitted == 1
        assert agent.value_model.fitted == 1
        assert agent.epsilon < 1.0
        decayed = agent.epsilon
        agent.epsilon = agent.final_epsilon
        agent.replay(2)
        assert agent.epsilon == pytest.approx(agent.final_epsilon)
        assert agent.epsilon < decayed

        agent.epsilon = 0.42
        agent.total_rewards = [1.5]
        agent.avg_rewards = [1.5]
        agent.training_episodes = 7
        model_dir = tmp_path / "rl-models"
        agent.save(str(model_dir))
        assert str(agent.policy_model.saved_to).endswith("policy_model.h5")
        assert str(agent.value_model.saved_to).endswith("value_model.h5")
        assert (model_dir / "hyperparams.pkl").is_file()

        agent.epsilon = 0.0
        agent.total_rewards = []
        agent.training_episodes = 0
        assert agent.load(str(model_dir)) is True
        assert agent.epsilon == pytest.approx(0.42)
        assert agent.total_rewards == [1.5]
        assert agent.avg_rewards == [1.5]
        assert agent.training_episodes == 7
        assert agent.load(str(tmp_path / "absent-models")) is False

        # load() a restauré l'historique : on repart d'un entraînement court.
        agent.total_rewards = []
        agent.avg_rewards = []
        agent.training_episodes = 0
        agent.exploration_strategy = "epsilon_greedy"
        agent.epsilon = 1.0
        saved_calls = []

        def remember_save(directory="models/rl"):
            saved_calls.append(directory)

        monkeypatch.setattr(agent, "save", remember_save)
        env = _OneStepEnv(state_size)
        averages = agent.train(env)
        assert len(averages) == 2
        assert env.renders == 0
        assert saved_calls == ["models/rl"]
        rendered = agent.train(env, episodes=1, render=True)
        assert len(rendered) == 3
        assert env.renders == 1
        assert saved_calls == ["models/rl", "models/rl"]

        agent.load_config(str(tmp_path / "missing.yaml"))
        assert agent.episodes == 1000
        assert agent.exploration_strategy == "epsilon_greedy"
    finally:
        _purge_tensorflow()
        importlib.reload(rl)
        assert rl._TF_AVAILABLE is False
