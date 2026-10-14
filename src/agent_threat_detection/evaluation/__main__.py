"""Measure detection and false-positive rates on a synthetic labelled trace.

python -m agent_threat_detection.evaluation [--agents 12] [--days 10] [--seed N] [--rules DIR]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent_threat_detection.detection.config import DetectionConfig
from agent_threat_detection.detection.detectors import BehaviouralDetectors
from agent_threat_detection.detection.pipeline import DetectionPipeline
from agent_threat_detection.detection.sigma import RuleSet
from agent_threat_detection.evaluation.metrics import evaluate
from agent_threat_detection.evaluation.simulator import INTERNAL_SUFFIX, TraceConfig, TraceGenerator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_threat_detection.evaluation")
    parser.add_argument("--agents", type=int, default=12)
    parser.add_argument("--days", type=int, default=10)
    parser.add_argument("--episodes", type=int, default=6)
    parser.add_argument("--seed", type=int, default=TraceConfig().seed)
    parser.add_argument("--rules", type=Path, default=Path("rules"))
    args = parser.parse_args(argv)
    trace = TraceGenerator(
        TraceConfig(
            agents=args.agents, days=args.days, episodes_per_scenario=args.episodes, seed=args.seed
        )
    ).generate()
    pipeline = DetectionPipeline(
        BehaviouralDetectors(DetectionConfig(internal_domain_suffixes=(INTERNAL_SUFFIX,))),
        RuleSet.from_directory(args.rules),
    )
    report = evaluate(trace, pipeline)
    sys.stdout.write(report.model_dump_json(indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
