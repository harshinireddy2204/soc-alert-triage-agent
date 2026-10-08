"""Command line entry point: ``python -m triage <command>``."""

from __future__ import annotations

import argparse
import json
import re
import sys

from . import paths


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "-", name.lower()).strip("-")


def cmd_fetch(args: argparse.Namespace) -> None:
    from .fetch import fetch

    fetch()


def cmd_build(args: argparse.Namespace) -> None:
    from .build import build

    build()


def _policy(args: argparse.Namespace):
    from .baselines import AlwaysEscalate, Scorecard, SeverityRule

    if args.policy == "scorecard":
        return Scorecard()
    if args.policy == "severity-rule":
        return SeverityRule()
    if args.policy == "always-escalate":
        return AlwaysEscalate()
    from .agent import LLMAgent
    from .llm import make_backend

    if not args.model:
        raise SystemExit("--model is required for the llm policy, for example --model qwen2.5:7b")
    backend = make_backend(args.backend, args.model, args.base_url, args.api_key_env, args.context_tokens)
    return LLMAgent(backend, max_steps=args.max_steps)


def cmd_run(args: argparse.Namespace) -> None:
    from .run import run_policy, select_cases

    if not paths.STORE_FILE.exists():
        raise SystemExit("event store not found; run `python -m triage fetch` and `python -m triage build` first")
    policy = _policy(args)
    cases = select_cases(args.split, args.limit, args.case)
    out = paths.RESULTS / args.split / f"{_slug(policy.name)}.jsonl"
    print(f"{policy.name}: {len(cases)} cases -> {out}")
    run_policy(policy, cases, out, resume=not args.fresh)


def cmd_report(args: argparse.Namespace) -> None:
    from .report import write_report

    reports = write_report(args.split, args.bootstrap)
    from .report import table

    print(table(reports))


def cmd_show(args: argparse.Namespace) -> None:
    """Print one investigation: the alert, each step, the verdict, and the truth."""
    from .agent import render_case
    from .build import load_cases
    from .run import load_results, public_view

    case = next((c for c in load_cases() if c["case_id"] == args.case_id), None)
    if case is None:
        raise SystemExit(f"no case {args.case_id}")
    print(render_case(public_view(case)))
    for path in sorted((paths.RESULTS / case["split"]).glob("*.jsonl")):
        if args.policy and args.policy not in path.stem:
            continue
        result = next((r for r in load_results(path) if r["case_id"] == args.case_id), None)
        if result is None:
            continue
        print(f"\n===== {result['policy']} =====")
        for number, step in enumerate(result["steps"], start=1):
            print(f"\n[{number}] {step.get('thought', '')}")
            if step["action"] != "final":
                print(f"    -> {step['action']} {json.dumps(step.get('arguments', {}))}")
                print("    " + step.get("output", "").replace("\n", "\n    ")[: args.width])
        outcome = "ESCALATE" if result["escalate"] else "DECIDED"
        print(f"\n{outcome}: {result['verdict']} (confidence {result['confidence']:.2f})")
        print(f"Summary: {result['summary']}")
        cited = ", ".join(f"E{e}" for e in result["evidence"]) or "none"
        unseen = ", ".join(f"E{e}" for e in result["evidence_not_shown"]) or "none"
        print(f"Evidence cited: {cited}. Cited but never shown to it: {unseen}.")
    print(f"\nGROUND TRUTH: {case['label']} ({case['label_basis']}). {case['label_reason']}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="triage", description="SOC alert triage agent and evaluation harness")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("fetch", help="download the public source data at pinned commits").set_defaults(run=cmd_fetch)
    commands.add_parser("build", help="build the event store, detect, and label the cases").set_defaults(run=cmd_build)

    run = commands.add_parser("run", help="triage cases with a policy and save the results")
    run.add_argument("policy", choices=["llm", "scorecard", "severity-rule", "always-escalate"])
    run.add_argument("--split", choices=["dev", "test", "all"], default="test")
    run.add_argument("--limit", type=int, help="only the first N cases")
    run.add_argument("--case", action="append", help="a specific case id; may be repeated")
    run.add_argument("--fresh", action="store_true", help="discard earlier results instead of resuming")
    run.add_argument("--backend", choices=["ollama", "openai"], default="ollama")
    run.add_argument("--model", help="model name as the backend knows it")
    run.add_argument("--base-url", help="server address (Ollama host, or an OpenAI-compatible /v1 base URL)")
    run.add_argument("--api-key-env", default="OPENAI_API_KEY", help="environment variable that holds the API key")
    run.add_argument("--context-tokens", type=int, default=8192, help="context window to request from Ollama")
    run.add_argument("--max-steps", type=int, default=10, help="tool calls allowed per case")
    run.set_defaults(run=cmd_run)

    report = commands.add_parser("report", help="score every saved run and regenerate tables and charts")
    report.add_argument("--split", choices=["dev", "test"], default="test")
    report.add_argument("--bootstrap", type=int, default=1000, help="resampling rounds for the intervals")
    report.set_defaults(run=cmd_report)

    show = commands.add_parser("show", help="print one case and how each policy handled it")
    show.add_argument("case_id")
    show.add_argument("--policy", help="only policies whose name contains this text")
    show.add_argument("--width", type=int, default=1200, help="characters of each tool output to print")
    show.set_defaults(run=cmd_show)

    args = parser.parse_args(argv)
    args.run(args)


if __name__ == "__main__":
    main(sys.argv[1:])
