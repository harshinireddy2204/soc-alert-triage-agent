"""Turn saved runs into a results table, two charts and a README section."""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import paths
from .evaluate import evaluate
from .run import load_results, select_cases

START, END = "<!-- results:start -->", "<!-- results:end -->"
# Categorical colours in fixed order (blue, orange, aqua, yellow, magenta, green).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"]
INK, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
ORDER = ["always-escalate", "severity-rule", "scorecard"]


def _pct(value: float | None, digits: int = 0) -> str:
    return "n/a" if value is None else f"{100 * value:.{digits}f}%"


def _with_ci(report: dict, key: str) -> str:
    low, high = report["confidence_intervals"].get(key, [None, None])
    if report[key] is None:
        return "n/a"
    if low is None:
        return _pct(report[key])
    return f"{_pct(report[key])} ({100 * low:.0f} to {100 * high:.0f})"


def collect(split: str, bootstrap_rounds: int = 1000) -> list[dict]:
    cases = select_cases(split)
    reports = []
    for path in sorted((paths.RESULTS / split).glob("*.jsonl")):
        results = load_results(path)
        if not results:
            continue
        report = evaluate(cases, results, bootstrap_rounds)
        report["file"] = path.name
        reports.append(report)
    reports.sort(key=lambda r: (ORDER.index(r["policy"]) if r["policy"] in ORDER else len(ORDER), r["policy"]))
    return reports


def table(reports: list[dict]) -> str:
    lines = [
        "| Policy | Auto-resolved | Accuracy when it decides | Attacks auto-closed as benign | Benign auto-raised as attack | Accuracy if forced to decide all |",
        "|---|---|---|---|---|---|",
    ]
    for r in reports:
        lines.append(
            f"| `{r['policy']}` | {_with_ci(r, 'auto_resolved')} | {_with_ci(r, 'auto_accuracy')} | "
            f"{r['missed_attack_count']} of {r['malicious']} ({_pct(r['missed_attacks'], 1)}) | "
            f"{r['false_alarm_count']} of {r['benign']} ({_pct(r['benign_raised_as_attack'], 1)}) | {_with_ci(r, 'forced_accuracy')} |"
        )
    return "\n".join(lines)


def escalation_table(reports: list[dict]) -> str:
    lines = [
        "| Policy | Escalated | Escalated cases it would have got wrong | Auto-resolved cases it got wrong | Share of its errors that escalation caught | Auto-resolvable at 95% accuracy |",
        "|---|---|---|---|---|---|",
    ]
    for r in reports:
        lines.append(
            f"| `{r['policy']}` | {_pct(r['escalated'])} | {_pct(r['escalated_would_be_wrong'])} | {_pct(r['auto_would_be_wrong'])} | "
            f"{_pct(r['errors_caught_by_escalation'])} | {_pct(r['coverage_at_95_accuracy'])} |"
        )
    return "\n".join(lines)


def cost_table(reports: list[dict]) -> str:
    lines = [
        "| Policy | Tool calls per case | Seconds per case | Tokens per case (in / out) | Cited events that were really shown | Investigations that failed |",
        "|---|---|---|---|---|---|",
    ]
    for r in reports:
        cost, evidence = r["cost"], r["evidence"]
        lines.append(
            f"| `{r['policy']}` | {cost['mean_tool_calls']:.1f} | {cost['mean_seconds']:.2f} | "
            f"{cost['mean_input_tokens']:.0f} / {cost['mean_output_tokens']:.0f} | "
            f"{(_pct(evidence['citation_validity']) + ' of ' + str(evidence['citations'])) if evidence['citations'] else 'cites nothing'} | "
            f"{cost['failed_investigations']} |"
        )
    return "\n".join(lines)


def breakdown_table(report: dict, key: str, heading: str) -> str:
    lines = [
        f"| {heading} | Cases | Accuracy if forced | Auto-resolved | Accuracy when it decides | Attacks auto-closed | Benign auto-raised |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, row in report[key].items():
        lines.append(
            f"| {name} | {row['cases']} | {_pct(row['forced_accuracy'])} | {_pct(row['auto_resolved'])} | "
            f"{_pct(row['auto_accuracy'])} | {row['missed_attack_count']} | {row['false_alarm_count']} |"
        )
    return "\n".join(lines)


def charts(reports: list[dict], split: str, out_dir: Path) -> list[Path]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "text.color": INK,
            "axes.labelcolor": MUTED,
            "xtick.color": MUTED,
            "ytick.color": MUTED,
            "axes.edgecolor": GRID,
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
        }
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []

    # 1. What happened to every case, per policy.
    figure, axis = plt.subplots(figsize=(8.6, 0.72 * len(reports) + 1.5))
    parts = [("Decided alone, correct", SERIES[0]), ("Escalated to a human", SERIES[2]), ("Decided alone, wrong", SERIES[1])]
    for row, report in enumerate(reversed(reports)):
        auto_right = report["auto_resolved"] * (report["auto_accuracy"] or 0)
        values = [auto_right, report["escalated"], report["auto_resolved"] - auto_right]
        left = 0.0
        for (label, color), value in zip(parts, values, strict=True):
            if value > 0:
                axis.barh(
                    row, value, left=left, color=color, height=0.52, edgecolor=SURFACE, linewidth=2, label=label if row == 0 else None
                )
                if value >= 0.06:
                    axis.text(
                        left + value / 2,
                        row,
                        f"{100 * value:.0f}%",
                        ha="center",
                        va="center",
                        color="white",
                        fontsize=10,
                        fontweight="bold",
                    )
                elif value > 0:
                    axis.text(left + value + 0.008, row + 0.34, f"{100 * value:.0f}%", ha="left", va="center", color=INK, fontsize=9)
            left += value
    axis.set_yticks(range(len(reports)), [r["policy"] for r in reversed(reports)])
    axis.tick_params(axis="y", colors=INK, length=0)
    axis.set_xlim(0, 1)
    axis.set_xticks([0, 0.25, 0.5, 0.75, 1], ["0%", "25%", "50%", "75%", "100%"])
    axis.set_xlabel(f"Share of the {reports[0]['cases']} scored {split} cases")
    for side in ("top", "right", "left"):
        axis.spines[side].set_visible(False)
    handles, labels = axis.get_legend_handles_labels()
    order = [labels.index(label) for label, _ in parts if label in labels]
    axis.legend(
        [handles[i] for i in order],
        [labels[i] for i in order],
        loc="lower center",
        bbox_to_anchor=(0.5, 1.0),
        ncol=3,
        frameon=False,
        fontsize=9.5,
        handlelength=1.2,
    )
    figure.tight_layout()
    path = out_dir / f"outcomes_{split}.png"
    figure.savefig(path, dpi=170)
    plt.close(figure)
    written.append(path)

    # 2. Accuracy against the share of cases acted on, most confident first.
    curves = [r for r in reports if len(r["risk_coverage"]) > 1]
    if curves:
        figure, axis = plt.subplots(figsize=(8.6, 4.4))
        for index, report in enumerate(curves):
            xs = [p["coverage"] for p in report["risk_coverage"]]
            ys = [p["accuracy"] for p in report["risk_coverage"]]
            color = SERIES[index % len(SERIES)]
            axis.plot(xs, ys, color=color, linewidth=2, marker="o", markersize=4, label=report["policy"])
            axis.annotate(
                report["policy"],
                (xs[-1], ys[-1]),
                xytext=(-6, -14 if index % 2 else 8),
                textcoords="offset points",
                ha="right",
                color=INK,
                fontsize=9,
            )
        axis.axhline(0.95, color=MUTED, linewidth=1, linestyle=(0, (4, 4)))
        axis.text(0.995, 0.953, "95% accuracy", color=MUTED, fontsize=9, va="bottom", ha="right")
        axis.set_xlim(0, 1.0)
        low = min(min(p["accuracy"] for p in r["risk_coverage"]) for r in curves)
        axis.set_ylim(max(0.0, low - 0.08), 1.01)
        axis.set_xticks([0, 0.25, 0.5, 0.75, 1], ["0%", "25%", "50%", "75%", "100%"])
        axis.set_yticks([t / 10 for t in range(int(max(0.0, low - 0.08) * 10) + 1, 11)])
        axis.set_yticklabels([f"{t * 10}%" for t in range(int(max(0.0, low - 0.08) * 10) + 1, 11)])
        axis.set_xlabel("Share of cases acted on automatically, most confident first")
        axis.set_ylabel("Accuracy on those cases")
        axis.grid(axis="y", color=GRID, linewidth=1)
        axis.set_axisbelow(True)
        for side in ("top", "right"):
            axis.spines[side].set_visible(False)
        if len(curves) > 1:
            axis.legend(frameon=False, fontsize=9.5, loc="lower left")
        figure.tight_layout()
        path = out_dir / f"accuracy_coverage_{split}.png"
        figure.savefig(path, dpi=170)
        plt.close(figure)
        written.append(path)
    return written


def results_markdown(reports: list[dict], split: str) -> str:
    first = reports[0]
    lines = [
        f"Scored on the **{split}** split: {first['cases']} cases ({first['malicious']} malicious, {first['benign']} benign) "
        f"from {len({c['capture'] for c in select_cases(split)})} recordings. "
        "Ranges in brackets are 95% intervals from resampling whole recordings.",
        "",
        table(reports),
        "",
        f"![What each policy did with every case](docs/img/outcomes_{split}.png)",
        "",
        "**Does it know when it does not know?**",
        "",
        escalation_table(reports),
        "",
        f"![Accuracy against share of cases acted on](docs/img/accuracy_coverage_{split}.png)",
        "",
        "**Cost and grounding**",
        "",
        cost_table(reports),
    ]
    return "\n".join(lines)


def details_markdown(reports: list[dict], split: str) -> str:
    cases = {c["case_id"]: c for c in select_cases(split)}
    lines = [
        f"# Detailed results ({split} split)",
        "",
        "Generated by `python -m triage report`. Do not edit by hand.",
        "",
        results_markdown(reports, split).replace("docs/img/", "../docs/img/"),
        "",
    ]
    for report in reports:
        lines += [f"## `{report['policy']}`", ""]
        lines += ["By highest rule severity in the case:", "", breakdown_table(report, "by_rule_severity", "Severity"), ""]
        lines += ["By how the ground-truth label was established:", "", breakdown_table(report, "by_label_basis", "Truth and basis"), ""]
        side = report["side_effect_cases"]
        lines += [
            f"Side-effect cases (not scored): {side['cases']} cases, {side['called_malicious']} called malicious, "
            f"{side['called_benign']} called benign, {side['escalated']} escalated.",
            "",
        ]
        decided_wrong = [e for e in report["errors"] if not e["escalated"]]
        if decided_wrong:
            lines += [
                "Wrong verdicts it acted on without escalating:",
                "",
                "| Case | Truth | Verdict | Confidence | Rule severity | Process | Why the truth is what it is |",
                "|---|---|---|---|---|---|---|",
            ]
            for error in decided_wrong:
                image = (error["image"] or "?").replace("|", "\\|")
                reason = cases[error["case_id"]]["label_reason"].replace("|", "\\|")
                lines.append(
                    f"| {error['case_id']} | {error['truth']} | {error['verdict']} | {error['confidence']:.2f} | {error['max_level']} | `{image}` | {reason} |"
                )
            lines.append("")
    return "\n".join(lines)


def write_report(split: str = "test", bootstrap_rounds: int = 1000, update_readme: bool = True, log=print) -> list[dict]:
    reports = collect(split, bootstrap_rounds)
    if not reports:
        raise SystemExit(f"no runs found in {paths.RESULTS / split}; run `python -m triage run` first")
    charts(reports, split, paths.REPO / "docs" / "img")
    summary = [{k: v for k, v in r.items() if k not in ("errors",)} for r in reports]
    (paths.RESULTS / f"summary_{split}.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (paths.RESULTS / f"RESULTS_{split}.md").write_text(details_markdown(reports, split) + "\n", encoding="utf-8")
    readme = paths.REPO / "README.md"
    if update_readme and split == "test" and readme.exists():
        text = readme.read_text(encoding="utf-8")
        if START in text and END in text:
            block = f"{START}\n{results_markdown(reports, split)}\n{END}"
            readme.write_text(re.sub(re.escape(START) + r".*?" + re.escape(END), lambda _: block, text, flags=re.DOTALL), encoding="utf-8")
    log(f"wrote results/summary_{split}.json, results/RESULTS_{split}.md and charts in docs/img")
    return reports
