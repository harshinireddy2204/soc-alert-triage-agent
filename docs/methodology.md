# Methodology

This note records the decisions behind the benchmark and the evaluation, including the ones that
make the numbers look worse.

## From recordings to cases

1. **Source.** 105 host recordings from OTRF Security Datasets at commit `d9d40ef`. Each records one
   simulated attack technique on lab machines, together with whatever else those machines were
   doing. 19 published recordings are excluded, each with a stated reason in
   `benchmark/captures.yaml` (older export format, no process-creation events, a duplicate, and one
   with inconsistent process identifiers).
2. **Normalisation.** Sysmon records carry a true UTC time; other channels carry only the
   collector's wall clock. The offset between the two is measured on the Sysmon records of each
   recording and applied to the rest, so timelines line up across channels.
3. **Process attribution.** PowerShell's own logs name their host process only by PID. They are
   matched to the Sysmon process list so that script text can be read as part of one process's
   activity. Processes that started before a recording began are reconstructed from later mentions
   (as a parent, or as the subject of a file, registry or network event).
4. **Detection.** The SigmaHQ rule set at commit `8a48134` is run unmodified over every event by a
   small evaluator written for this project (`src/triage/sigma.py`). Rules it cannot evaluate
   faithfully are skipped and counted. Rules rated `informational` are not alerts and are left out.
5. **Cases.** Hits are grouped by (host, process). A hit that cannot be tied to a process is counted
   and left out.

## Labels

The label answers one question: **was the activity that fired the rules the attacker's doing?**

- `malicious`: the process was attacker-controlled (a foothold, a descendant of one, or started
  remotely by the attacker), or it is a system service carrying out the attacker's request and the
  event that fired names something the attacker created.
- `benign`: unrelated to the simulated attack.
- `side_effect`: a Windows component reacting generically to something the attacker started, where
  the event that fired contains nothing the attacker made. Not scored.

Footholds come from each recording's published metadata, which includes the attacker's console
transcript with agent process IDs. Descendants are labeled by ancestry, with no exceptions: a
console host or crash reporter spawned under an attacker process exists only because of the attack,
and an analyst would file its alert under the incident.

Every label carries its basis (`foothold`, `lineage`, `reviewed`, or the id of a recurring pattern)
and a sentence of reasoning, in `benchmark/cases.jsonl`. Results are broken down by basis, which
shows where a policy's errors concentrate.

**Known weaknesses.** One reviewer, working with rule-assisted review, and no independent audit.
The boundary between "service acting on the attacker's request" (malicious) and "component reacting
generically" (side effect) is a judgment call; the rule used is whether the event names an object
the attacker created. Sysmon occasionally fails to record a parent link, in which case the label
rests on a reviewed decision instead of ancestry.

## Split and tuning

Recordings, not cases, are assigned to dev or test by `sha1(name) mod 100 < 35`. Nobody chose which
recordings went where.

The checklist baseline has three numbers that were tuned, on dev only, by rules fixed before
looking at the outcome:

- `DECIDE_AT`: the cut that maximises forced-choice accuracy on dev.
- `BENIGN_AT`, `MALICIOUS_AT`: the widest auto-resolve band that keeps accuracy on auto-resolved dev
  cases at 95% or more.

Its signals and weights were written by hand by the same person who reviewed the labels, having
seen cases from both splits. Treat its test score as an upper bound on what a checklist would do on
data its author had not seen.

The LLM agent's prompt contains no examples from the benchmark.

## Metrics

Each policy returns a best-guess verdict, a confidence and an escalate flag, for every case.

| Metric | Question it answers |
|---|---|
| Accuracy if forced to decide all | How good are the verdicts, ignoring escalation? |
| Auto-resolved | What share of the queue does it take off a human's desk? |
| Accuracy when it decides | Of the cases it acted on alone, how many were right? |
| Attacks auto-closed as benign | The expensive error: a real attack closed without review. |
| Benign auto-raised as attack | The cheap but corrosive error: noise presented as a finding. |
| Escalated cases it would have got wrong | Is escalation aimed at the right cases? Compare with the next column. |
| Auto-resolved cases it got wrong | The error rate where it chose not to escalate. |
| Share of its errors that escalation caught | Of everything its best guess got wrong, how much did a human get to see? |
| Auto-resolvable at 95% accuracy | If only its most confident verdicts were acted on, how many could be, at 95%? Uses confidence, not the escalate flag. |
| Cited events that were really shown | Does the evidence it cites exist in what it was given? |

Intervals are 95% percentile intervals from 1,000 resamples of whole recordings. With 69 test
recordings they are wide, and differences of a few points between policies should not be read as
real.

## Reproducing

`python -m triage fetch` verifies every recording against a pinned SHA-256. `python -m triage build`
then regenerates `benchmark/cases.jsonl` identically. Baseline results are deterministic. LLM runs
use temperature 0 and a fixed seed where the backend supports one, but should be expected to vary
slightly between model builds.
