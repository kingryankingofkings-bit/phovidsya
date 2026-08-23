# Detection — what is measured, and what is not

## The short version

The policy thresholds are measured against a **synthetic workload corpus** that
models I/O *shape*. They are **not** validated against real ransomware. No
true-positive or false-positive rate against real malware is claimed anywhere in
this project, and none should be inferred from the numbers below.

What the measurement does establish is narrower but still worth having: the
shipped configuration does not freeze a device for legitimate high-entropy work,
and it does catch the canonical in-place encryption pattern.

Run it yourself:

```bash
aegis-shield benchmark
```

## Why entropy alone cannot work

This is the central constraint, and it is not a limitation of this
implementation — it is information theory.

A compressed archive and an encrypted file are both approximately 8.0 bits per
byte. They are statistically indistinguishable at the payload level. Measured
from the corpus:

| Workload | Mean write entropy | Reality |
|---|---:|---|
| `archive_copy` (`.tar.gz`) | 7.95 | benign |
| `media_import` (JPEG) | 7.95 | benign |
| `encrypted_volume_fill` (LUKS) | 7.96 | benign |
| `encrypt_in_place` (ransomware) | 7.96 | **attack** |

Any detector that contains on "high entropy plus volume" will freeze a machine
for copying a `.tar.gz`. That failure mode is worse than useless: it is a
self-inflicted outage triggered by ordinary work.

## What actually separates them

Ransomware **reads existing data and replaces it in place, across the
namespace**. Copying an archive writes new content to fresh blocks and never
reads what was there.

| Feature | `archive_copy` | `encrypt_in_place` |
|---|---:|---:|
| `mean_write_entropy` | 7.95 | 7.96 |
| `changed_byte_fraction` | 0.996 | 0.996 |
| `overwrite_fraction` | 1.000 | 1.000 |
| **`read_before_write_fraction`** | **0.000** | **1.000** |

So the weighting is deliberately behaviour-dominant:

| Signal | Weight | Role |
|---|---:|---|
| `read_before_write` | 0.24 | the read-then-replace signature |
| `overwrite` | 0.18 | destroying existing content |
| `coverage` | 0.16 | breadth of the campaign |
| `entropy` | 0.10 | necessary, not sufficient |
| `high_entropy` | 0.10 | necessary, not sufficient |
| `changed` | 0.10 | necessary, not sufficient |
| `write_fraction` | 0.06 | supporting |
| `deallocate` | 0.06 | wipe-after-encrypt |

Behavioural signals total 0.58 against 0.30 for content.

**Pushing `read_before_write` higher makes things worse.** A package upgrade is
also a legitimate read-then-replace. At 0.30 the benign peak rises from 0.707 to
0.758 and `software_update` starts to look like an attack. 0.24 is a measured
optimum, not a dial turned to maximum.

## Measured results

12 seeds, 512-block namespace, device pre-filled with content (a device *in
service*, not a blank one — see the caveat below).

| | Result |
|---|---|
| False positives | **0 of 7** benign workloads |
| True positives | **3 of 4** ransomware-shaped workloads |
| Loudest benign | 0.707 (`software_update`) |
| Quietest attack | 0.605 (`low_and_slow`) |
| Containment threshold | 0.82 |
| **Headroom before a false freeze** | **+0.113** |

Alert fires at 0.72 — above every benign workload, so `ELEVATED` means something
genuinely unusual rather than "someone copied an archive".

### This changed the shipped configuration

Before this was measured, the weights were content-dominant and the numbers were:

| | Before | After |
|---|---:|---:|
| Loudest benign | 0.816 | 0.707 |
| Headroom to threshold | **+0.004** | **+0.113** |
| True-positive rate | 50% | 75% |

Copying an archive scored 0.816 against a 0.820 trigger. The margin was four
thousandths. Nothing was wrong with the code — nobody had ever measured it.

## Known gaps

**`low_and_slow` is not caught.** Encryption interleaved with benign traffic
(1 malicious write per 2 benign) dilutes every windowed signal below threshold.
It peaks at 0.605 against a 0.82 threshold, and below the 0.72 alert too, so it
passes silently.

No threshold fixes this: the quietest attack (0.605) scores *below* the loudest
benign workload (0.707). The sets overlap. Catching evasive attacks needs
something this detector does not have — longer-horizon state across many
windows, or per-file rather than per-block correlation. A test
(`test_evasive_workload_is_documented_as_missed`) asserts this gap so it stays
visible rather than being quietly forgotten.

**Separation is negative (−0.102).** Stated plainly: there is no single
threshold that cleanly separates all attacks from all benign work in this
corpus. The shipped configuration prioritises never freezing a healthy machine,
and accepts missing the evasive case.

## What this measurement cannot tell you

- **Nothing about real ransomware.** The corpus models I/O shape. Real families
  differ in file selection, ordering, threading, chunk size, and whether they
  encrypt in place at all. A 75% rate here does not predict 75% in the field.
- **Nothing about real benign workloads.** Seven synthetic patterns are not a
  production fleet. A real environment will contain workloads not modelled here,
  and some may score higher than 0.707.
- **Nothing about tuned evasion.** An attacker who reads this file can stay under
  the threshold. `low_and_slow` demonstrates that without even trying hard.
- **Nothing about the hardware design.** These are software-model measurements.

## What would constitute real validation

1. A labelled corpus of real ransomware I/O traces across multiple families.
2. Captured I/O from a real production fleet for the false-positive side.
3. Replay of both through the engine, reporting TPR/FPR with confidence
   intervals.
4. Held-out evaluation — thresholds tuned on one split, reported on another.

Until that exists, treat the thresholds as **engineering estimates measured
against a synthetic corpus**, which is what `PolicyConfig`'s docstring says.

## Extending the corpus

Add a `Workload` to `BENIGN` or `RANSOMWARE` in
`aegis_shield/core/workloads.py`. The most useful additions are benign
workloads that score *high* — those are what set the safety margin. If you find
one that scores above 0.707, the corpus has told you something and the
thresholds need revisiting.
