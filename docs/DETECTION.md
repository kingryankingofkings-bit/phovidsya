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
| True positives | **3 of 5** ransomware-shaped workloads |
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

## Known gaps — and how cheap evasion actually is

**One interleaved benign write per encryption defeats containment.** Not an
exotic technique; the minimum possible effort.

| Benign writes per encryption | Peak score | Contained (0.82)? | Alerted (0.72)? |
|---:|---:|---|---|
| 0 (straight sweep) | 0.907 | **yes** | yes |
| 1 (`minimal_evasion`) | 0.776 | no | yes |
| 2 (`low_and_slow`) | 0.606 | no | no |
| 4 | 0.595 | no | no |
| 8 | 0.553 | no | no |

The cliff is between 0 and 1. That is the honest measure of how much the
current design demands of an attacker.

Note the middle row still **alerts**. Escaping containment is not the same as
being invisible, and it is why the alert threshold sits at 0.72 rather than
being folded into the containment threshold: it is the only signal an operator
gets in the 1:1 case.

### A bigger window does not fix it

An earlier version of this document said the gap needed "longer-horizon state
across many windows". **That was measured and is wrong**, so it is corrected
here. Over a 1:2 interleave:

| Window | Peak score |
|---:|---:|
| 128 (shipped) | 0.645 |
| 256 | 0.680 |
| 512 | 0.702 |
| 1024 | 0.681 |

A 4× window buys ~0.06 and then plateaus — 1024 scores *below* 512. Roughly
0.18 would be needed to reach containment.

The reason is structural: the policy consumes windowed **means**, and a mean is
close to ratio-invariant. Averaging over more operations at the same
malicious-to-benign ratio yields nearly the same average. Enlarging the window
does not sharpen a ratio; it just measures the same ratio more smoothly.

**Any fix has to accumulate rather than average.** An attacker encrypting
10,000 files slowly still performs 10,000 read-encrypt-overwrite operations; a
running *count* of high-suspicion operations sees that campaign, and a windowed
*mean* structurally cannot. That is a different mechanism, not a tuning change.

It is deliberately not implemented here. Choosing its thresholds would mean
tuning a new decision path against the eleven synthetic workloads on this page,
which is how a detector comes to score well in a lab and badly in the field.
That mechanism needs real traces before it needs code.

`test_one_interleaved_write_defeats_containment` and
`test_window_size_cannot_close_the_dilution_gap` pin both findings.

**Separation is negative (−0.102).** Stated plainly: no single threshold
separates all attacks from all benign work in this corpus. The shipped
configuration prioritises never freezing a healthy machine and accepts missing
the diluted cases.

## What this measurement cannot tell you

- **Nothing about real ransomware.** The corpus models I/O shape. Real families
  differ in file selection, ordering, threading, chunk size, and whether they
  encrypt in place at all. A 75% rate here does not predict 75% in the field.
- **Nothing about real benign workloads.** Seven synthetic patterns are not a
  production fleet. A real environment will contain workloads not modelled here,
  and some may score higher than 0.707.
- **Nothing about tuned evasion.** An attacker who reads this file can stay under
  the threshold — and the table above shows one interleaved write is enough. The
  corpus measures the *cost* of evasion, not resistance to it.
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
