# Reference scoring implementation

`score.py` recomputes every published score from the data files in `../data/`:
per-mechanism H(M), the per-category aggregates, the composite H_total, and the
derived breadth and quality metrics.

It is the computational implementation of the methodology that the article
refers to when it fixes the rounding order of intermediate and final values
(section 4.7). The rounding and summation order is written out under
[Rounding order](#rounding-order) below.

## Requirements

Python 3.8 or newer and PyYAML. Everything else is the standard library.

```bash
pip install -r scripts/requirements.txt   # from the directory holding data/
```

## Usage

Run it from the directory that holds `data/`:

```bash
python3 scripts/score.py                 # cross-system ranking table
python3 scripts/score.py linux           # full breakdown for one system
python3 scripts/score.py linux openbsd   # several systems
python3 scripts/score.py --list          # the systems in this data set
python3 scripts/score.py --json          # machine-readable output
```

Two options choose the weighting; `python3 scripts/score.py --help` lists them
all:

| Option | Meaning |
| --- | --- |
| `--profile` | weight profile: `balanced` (default), `security_first`, `pragmatic`, `architectural` |
| `--threat-model` | deployment category: `general_purpose_server` (default), `high_security`, `embedded_iot` |

A self-check: `python3 scripts/score.py linux` ends with

```text
  H_total = 1.67  (56% of 3.00)

  scored 69   present 57 (83%)   N/A 6 (8%)
  default-on 44 (64%, 77% of present)   mandatory 2 (3%)
  strength 111/207 (54%)   implemented quality 2.02
```

## The score

For each mechanism, with dimension weights from the chosen profile:

```text
H(M) = P x (w_d*D + w_s*S_eff + w_a*A + w_t*T)
```

`S_eff` is Strength after dependency capping: a mechanism may be at most one
level above its weakest hard prerequisite, and an absent prerequisite caps it
at S=1. The `S` in the data file stays the raw, mechanism-in-isolation
assessment. A
prerequisite that is N/A, a cross-reference or unscored is skipped rather than
treated as absent — N/A means its threat surface does not exist on that system,
so the property being relied on cannot be undermined.

Category scores H(C_k) are the mean over the scorable mechanisms of that
category; H_total is their weighted mean, with the category weights
renormalized over the categories that apply to the system in question.

## Two fields are re-derived

The published data set is a projection of the working evaluation, so two
per-mechanism fields are recomputed here rather than read:

- **`T`** — maturity is `min(T_age, T_maintained)`, the weaker of "how long has
  this existed" and "is it still maintained".
- **`status`** — `xref` when the row carries that marker, `na` when `P` is null,
  and `scored` otherwise. The `xref` marker is the one piece of workflow state
  the projection keeps, because it cannot be reconstructed: a cross-reference
  row carries zeros that would otherwise read as a scored, genuinely absent
  (P=0) mechanism, pulling down the category it sits in.

Only `scored` rows enter an average. `na` rows are excluded because the attack
surface does not exist on that system; a category leaves the H_total
normalization entirely when every independent mechanism in it is N/A.

## Rounding order

The published values depend on where rounding happens, so the order is fixed:

1. `H(M)` is rounded to 2 decimals **per mechanism**, before anything is summed.
2. Category `sum` is the rounded sum of those rounded values; category `avg` is
   `round(sum / count, 2)` — the sum is rounded first, then divided.
3. Category weights are renormalized over the applicable categories, and only
   when they do not already total 1 (within `1e-12`), so the all-categories
   case performs no division at all.
4. Each weighted term is `round(alpha * avg, 3)`; `H_total` is `round(sum, 2)`
   of those terms.
5. `implemented_quality` averages **without** the intermediate rounding of
   step 2 (`round(sum / count, 2)` directly), then `round(term, 3)` per
   category and `round(total, 2)`.
6. Percentages are `round(x / y * 100)` — Python's round-half-to-even, to an
   integer.
7. Every float sum uses Neumaier compensated summation, which is what CPython's
   builtin `sum()` does for floats from 3.12 onward. `score.py` spells the
   algorithm out so that it produces the published numbers on older
   interpreters too; a plain accumulation loop does not (it moves Linux's
   implemented quality from 2.02 to 2.03).

Rounding is half-to-even throughout, as Python's `round()` does it.

## Scope

This reproduces the published, rounded pipeline. The continuous weight-space
robustness study described in the article samples the exact unrounded form and
is not reproduced here.

## Citation

Efremov D. V. Comparative Quantitative Evaluation of Kernel Hardening Mechanisms
in Operating Systems // Proceedings of the Institute for System Programming of
the RAS. 2026. Vol. 38, no. 4. P. 81–108.
DOI: [10.15514/ISPRAS-2026-38(4)-20](https://doi.org/10.15514/ISPRAS-2026-38(4)-20).

```bibtex
@article{efremov_hardening_quant_2026,
    author  = {Efremov, D. V.},
    title   = {Comparative Quantitative Evaluation of Kernel Hardening Mechanisms in Operating Systems},
    journal = {Proceedings of the Institute for System Programming of the RAS},
    year    = {2026},
    volume  = {38},
    number  = {4},
    pages   = {81--108},
    doi     = {10.15514/ISPRAS-2026-38(4)-20},
    issn    = {2079-8156}
}
```

## License

`score.py` and this file: MIT, © 2026 Denis Efremov. The evaluation data in
`../data/` is CC BY 4.0.
