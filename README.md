# OS Hardening Evaluation

Supplementary data and interactive viewer for a comparative quantitative evaluation
of kernel hardening mechanisms across nine operating systems.

**Live site: <https://evdenis.github.io/os-hardening-evaluation/>**

The viewer shows per-profile rankings, a cross-OS radar comparison, per-category
dossiers, and per-mechanism evidence with the originating upstream commit and its
diff rendered inline.

## Scope

| System | Kernel | Evaluated version | TCB, KLOC |
|---|---|---|---|
| Linux | monolithic | 7.1.4 / Fedora 44 (`7.1.4-200.fc44`) | 11 158 |
| OpenBSD | monolithic | 7.9 | 1 909 |
| NetBSD | monolithic | 11.0 | 2 269 |
| Fuchsia (Zircon) | microkernel | F30 | 234 |
| GNU/Hurd (GNU Mach) | microkernel | snapshot 2026-07-21 / Debian GNU/Hurd 2025 | 54 |
| Redox OS | microkernel | 0.9.0 / kernel crate 0.5.12 | 29 |
| Zephyr RTOS | monolithic | v4.4.1 | 25 |
| Tock OS | monolithic | 2.2 | 33 |
| seL4 | microkernel | 15.0.0 | 11 |

## Scoring model

76 mechanisms in 7 categories and 22 subcategories, each scored on five dimensions:

| Dimension | Range | Meaning |
|---|---|---|
| P — Presence | N/A, 0–1 | Is the mechanism implemented? (N/A = no such attack surface) |
| D — Default posture | 0–3 | Off, available, on by default, or architecturally mandatory |
| S — Strength | 0–3 | How hard is the defense to bypass? |
| A — Integration depth | 0–3 | Out-of-tree patch, in-tree option, or inseparable property |
| T — Maturity | 0–3 | `min(age, maintenance activity)` |

Composite score: `H(M) = P × (w_D·D + w_S·S + w_A·A + w_T·T)`, aggregated per category
and overall. Four weight profiles (`balanced`, `security_first`, `pragmatic`,
`architectural`) and three deployment categories (`general_purpose_server`,
`high_security`, `embedded_iot`) are shipped, and the viewer lets you switch between
them.

| Category | Mechanisms |
|---|---|
| C1 — Memory corruption prevention | 26 |
| C2 — Control flow integrity | 8 |
| C3 — Information leak prevention | 9 |
| C4 — Privilege boundary enforcement | 6 |
| C5 — Architectural isolation | 13 |
| C6 — Integrity and trust chain | 5 |
| C7 — Transient execution defenses | 9 |

## Reproducing the scores

Every published number can be recomputed from `data/` with the reference
implementation in `scripts/`. It needs Python 3.8+ and PyYAML, nothing else:

```bash
git clone https://github.com/evdenis/os-hardening-evaluation
cd os-hardening-evaluation
pip install -r scripts/requirements.txt

python3 scripts/score.py                 # cross-system ranking table
python3 scripts/score.py linux           # full per-mechanism breakdown
python3 scripts/score.py --all --json    # machine-readable output
```

This is the implementation the article refers to when it fixes the rounding
order of intermediate and final values (section 4.7); that order is written
out in [`scripts/README.md`](scripts/README.md).

## Contents

- `index.html`, `assets/` — prebuilt SPA (React/Vite bundle, self-hosted fonts,
  Shiki grammars for the diff view)
- `data/taxonomy.yaml` — mechanism catalogue, per-OS metadata and architectural
  metrics, dimension-weight profiles and category weights
- `data/evaluation-<os>.yaml` — 76 rows per system: P/D/S/A/T scores with prose
  rationale, config options, source files, upstream commits and discussion links
- `data/evaluation-empty.yaml` — blank template for adding a system
- `data/commit-details.json`, `data/commit-diffs.json` — cached metadata and unified
  diffs for 514 upstream commits, backing the evidence viewer
  (`commit-diffs.json` is ~8 MB and dominates the clone size)
- `scripts/` — reference implementation of the scoring pipeline
  (`score.py`, `README.md`, `requirements.txt`): recomputes every published
  score from `data/`, with the rounding order documented
- `.nojekyll` — keeps GitHub Pages from filtering the build output

## Citation

Efremov D. V. Comparative Quantitative Evaluation of Kernel Hardening Mechanisms in
Operating Systems // Proceedings of the Institute for System Programming of the RAS.
2026. Vol. 38, no. 4. P. 81–108. DOI:
[10.15514/ISPRAS-2026-38(4)-20](https://doi.org/10.15514/ISPRAS-2026-38(4)-20).
[Full text](https://www.ispras.ru/proceedings/isp_38_2026_4-2/isp_38_2026_4-2_81/)

```bibtex
@article{efremov_hardening_quant_2026,
    author = {Efremov, D. V.},
    title = {Comparative Quantitative Evaluation of Kernel Hardening Mechanisms in Operating Systems},
    journal = {Proceedings of the Institute for System Programming of the RAS},
    year = {2026},
    volume = {38},
    number = {4},
    pages = {81--108},
    doi = {10.15514/ISPRAS-2026-38(4)-20},
    issn = {2079-8156},
    url = {https://www.ispras.ru/proceedings/isp_38_2026_4-2/isp_38_2026_4-2_81/}
}
```

## License

- Viewer code and reference scripts (`index.html`, `assets/`, `scripts/`) — MIT,
  see [`LICENSE`](LICENSE).
- Evaluation data (`data/`) — CC BY 4.0, see [`LICENSE-DATA`](LICENSE-DATA).

Bundled third-party assets keep their own terms: the Inter Tight, JetBrains Mono and
Source Serif 4 `.woff2` subsets are under SIL Open Font License 1.1; the Shiki
grammar and theme chunks are MIT.
