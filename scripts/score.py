#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Denis Efremov
"""Reference implementation of the OS kernel hardening score.

Recomputes every published number from the data files shipped next to this
script: per-mechanism H(M), the per-category aggregates, the composite
H_total, and the derived breadth/quality metrics.

    H(M) = P x (w_d*D + w_s*S_eff + w_a*A + w_t*T)

This is the computational implementation of the methodology that the article
refers to when it fixes the rounding order of intermediate and final values
(article section 4.7; see the Rounding order section of README.md).

Usage, from the directory that holds ``data/``:

    python3 scripts/score.py                 # cross-system ranking table
    python3 scripts/score.py linux           # full breakdown for one system
    python3 scripts/score.py linux openbsd --profile security_first
    python3 scripts/score.py --list          # the systems in this data set
    python3 scripts/score.py --json          # machine-readable output

Requires Python 3.8 or newer and PyYAML (``pip install -r requirements.txt``).
Everything else is the standard library.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

# The repository lints at target-version py312, but this file is downloaded
# and run on whatever interpreter a reader happens to have.
if sys.version_info < (3, 8):  # noqa: UP036
    sys.exit(f"score.py needs Python 3.8 or newer; this is {sys.version.split()[0]}")

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not a code path
    sys.exit("score.py needs PyYAML: pip install -r requirements.txt")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CATEGORIES = ("C1", "C2", "C3", "C4", "C5", "C6", "C7")

PROFILES = ("balanced", "security_first", "pragmatic", "architectural")
THREAT_MODELS = ("general_purpose_server", "high_security", "embedded_iot")

DEFAULT_PROFILE = "balanced"
DEFAULT_THREAT_MODEL = "general_purpose_server"

# Only "scored" rows enter an average. "na" means the attack surface does not
# exist on that system; "xref" means the row is a cross-reference to another
# mechanism and would otherwise be counted twice.
SCORABLE_STATUSES = frozenset({"scored"})

# H_total is reported as a percentage of the theoretical maximum of 3.00.
MAX_SCORE = 3.00


# ---------------------------------------------------------------------------
# Locating the data
# ---------------------------------------------------------------------------


def data_dir_candidates() -> list[Path]:
    """The two layouts this file is expected to live in, in probe order.

    1. the published data set: ``<root>/scripts/score.py`` beside ``<root>/data/``
    2. the research repository: ``scripts/public/score.py`` beside
       ``evaluation/public/``

    Both are resolved relative to this file, never to the working directory,
    so the answer does not depend on where the script is invoked from.
    """
    here = Path(__file__).resolve().parent
    return [here.parent / "data", here.parent.parent / "evaluation" / "public"]


def resolve_data_dir(explicit: str | None = None) -> Path:
    """Return the directory holding taxonomy.yaml, or exit with a useful error."""
    if explicit is not None:
        path = Path(explicit).expanduser().resolve()
        if not (path / "taxonomy.yaml").is_file():
            sys.exit(f"no taxonomy.yaml in {path}")
        return path
    for candidate in data_dir_candidates():
        if (candidate / "taxonomy.yaml").is_file():
            return candidate
    tried = "\n  ".join(str(c) for c in data_dir_candidates())
    sys.exit(f"could not locate the data directory; tried:\n  {tried}\nPass --data-dir.")


def load_taxonomy(data_dir: Path) -> dict:
    """Load the mechanism catalogue, weight profiles and system metadata."""
    with (data_dir / "taxonomy.yaml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_evaluation(data_dir: Path, os_id: str) -> dict:
    """Load one system's scores."""
    path = data_dir / f"evaluation-{os_id}.yaml"
    if not path.is_file():
        sys.exit(f"no evaluation file for {os_id!r} ({path})")
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def available_os_ids(taxonomy: Mapping) -> list[str]:
    """The evaluated systems, in taxonomy order.

    Read from ``operating_systems`` rather than by globbing the data
    directory: ``evaluation-empty.yaml`` ships as a blank template for adding
    a system and is not an evaluation.
    """
    return list(taxonomy.get("operating_systems") or {})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Mechanism:
    """One mechanism's evaluation for one system."""

    id: str
    category: str
    status: str
    P: int | None  # None = not applicable
    D: int
    S: int
    A: int
    T: int
    dependencies: tuple[str, ...]


def _int0(value: int | None) -> int:
    """Coerce a score cell to int, treating a missing value as 0."""
    return 0 if value is None else int(value)


def _derive_status(tax_data: Mapping, eval_data: Mapping | None) -> str:
    """Re-derive the row's status from the published fields.

    The published data set drops the per-mechanism workflow ``status`` with
    one exception: an explicit ``xref`` marker survives, because it is not
    derivable from the scores. A cross-reference row carries zeros that would
    otherwise read as a scored, genuinely absent (P=0) mechanism.
    """
    if eval_data is None:
        return "xref" if tax_data.get("xref_target") else "na"
    if eval_data.get("status") == "xref":
        return "xref"
    if eval_data.get("P") is None:
        return "na"
    return "scored"


def build_mechanisms(taxonomy: Mapping, evaluation: Mapping) -> list[Mechanism]:
    """Join the taxonomy with one system's evaluation.

    Two fields are re-derived here because the published projection does not
    carry them: ``status`` (see _derive_status) and ``T = min(T_age,
    T_maintained)`` -- maturity is the weaker of "how long has this existed"
    and "is it still maintained".
    """
    eval_mechs = evaluation.get("mechanisms") or {}
    mechanisms = []
    for mech_id, tax_data in taxonomy["mechanisms"].items():
        eval_data = eval_mechs.get(mech_id)
        status = _derive_status(tax_data, eval_data)
        row: Mapping = eval_data or {}

        mechanisms.append(
            Mechanism(
                id=mech_id,
                category=tax_data["category"],
                status=status,
                P=None if status == "na" else _int0(row.get("P")),
                D=_int0(row.get("D")),
                S=_int0(row.get("S")),
                A=_int0(row.get("A")),
                T=min(_int0(row.get("T_age")), _int0(row.get("T_maintained"))),
                dependencies=tuple(tax_data.get("dependencies") or ()),
            )
        )
    return mechanisms


# ---------------------------------------------------------------------------
# Arithmetic primitives
#
# The published values are produced by a specific rounding and summation
# order. Reproducing them is the point of this file, so neither is incidental:
# see the Rounding order section of README.md.
# ---------------------------------------------------------------------------


def round2(x: float) -> float:
    return round(x, 2)


def round3(x: float) -> float:
    return round(x, 3)


def _sum_exact(values: Iterable[float]) -> float:
    """Neumaier compensated summation over floats.

    CPython's builtin ``sum()`` has used this algorithm for floats since 3.12,
    and the published numbers were produced with it. A plain accumulation loop
    is *not* equivalent -- it shifts, for instance, Linux's implemented
    quality from 2.02 to 2.03 under the default profile. Spelling the
    algorithm out keeps this script exact on older interpreters too.
    """
    total = 0.0
    compensation = 0.0
    for value in values:
        tentative = total + value
        if abs(total) >= abs(value):
            compensation += (total - tentative) + value
        else:
            compensation += (value - tentative) + total
        total = tentative
    return total + compensation


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def get_weights(
    taxonomy: Mapping, profile: str = DEFAULT_PROFILE
) -> tuple[float, float, float, float]:
    """Dimension weights (w_d, w_s, w_a, w_t) for a weight profile."""
    weights = taxonomy["dimension_weights"][profile]
    return (weights["w_d"], weights["w_s"], weights["w_a"], weights["w_t"])


def get_category_weights(
    taxonomy: Mapping, threat_model: str = DEFAULT_THREAT_MODEL
) -> dict[str, float]:
    """Category weights alpha_k for a deployment category."""
    return dict(taxonomy["category_weights"][threat_model])


def compute_effective_s(m: Mechanism, mech_map: Mapping[str, Mechanism]) -> int:
    """Dependency-capped Strength.

    A mechanism may be at most one strength level above its weakest hard
    prerequisite; an absent prerequisite (P=0, or S=0) caps it at S=1. The
    ``S`` in the data file stays the raw, mechanism-in-isolation assessment.

    A prerequisite that is N/A, a cross-reference or unscored is skipped
    rather than treated as absent: N/A means the prerequisite's threat surface
    does not exist on that system, so the property this mechanism relies on
    cannot be undermined.
    """
    if m.P != 1 or not m.dependencies:
        return m.S

    effective = m.S
    for dependency_id in m.dependencies:
        dependency = mech_map.get(dependency_id)
        if dependency is None or dependency.status not in SCORABLE_STATUSES:
            continue
        cap = 1 if (dependency.P != 1 or dependency.S == 0) else dependency.S + 1
        effective = min(effective, cap)
    return effective


def compute_hm(
    m: Mechanism,
    w_d: float,
    w_s: float,
    w_a: float,
    w_t: float,
    effective_s: int | None = None,
) -> float:
    """H(M) for one mechanism, using raw S or an explicitly supplied effective S."""
    presence = 0 if m.P is None else m.P
    strength = m.S if effective_s is None else effective_s
    return presence * (w_d * m.D + w_s * strength + w_a * m.A + w_t * m.T)


def compute_category(
    cat: str, mechs: Sequence[Mechanism], w: tuple[float, float, float, float]
) -> dict:
    """Aggregate H(C_k) over the scorable mechanisms of one category."""
    w_d, w_s, w_a, w_t = w
    mech_map = {m.id: m for m in mechs}
    scorable = [m for m in mechs if m.category == cat and m.status in SCORABLE_STATUSES]
    hm_values = [
        round2(compute_hm(m, w_d, w_s, w_a, w_t, compute_effective_s(m, mech_map)))
        for m in scorable
    ]
    count = len(scorable)
    cat_sum = round2(_sum_exact(hm_values))
    avg = round2(cat_sum / count) if count > 0 else 0.0
    return {"count": count, "sum": cat_sum, "avg": avg}


def category_has_applicable_surface(cat: str, mechs: Sequence[Mechanism]) -> bool:
    """Whether a category should keep its weight in H_total.

    A category leaves the normalization only when every independent mechanism
    in it is genuinely N/A on this system.
    """
    return any(m.category == cat and m.status not in {"na", "xref"} for m in mechs)


def get_effective_category_weights(
    taxonomy: Mapping,
    mechs: Sequence[Mechanism],
    threat_model: str = DEFAULT_THREAT_MODEL,
) -> dict[str, float]:
    """Category weights renormalized over the categories that apply here."""
    base_weights = get_category_weights(taxonomy, threat_model)
    applicable = [cat for cat in CATEGORIES if category_has_applicable_surface(cat, mechs)]
    denominator = _sum_exact(base_weights[cat] for cat in applicable)
    if denominator <= 0:
        return {cat: 0.0 for cat in CATEGORIES}
    # Every category applies: divide by nothing rather than by a float 1.0.
    if abs(denominator - 1.0) < 1e-12:
        return {cat: (base_weights[cat] if cat in applicable else 0.0) for cat in CATEGORIES}
    return {
        cat: (base_weights[cat] / denominator if cat in applicable else 0.0) for cat in CATEGORIES
    }


def compute_htotal_breakdown(
    taxonomy: Mapping,
    mechs: Sequence[Mechanism],
    profile: str = DEFAULT_PROFILE,
    threat_model: str = DEFAULT_THREAT_MODEL,
) -> dict:
    """H_total together with the per-category terms it is built from."""
    w = get_weights(taxonomy, profile)
    cat_weights = get_effective_category_weights(taxonomy, mechs, threat_model)
    per_category = {}
    weighted_terms = []
    for cat in CATEGORIES:
        data = compute_category(cat, mechs, w)
        alpha = cat_weights[cat]
        weighted = round3(alpha * data["avg"])
        per_category[cat] = dict(data, alpha=alpha, weighted=weighted)
        weighted_terms.append(weighted)
    return {"htotal": round2(_sum_exact(weighted_terms)), "categories": per_category}


def compute_htotal(
    taxonomy: Mapping,
    mechs: Sequence[Mechanism],
    profile: str = DEFAULT_PROFILE,
    threat_model: str = DEFAULT_THREAT_MODEL,
) -> float:
    """The composite hardening score for one system."""
    return compute_htotal_breakdown(taxonomy, mechs, profile, threat_model)["htotal"]


def compute_implemented_quality(
    taxonomy: Mapping,
    mechs: Sequence[Mechanism],
    profile: str = DEFAULT_PROFILE,
    threat_model: str = DEFAULT_THREAT_MODEL,
) -> float:
    """Category-weighted H(M) over implemented mechanisms only.

    Diagnostic rather than a second ranking: each category average excludes
    P=0 rows and the weights are renormalized over the categories that have at
    least one present mechanism. It answers "how good is what is there",
    independently of how much of the taxonomy is covered.

    Note the averaging differs from compute_category on purpose: there is no
    intermediate rounding of the sum here.
    """
    w_d, w_s, w_a, w_t = get_weights(taxonomy, profile)
    base_weights = get_category_weights(taxonomy, threat_model)
    mech_map = {m.id: m for m in mechs}
    present_by_category = {
        cat: [m for m in mechs if m.category == cat and m.status in SCORABLE_STATUSES and m.P == 1]
        for cat in CATEGORIES
    }
    represented = [cat for cat in CATEGORIES if present_by_category[cat]]
    denominator = _sum_exact(base_weights[cat] for cat in represented)
    if denominator <= 0:
        return 0.0

    weighted_terms = []
    for cat in represented:
        values = [
            round2(compute_hm(m, w_d, w_s, w_a, w_t, compute_effective_s(m, mech_map)))
            for m in present_by_category[cat]
        ]
        average = round2(_sum_exact(values) / len(values))
        weighted_terms.append(round3(base_weights[cat] / denominator * average))
    return round2(_sum_exact(weighted_terms))


def compute_derived_metrics(
    taxonomy: Mapping,
    mechs: Sequence[Mechanism],
    profile: str = DEFAULT_PROFILE,
    threat_model: str = DEFAULT_THREAT_MODEL,
) -> dict:
    """Breadth and implemented-mechanism diagnostics for one system."""
    scorable = [m for m in mechs if m.status in SCORABLE_STATUSES]
    mech_map = {m.id: m for m in mechs}
    n = len(scorable)
    present = sum(1 for m in scorable if m.P == 1)
    default_on = sum(1 for m in scorable if m.P == 1 and m.D >= 2)
    # D=3 is "mandatory": the protection cannot be turned off.
    mandatory = sum(1 for m in scorable if m.P == 1 and m.D == 3)
    strength_sum = sum(compute_effective_s(m, mech_map) for m in scorable if m.P == 1)
    strength_max = 3 * n if n > 0 else 1
    absent = sum(1 for m in scorable if m.P == 0)
    na_count = sum(1 for m in mechs if m.status == "na")
    independent_total = sum(1 for m in mechs if m.status != "xref")
    return {
        "total_scored": n,
        "present": present,
        "default_on": default_on,
        "strength_sum": strength_sum,
        "strength_max": strength_max,
        "absent": absent,
        "coverage_pct": round(present / n * 100) if n > 0 else 0,
        "default_pct": round(default_on / n * 100) if n > 0 else 0,
        "mandatory": mandatory,
        "mandatory_pct": round(mandatory / n * 100) if n > 0 else 0,
        "default_among_present_pct": round(default_on / present * 100) if present > 0 else 0,
        "strength_pct": round(strength_sum / strength_max * 100) if strength_max > 0 else 0,
        "implemented_quality": compute_implemented_quality(taxonomy, mechs, profile, threat_model),
        "na_count": na_count,
        "na_pct": round(na_count / independent_total * 100) if independent_total > 0 else 0,
    }


# ---------------------------------------------------------------------------
# Whole-system convenience
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OsScores:
    """Everything this script computes for one system."""

    os_id: str
    mechanisms: list[Mechanism]
    per_category: dict
    htotal: float
    derived: dict
    per_mechanism_hm: dict
    per_mechanism_effective_s: dict


def compute_os_scores(
    taxonomy: Mapping,
    evaluation: Mapping,
    profile: str = DEFAULT_PROFILE,
    threat_model: str = DEFAULT_THREAT_MODEL,
) -> OsScores:
    """Compute everything for one system in a single call."""
    mechanisms = build_mechanisms(taxonomy, evaluation)
    w_d, w_s, w_a, w_t = get_weights(taxonomy, profile)
    breakdown = compute_htotal_breakdown(taxonomy, mechanisms, profile, threat_model)
    mech_map = {m.id: m for m in mechanisms}

    per_mechanism_hm = {}
    per_mechanism_effective_s = {}
    for m in mechanisms:
        effective_s = compute_effective_s(m, mech_map)
        per_mechanism_effective_s[m.id] = effective_s
        per_mechanism_hm[m.id] = (
            round2(compute_hm(m, w_d, w_s, w_a, w_t, effective_s))
            if m.status in SCORABLE_STATUSES
            else 0.0
        )

    return OsScores(
        os_id=evaluation.get("os", "?"),
        mechanisms=mechanisms,
        per_category=breakdown["categories"],
        htotal=breakdown["htotal"],
        derived=compute_derived_metrics(taxonomy, mechanisms, profile, threat_model),
        per_mechanism_hm=per_mechanism_hm,
        per_mechanism_effective_s=per_mechanism_effective_s,
    )


def htotal_pct(htotal: float) -> int:
    """H_total as a percentage of the maximum, computed from the rounded value."""
    return round(htotal / MAX_SCORE * 100)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _os_meta(taxonomy: Mapping, os_id: str) -> Mapping:
    return (taxonomy.get("operating_systems") or {}).get(os_id) or {}


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _rule(header: str) -> str:
    """An underline as wide as the header it follows."""
    return "  " + "-" * (len(header) - 2)


# Column widths shared by the per-system report, the ranking table and --list.
ID_W, NAME_W, VERSION_W = 9, 46, 26


def format_os_report(taxonomy: Mapping, scores: OsScores, profile: str, threat_model: str) -> str:
    """One system's full breakdown, as a text block."""
    meta = _os_meta(taxonomy, scores.os_id)
    tax_mechs = taxonomy["mechanisms"]
    name = meta.get("name", scores.os_id)
    version = meta.get("version", "")
    mech_header = (
        f"  {'id':<8} {'mechanism':<{NAME_W}} {'status':<6} "
        f"{'P D S A T':<9} {'S_eff':>5} {'H(M)':>7}"
    )
    lines = [
        f"{scores.os_id} -- {name} {version}".rstrip(),
        f"profile={profile}  deployment={threat_model}",
        "",
        mech_header,
        _rule(mech_header),
    ]
    for m in scores.mechanisms:
        label = _truncate(str(tax_mechs[m.id].get("name", "")), NAME_W)
        if m.status in SCORABLE_STATUSES:
            dims = f"{m.P or 0} {m.D} {m.S} {m.A} {m.T}"
            seff = str(scores.per_mechanism_effective_s[m.id])
            hm = f"{scores.per_mechanism_hm[m.id]:.2f}"
        else:
            dims, seff, hm = "- - - - -", "-", "-"
        lines.append(f"  {m.id:<8} {label:<{NAME_W}} {m.status:<6} {dims:<9} {seff:>5} {hm:>7}")

    cat_header = f"  {'cat':<4} {'n':>5} {'sum':>8} {'avg':>7} {'alpha':>8} {'weighted':>9}"
    lines += ["", cat_header, _rule(cat_header)]
    for cat in CATEGORIES:
        data = scores.per_category[cat]
        lines.append(
            f"  {cat:<4} {data['count']:>5} {data['sum']:>8.2f} "
            f"{data['avg']:>7.2f} {data['alpha']:>8.3f} {data['weighted']:>9.3f}"
        )

    d = scores.derived
    lines += [
        _rule(cat_header),
        f"  H_total = {scores.htotal:.2f}  ({htotal_pct(scores.htotal)}% of {MAX_SCORE:.2f})",
        "",
        f"  scored {d['total_scored']}   present {d['present']} ({d['coverage_pct']}%)"
        f"   N/A {d['na_count']} ({d['na_pct']}%)",
        f"  default-on {d['default_on']} ({d['default_pct']}%,"
        f" {d['default_among_present_pct']}% of present)"
        f"   mandatory {d['mandatory']} ({d['mandatory_pct']}%)",
        f"  strength {d['strength_sum']}/{d['strength_max']} ({d['strength_pct']}%)"
        f"   implemented quality {d['implemented_quality']:.2f}",
    ]
    return "\n".join(lines)


def format_ranking_table(
    taxonomy: Mapping, all_scores: Sequence[OsScores], profile: str, threat_model: str
) -> str:
    """Every system ranked by H_total, as a text table."""
    header = (
        f"  {'#':<3} {'system':<{ID_W}} {'version':<{VERSION_W}} "
        f"{'H_total':>8} {'%':>5} {'coverage':>9} {'quality':>8}"
    )
    lines = [f"profile={profile}  deployment={threat_model}", "", header, _rule(header)]
    for rank, scores in enumerate(sorted(all_scores, key=lambda s: -s.htotal), start=1):
        version = _truncate(str(_os_meta(taxonomy, scores.os_id).get("version", "")), VERSION_W)
        lines.append(
            f"  {rank:<3} {scores.os_id:<{ID_W}} {version:<{VERSION_W}} "
            f"{scores.htotal:>8.2f} {htotal_pct(scores.htotal):>4}% "
            f"{scores.derived['coverage_pct']:>8}% {scores.derived['implemented_quality']:>8.2f}"
        )
    return "\n".join(lines)


def format_os_list(taxonomy: Mapping, os_ids: Sequence[str]) -> str:
    """id, version and name, one system per line."""
    lines = []
    for os_id in os_ids:
        meta = _os_meta(taxonomy, os_id)
        version = _truncate(str(meta.get("version", "")), VERSION_W)
        lines.append(f"{os_id:<{ID_W}} {version:<{VERSION_W}} {meta.get('name', '')}".rstrip())
    return "\n".join(lines)


def to_json_obj(
    taxonomy: Mapping,
    all_scores: Sequence[OsScores],
    data_dir: Path,
    profile: str,
    threat_model: str,
) -> dict:
    """The same results as a JSON-serializable object."""
    systems = {}
    for scores in all_scores:
        meta = _os_meta(taxonomy, scores.os_id)
        systems[scores.os_id] = {
            "name": meta.get("name"),
            "version": meta.get("version"),
            "htotal": scores.htotal,
            "htotal_pct": htotal_pct(scores.htotal),
            "categories": scores.per_category,
            "derived": scores.derived,
            "mechanisms": {
                m.id: {
                    "status": m.status,
                    "P": m.P,
                    "D": m.D,
                    "S": m.S,
                    "S_eff": scores.per_mechanism_effective_s[m.id],
                    "A": m.A,
                    "T": m.T,
                    "HM": scores.per_mechanism_hm[m.id],
                }
                for m in scores.mechanisms
            },
        }
    return {
        "meta": {
            "data_dir": str(data_dir),
            "evaluation_review_date": str(taxonomy.get("evaluation_review_date", "")),
            "profile": profile,
            "threat_model": threat_model,
            "dimension_weights": dict(taxonomy["dimension_weights"][profile]),
            "category_weights": get_category_weights(taxonomy, threat_model),
            "mechanism_count": len(taxonomy["mechanisms"]),
        },
        "systems": systems,
    }


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recompute the published OS kernel hardening scores.",
        epilog="With no system named, prints the cross-system ranking table.",
    )
    parser.add_argument(
        "os_ids", nargs="*", metavar="OS", help="systems to report on (default: all of them)"
    )
    parser.add_argument("--data-dir", help="directory holding taxonomy.yaml (default: ../data)")
    parser.add_argument("--list", action="store_true", help="list the systems and exit")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--profile", choices=PROFILES, default=DEFAULT_PROFILE)
    parser.add_argument("--threat-model", choices=THREAT_MODELS, default=DEFAULT_THREAT_MODEL)
    args = parser.parse_args(argv)

    data_dir = resolve_data_dir(args.data_dir)
    taxonomy = load_taxonomy(data_dir)
    known = available_os_ids(taxonomy)

    if args.list:
        print(format_os_list(taxonomy, known))
        return 0

    unknown = [os_id for os_id in args.os_ids if os_id not in known]
    if unknown:
        parser.error(f"unknown system(s): {', '.join(unknown)}; known: {', '.join(known)}")

    # Naming systems asks for their full breakdown; naming none ranks them all.
    selected = args.os_ids or known
    all_scores = [
        compute_os_scores(
            taxonomy, load_evaluation(data_dir, os_id), args.profile, args.threat_model
        )
        for os_id in selected
    ]

    if args.json:
        payload = to_json_obj(taxonomy, all_scores, data_dir, args.profile, args.threat_model)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif args.os_ids:
        print(
            "\n\n".join(
                format_os_report(taxonomy, scores, args.profile, args.threat_model)
                for scores in all_scores
            )
        )
    else:
        print(format_ranking_table(taxonomy, all_scores, args.profile, args.threat_model))
    return 0


if __name__ == "__main__":
    sys.exit(main())
