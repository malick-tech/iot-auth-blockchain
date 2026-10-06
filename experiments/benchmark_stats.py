"""Statistiques du benchmark, sans dépendance externe (bibliothèque standard seule).

Objectif : ne jamais conclure à une différence de latence « significative » sur la
seule base de deux moyennes. On fournit :

  - la médiane et son intervalle de confiance à 95 % (bootstrap percentile) ;
  - un test de Mann-Whitney U bilatéral (approximation normale avec correction des
    ex æquo), adapté aux distributions de latence asymétriques ;
  - une taille d'effet (corrélation bisériale par rangs) ;
  - la réduction relative de médiane entre deux scénarios, avec son IC bootstrap.

Les latences sont des séries temporelles potentiellement autocorrélées (JIT, GC,
cache) : le bootstrap ci-dessous suppose des observations échangeables. Le benchmark
atténue ce biais par un échauffement et un entrelacement des scénarios, mais ne
l'élimine pas ; cette limite doit figurer dans le chapitre 5.
"""

from __future__ import annotations

import math
import random
from statistics import median


def percentile(values: list[float], fraction: float) -> float:
    """Percentile par interpolation linéaire (méthode « type 7 », celle de NumPy)."""
    ordered = sorted(values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def bootstrap_median_ci(
    values: list[float], resamples: int = 2000, confidence: float = 0.95, seed: int = 12345
) -> tuple[float, float]:
    """IC bootstrap percentile de la médiane."""
    if len(values) < 2:
        v = values[0] if values else 0.0
        return v, v
    rng = random.Random(seed)
    n = len(values)
    medians = sorted(median(rng.choices(values, k=n)) for _ in range(resamples))
    alpha = (1 - confidence) / 2
    return percentile(medians, alpha), percentile(medians, 1 - alpha)


def _ranks_with_ties(pooled: list[float]) -> tuple[list[float], list[int]]:
    """Rangs moyens (1-indexés) et tailles des groupes d'ex æquo."""
    order = sorted(range(len(pooled)), key=lambda i: pooled[i])
    ranks = [0.0] * len(pooled)
    tie_sizes: list[int] = []
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and pooled[order[j + 1]] == pooled[order[i]]:
            j += 1
        average_rank = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = average_rank
        tie_sizes.append(j - i + 1)
        i = j + 1
    return ranks, tie_sizes


def mann_whitney_u(a: list[float], b: list[float]) -> dict:
    """Test de Mann-Whitney U bilatéral, approximation normale avec correction de continuité
    et correction des ex æquo. Fiable pour n1, n2 >= ~20.

    Retourne U (de l'échantillon a), la p-value bilatérale et la corrélation bisériale par
    rangs r = 2*U/(n1*n2) - 1 (r > 0 : a tend à être plus grand que b).
    """
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        raise ValueError("Échantillons vides")
    pooled = list(a) + list(b)
    ranks, tie_sizes = _ranks_with_ties(pooled)
    rank_sum_a = sum(ranks[:n1])
    u1 = rank_sum_a - n1 * (n1 + 1) / 2
    mean_u = n1 * n2 / 2
    n = n1 + n2
    tie_term = sum(t**3 - t for t in tie_sizes)
    variance = n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1)))
    if variance <= 0:
        return {"u": u1, "p_value": 1.0, "rank_biserial": 0.0}
    delta = u1 - mean_u
    # correction de continuité (0,5) vers la moyenne
    z = (abs(delta) - 0.5) / math.sqrt(variance)
    z = max(z, 0.0)
    p_value = math.erfc(z / math.sqrt(2))  # 2 * (1 - Phi(z))
    return {
        "u": u1,
        "p_value": min(1.0, p_value),
        "rank_biserial": 2 * u1 / (n1 * n2) - 1,
    }


def median_reduction_percent(
    fast: list[float], slow: list[float], resamples: int = 2000, confidence: float = 0.95, seed: int = 54321
) -> tuple[float, float, float]:
    """Réduction relative de la médiane : 100 * (1 - med(fast)/med(slow)).

    Retourne (estimation, borne basse, borne haute) de l'IC bootstrap (rééchantillonnage
    indépendant des deux séries).
    """
    point = 100 * (1 - median(fast) / median(slow))
    rng = random.Random(seed)
    nf, ns = len(fast), len(slow)
    estimates = []
    for _ in range(resamples):
        mf = median(rng.choices(fast, k=nf))
        ms = median(rng.choices(slow, k=ns))
        estimates.append(100 * (1 - mf / ms))
    estimates.sort()
    alpha = (1 - confidence) / 2
    return point, percentile(estimates, alpha), percentile(estimates, 1 - alpha)


def summarize(values: list[float]) -> dict:
    """Résumé descriptif d'une série de latences (ms)."""
    ci_low, ci_high = bootstrap_median_ci(values)
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1) if len(values) > 1 else 0.0
    return {
        "n": len(values),
        "mean_ms": round(mean, 3),
        "std_ms": round(math.sqrt(variance), 3),
        "median_ms": round(median(values), 3),
        "median_ci95_low_ms": round(ci_low, 3),
        "median_ci95_high_ms": round(ci_high, 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "min_ms": round(min(values), 3),
        "max_ms": round(max(values), 3),
    }
