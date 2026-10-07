"""Statistiques du benchmark, sans dépendance externe (bibliothèque standard seule).

Objectif : ne jamais conclure à une différence de latence « significative » sur la
seule base de deux moyennes. On fournit :

  - la médiane et son intervalle de confiance à 95 % (bootstrap percentile) ;
  - un test de Mann-Whitney U bilatéral (approximation normale avec correction des
    ex æquo), adapté aux distributions de latence asymétriques ;
  - une taille d'effet (corrélation bisériale par rangs) ;
  - la réduction relative de médiane entre deux scénarios, avec son IC bootstrap.

Les latences sont des séries temporelles autocorrélées (JIT, GC, cache) : un bootstrap
« à plat » sur les 1 000 observations suppose à tort qu'elles sont indépendantes et
donne des IC trop étroits. La v3 ajoute donc :

  - un bootstrap PAR BLOCS (les répétitions sont les unités rééchantillonnées) ;
  - un test de permutation par retournement de signe sur les médianes par répétition
    (les scénarios sont entrelacés : chaque répétition fournit une paire naturelle) ;
  - la correction de Holm pour les comparaisons multiples ;
  - l'autocorrélation d'ordre 1 et la taille d'échantillon effective.

Mann-Whitney sur observations brutes est conservé à titre descriptif (taille d'effet) ;
sa p-value ne doit pas être citée seule dans le chapitre 5.
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


def lag1_autocorrelation(values: list[float]) -> float:
    """Autocorrélation d'ordre 1 d'une série ordonnée dans le temps."""
    n = len(values)
    if n < 3:
        return 0.0
    mean = sum(values) / n
    denom = sum((v - mean) ** 2 for v in values)
    if denom == 0:
        return 0.0
    return sum((values[i] - mean) * (values[i + 1] - mean) for i in range(n - 1)) / denom


def effective_sample_size(values: list[float]) -> float:
    """n_eff = n (1 - r) / (1 + r) pour un AR(1) ; borné à [1, n]."""
    n = len(values)
    r = max(min(lag1_autocorrelation(values), 0.99), 0.0)
    return max(1.0, min(float(n), n * (1 - r) / (1 + r)))


def cluster_bootstrap_median_ci(
    groups: list[list[float]], resamples: int = 2000, confidence: float = 0.95, seed: int = 12345
) -> tuple[float, float]:
    """IC bootstrap de la médiane globale en rééchantillonnant les BLOCS (répétitions)."""
    groups = [g for g in groups if g]
    if len(groups) < 2:
        v = median(groups[0]) if groups else 0.0
        return v, v
    rng = random.Random(seed)
    k = len(groups)
    estimates = []
    for _ in range(resamples):
        pooled: list[float] = []
        for g in rng.choices(groups, k=k):
            pooled.extend(g)
        estimates.append(median(pooled))
    estimates.sort()
    alpha = (1 - confidence) / 2
    return percentile(estimates, alpha), percentile(estimates, 1 - alpha)


def paired_cluster_reduction_percent(
    fast_by_rep: dict[int, list[float]], slow_by_rep: dict[int, list[float]],
    resamples: int = 2000, confidence: float = 0.95, seed: int = 54321,
) -> tuple[float, float, float, int]:
    """Réduction relative de médiane 100 * (1 - med(fast)/med(slow)), IC par bootstrap de
    blocs APPARIÉS : une même répétition est tirée pour les deux scénarios.

    Retourne (estimation, borne basse, borne haute, nombre de répétitions appariées).
    """
    reps = sorted(set(fast_by_rep) & set(slow_by_rep))
    if len(reps) < 2:
        raise ValueError("Au moins 2 répétitions appariées sont nécessaires")
    flat_f = [v for r in reps for v in fast_by_rep[r]]
    flat_s = [v for r in reps for v in slow_by_rep[r]]
    point = 100 * (1 - median(flat_f) / median(flat_s))
    rng = random.Random(seed)
    estimates = []
    for _ in range(resamples):
        drawn = rng.choices(reps, k=len(reps))
        f = [v for r in drawn for v in fast_by_rep[r]]
        s = [v for r in drawn for v in slow_by_rep[r]]
        estimates.append(100 * (1 - median(f) / median(s)))
    estimates.sort()
    alpha = (1 - confidence) / 2
    return point, percentile(estimates, alpha), percentile(estimates, 1 - alpha), len(reps)


def paired_sign_flip_test(
    fast_by_rep: dict[int, list[float]], slow_by_rep: dict[int, list[float]],
    permutations: int = 20000, seed: int = 777,
) -> dict:
    """Test de permutation par retournement de signe sur d_r = med_slow(r) - med_fast(r).

    H0 : la distribution des différences par répétition est symétrique autour de 0.
    Exact (2^k) si k <= 16, sinon Monte-Carlo. Retourne la différence moyenne des médianes
    par répétition, la p-value bilatérale et le nombre de répétitions k.
    """
    reps = sorted(set(fast_by_rep) & set(slow_by_rep))
    diffs = [median(slow_by_rep[r]) - median(fast_by_rep[r]) for r in reps]
    k = len(diffs)
    if k < 2:
        raise ValueError("Au moins 2 répétitions appariées sont nécessaires")
    observed = abs(sum(diffs) / k)
    count = total = 0
    if k <= 16:
        for mask in range(1 << k):
            s = sum(d if (mask >> i) & 1 else -d for i, d in enumerate(diffs)) / k
            total += 1
            count += abs(s) >= observed - 1e-12
    else:
        rng = random.Random(seed)
        for _ in range(permutations):
            s = sum(d if rng.random() < 0.5 else -d for d in diffs) / k
            total += 1
            count += abs(s) >= observed - 1e-12
        count += 1
        total += 1  # estimateur sans biais de la p-value Monte-Carlo
    return {"mean_diff_ms": sum(diffs) / k, "p_value": count / total, "k": k,
            "n_positive": sum(d > 0 for d in diffs)}


def holm_adjust(p_values: list[float]) -> list[float]:
    """Correction de Holm-Bonferroni (p-values ajustées, ordre d'origine conservé)."""
    m = len(p_values)
    order = sorted(range(m), key=lambda i: p_values[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * p_values[i]))
        adjusted[i] = running
    return adjusted


def summarize(values: list[float], groups: list[list[float]] | None = None) -> dict:
    """Résumé descriptif d'une série de latences (ms), dans l'ordre temporel.

    Si `groups` (une liste de latences par répétition) est fourni, l'IC de la médiane
    est calculé par bootstrap de blocs ; l'IC « à plat » est conservé à titre indicatif.
    """
    flat_low, flat_high = bootstrap_median_ci(values)
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1) if len(values) > 1 else 0.0
    out = {
        "n": len(values),
        "mean_ms": round(mean, 3),
        "std_ms": round(math.sqrt(variance), 3),
        "median_ms": round(median(values), 3),
        "median_ci95_low_ms": round(flat_low, 3),
        "median_ci95_high_ms": round(flat_high, 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "min_ms": round(min(values), 3),
        "max_ms": round(max(values), 3),
        "lag1_autocorr": round(lag1_autocorrelation(values), 3),
        "n_effective": round(effective_sample_size(values), 1),
    }
    if groups and len([g for g in groups if g]) >= 2:
        lo, hi = cluster_bootstrap_median_ci(groups)
        out["median_block_ci95_low_ms"] = round(lo, 3)
        out["median_block_ci95_high_ms"] = round(hi, 3)
        out["n_blocks"] = len([g for g in groups if g])
    return out
