use crate::rng::Rng;
use crate::trace::{NormEvent, Op};

// NOTE: all public generators below require the object count `n > 0`; they panic
// on `n == 0` (`zipf`/`uniform_random` divide by / index on `n`). Callers/tests
// always pass n > 0; this is a test fixture generator, not production input.

fn ev(ts: u64, id: usize) -> NormEvent {
    NormEvent {
        ts_ns: ts,
        op: Op::Get,
        object_id: format!("obj-{id}"),
        range: None,
        size: Some(1),
        version: None,
        status: Some(200),
    }
}

/// `passes` sequential scans over `n` objects, 0..n repeated. Highest possible
/// predictability for a sequence model.
pub fn sequential(n: usize, passes: usize) -> Vec<NormEvent> {
    let mut out = Vec::with_capacity(n * passes);
    let mut ts = 0;
    for _ in 0..passes {
        for i in 0..n {
            out.push(ev(ts, i));
            ts += 1;
        }
    }
    out
}

/// Zipf-distributed popularity over `n` objects with exponent `alpha`.
pub fn zipf(n: usize, alpha: f64, accesses: usize, seed: u64) -> Vec<NormEvent> {
    // Precompute cumulative weights w_k = 1 / k^alpha, k = 1..=n.
    let mut cum = Vec::with_capacity(n);
    let mut sum = 0.0;
    for k in 1..=n {
        sum += 1.0 / (k as f64).powf(alpha);
        cum.push(sum);
    }
    let mut r = Rng::new(seed);
    let mut out = Vec::with_capacity(accesses);
    for ts in 0..accesses {
        let target = r.next_f64() * sum;
        // linear scan is fine for a generator; ids are 0-based (rank-1).
        let idx = cum.iter().position(|&c| c >= target).unwrap_or(n - 1);
        out.push(ev(ts as u64, idx));
    }
    out
}

/// Build a near-cyclic transition matrix: state i -> i+1 (mod n) with prob `p`,
/// remaining `1-p` spread uniformly over all states.
pub fn cyclic_matrix(n: usize, p: f64) -> Vec<Vec<f64>> {
    let mut m = vec![vec![(1.0 - p) / n as f64; n]; n];
    for i in 0..n {
        m[i][(i + 1) % n] += p;
    }
    m
}

/// Walk a Markov chain defined by `matrix` (row-stochastic) for `accesses` steps.
pub fn markov(matrix: &[Vec<f64>], accesses: usize, seed: u64) -> Vec<NormEvent> {
    let n = matrix.len();
    let mut r = Rng::new(seed);
    let mut state = 0usize;
    let mut out = Vec::with_capacity(accesses);
    for ts in 0..accesses {
        out.push(ev(ts as u64, state));
        let roll = r.next_f64();
        let mut acc = 0.0;
        let mut next = n - 1;
        for (j, &prob) in matrix[state].iter().enumerate() {
            acc += prob;
            if roll < acc {
                next = j;
                break;
            }
        }
        state = next;
    }
    out
}

/// Uniform-random access — the adversarial floor. No predictor should beat LRU.
pub fn uniform_random(n: usize, accesses: usize, seed: u64) -> Vec<NormEvent> {
    let mut r = Rng::new(seed);
    (0..accesses)
        .map(|ts| ev(ts as u64, r.below(n as u64) as usize))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::Op;

    #[test]
    fn sequential_walks_objects_in_order() {
        let t = sequential(5, 3); // 5 objects, 3 passes
        assert_eq!(t.len(), 15);
        assert!(t.iter().all(|e| e.op == Op::Get));
        assert_eq!(t[0].object_id, "obj-0");
        assert_eq!(t[1].object_id, "obj-1");
        assert_eq!(t[5].object_id, "obj-0"); // second pass wraps
    }

    #[test]
    fn zipf_is_skewed_toward_low_ids() {
        let t = zipf(100, 1.0, 10_000, 42);
        assert_eq!(t.len(), 10_000);
        let count0 = t.iter().filter(|e| e.object_id == "obj-0").count();
        let count99 = t.iter().filter(|e| e.object_id == "obj-99").count();
        assert!(count0 > count99 * 3, "obj-0={count0} obj-99={count99}");
    }

    #[test]
    fn markov_is_deterministic_for_a_seed() {
        // near-cyclic chain: state i -> i+1 with prob 0.9, else random
        let m = cyclic_matrix(6, 0.9);
        let a = markov(&m, 500, 1);
        let b = markov(&m, 500, 1);
        assert_eq!(a, b);
    }

    #[test]
    fn uniform_random_has_no_dominant_object() {
        let t = uniform_random(50, 10_000, 3);
        let c0 = t.iter().filter(|e| e.object_id == "obj-0").count();
        // ~200 expected; assert it's not wildly dominant
        assert!(c0 < 400, "obj-0 appeared {c0} times");
    }
}
