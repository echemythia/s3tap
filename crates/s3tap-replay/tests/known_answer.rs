use s3tap_replay::driver::run;
use s3tap_replay::predict::{FrequencyPredictor, MarkovPredictor, NullPredictor};
use s3tap_replay::synth::{cyclic_matrix, markov, uniform_random, zipf};

/// On a near-cyclic Markov trace, the Markov predictor must clearly beat the
/// reactive floor — it should be *learning* the sequence.
#[test]
fn markov_beats_floor_on_markov_trace() {
    let m = cyclic_matrix(20, 0.9);
    let trace = markov(&m, 20_000, 1);
    let cap = 5; // small: floor can't hold the working set; prefetch must earn hits

    let floor = run(&trace, &mut NullPredictor, cap).hit_rate();
    let mk = run(&trace, &mut MarkovPredictor::new(1), cap).hit_rate();

    assert!(mk > floor + 0.20, "markov={mk:.3} floor={floor:.3}");
}

/// On uniform-random access there is NO structure; every predictor must collapse
/// to ~the floor. If a predictor scores meaningfully above the floor here, it is
/// leaking future information — a bug.
#[test]
fn nothing_beats_floor_on_random_trace() {
    let trace = uniform_random(50, 20_000, 7);
    let cap = 10;

    let floor = run(&trace, &mut NullPredictor, cap).hit_rate();
    let mk = run(&trace, &mut MarkovPredictor::new(3), cap).hit_rate();
    let freq = run(&trace, &mut FrequencyPredictor::new(3), cap).hit_rate();

    assert!((mk - floor).abs() < 0.05, "markov={mk:.3} floor={floor:.3}");
    assert!((freq - floor).abs() < 0.05, "freq={freq:.3} floor={floor:.3}");
}

/// On a Zipf popularity trace at a capacity too small for the tail, frequency
/// prefetching (keep the hot set warm) should beat the reactive floor.
#[test]
fn frequency_beats_floor_on_zipf_trace() {
    let trace = zipf(1000, 1.1, 40_000, 3);
    let cap = 20;

    let floor = run(&trace, &mut NullPredictor, cap).hit_rate();
    // k = 20 = cap is intentional here: it probes the hot-set ceiling in
    // isolation (pin the top-20). This differs from the sweep's deliberately
    // gentle k = cap/4 comparability policy — this test doesn't call sweep.
    let freq = run(&trace, &mut FrequencyPredictor::new(20), cap).hit_rate();

    assert!(freq > floor + 0.05, "freq={freq:.3} floor={floor:.3}");
}
