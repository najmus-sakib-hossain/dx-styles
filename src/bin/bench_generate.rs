use dx::StyleEngine;
use dx::ClassInterner;
use std::time::Instant;

fn main() {
    println!("bench: starting");
    // Attempt to construct engine; tests may run without .dx/styles.bin present, so bail gracefully.
    println!("bench: constructing StyleEngine...");
    let engine = match StyleEngine::new() {
        Ok(e) => e,
        Err(err) => { println!("StyleEngine::new() failed: {} - exiting benchmark.", err); return; }
    };
    println!("bench: engine constructed");

    let mut interner = ClassInterner::new();
    // Create 100 class names with some prefixes
    let mut ids = Vec::new();
    for i in 0..1000 {
        let cn = format!("sm:btn-{}", i);
        ids.push(interner.intern(&cn));
    }

    // Prewarm engine rules for all interned names.
    engine.prewarm(&interner);

    // Warm up cache
    let _ = engine.generate_css_for_ids(&ids, &interner);

    // Benchmark repeated calls
    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = engine.generate_css_for_ids(&ids, &interner);
    }
    let dur = start.elapsed();
    let per_call = dur.as_secs_f64() / iterations as f64;
    println!("Total: {:?} for {} iterations, avg = {} us", dur, iterations, per_call * 1_000_000.0);
}
