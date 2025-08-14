use dx::StyleEngine;
use dx::ClassInterner;
use std::time::Instant;

fn main() {
    // Attempt to construct engine; tests may run without .dx/styles.bin present, so bail gracefully.
    let engine = match StyleEngine::new() {
        Ok(e) => e,
        Err(_) => { println!("StyleEngine::new() failed - ensure .dx/styles.bin exists for accurate benchmark. Exiting."); return; }
    };

    let mut interner = ClassInterner::new();
    // Create 100 class names with some prefixes
    let mut ids = Vec::new();
    for i in 0..100 {
        let cn = format!("sm:btn-{}", i);
        ids.push(interner.intern(&cn));
    }

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
