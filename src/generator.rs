use crate::engine::StyleEngine;
use crate::interner::ClassInterner;
use lightningcss::stylesheet::{ParserOptions, PrinterOptions, StyleSheet};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[allow(dead_code)] // Legacy string-based generation; superseded by generate_css_ids
pub fn generate_css(
    class_names: &HashSet<String>,
    output_path: &Path,
    engine: &StyleEngine,
    _file_classnames: &HashMap<PathBuf, HashSet<String>>,
) {
    let is_production = std::env::var("DX_ENV").map_or(false, |v| v == "production");

    let mut sorted_class_names: Vec<_> = class_names.iter().collect();
    sorted_class_names.sort_unstable();

    // Convert once to &str slice for batch generation. We still keep rayon parallelism
    // but operate in chunks to reduce overhead for very large sets.
    let css_rules: Vec<String> = if sorted_class_names.len() < 512 {
        let refs: Vec<&str> = sorted_class_names.iter().map(|s| s.as_str()).collect();
        engine.generate_css_for_classes_batch(&refs)
    } else {
        // Chunk + parallel map; each chunk uses the batch API (double-lock strategy) to cut contention.
        const CHUNK: usize = 512;
        sorted_class_names
            .par_chunks(CHUNK)
            .flat_map_iter(|chunk| {
                let refs: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
                engine.generate_css_for_classes_batch(&refs)
            })
            .collect()
    };

    if css_rules.is_empty() {
        fs::write(output_path, "").expect("Failed to write empty CSS file");
        return;
    }

    let css_content = css_rules.join("\n\n");

    if is_production {
        let stylesheet =
            StyleSheet::parse(&css_content, ParserOptions::default()).expect("Failed to parse CSS");
        let minified_css = stylesheet
            .to_css(PrinterOptions {
                minify: true,
                ..Default::default()
            })
            .expect("Failed to minify CSS");
        fs::write(output_path, minified_css.code.as_bytes())
            .expect("Failed to write minified CSS");
    } else {
        fs::write(output_path, css_content).expect("Failed to write CSS file");
    }
}

// Extremely fast incremental appender: assumes only new classes (no removals) were added.
// Appends rules in insertion order (not globally sorted) for minimal work.
#[allow(dead_code)] // Legacy string-based incremental append; superseded by append_new_classes_ids
pub fn append_new_classes(
    new_classes: &[String],
    output_path: &Path,
    engine: &StyleEngine,
) {
    if new_classes.is_empty() {
        return;
    }
    // Build & compute in batch for cache efficiency.
    let refs: Vec<&str> = new_classes.iter().map(|s| s.as_str()).collect();
    let rules = engine.generate_css_for_classes_batch(&refs);
    if rules.is_empty() { return; }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(output_path)
        .expect("Failed to open CSS file for appending");
    let need_leading = file.metadata().map(|m| m.len() > 0).unwrap_or(false);
    // Estimate buffer size: average rule length + separators.
    let estimated: usize = rules.iter().map(|r| r.len() + 2).sum::<usize>() + 4;
    let mut buffer = String::with_capacity(estimated);
    if need_leading { buffer.push_str("\n\n"); }
    for (i, rule) in rules.iter().enumerate() {
        if i > 0 { buffer.push_str("\n\n"); }
        buffer.push_str(rule);
    }
    let _ = file.write_all(buffer.as_bytes());
}

// ID-based full generation (after migration complete)
pub fn generate_css_ids(
    class_ids: &HashSet<u32>,
    output_path: &Path,
    engine: &StyleEngine,
    interner: &ClassInterner,
) {
    let mut sorted: Vec<u32> = class_ids.iter().cloned().collect();
    sorted.sort_unstable();
    let css_rules = engine.generate_css_for_ids(&sorted, interner);
    let css_content = css_rules.join("\n\n");
    fs::write(output_path, css_content).expect("Failed to write CSS file");
}

pub fn append_new_classes_ids(
    new_ids: &[u32],
    output_path: &Path,
    engine: &StyleEngine,
    interner: &ClassInterner,
) {
    if new_ids.is_empty() { return; }
    let rules = engine.generate_css_for_ids(new_ids, interner);
    if rules.is_empty() { return; }
    use std::fs::OpenOptions; use std::io::Write;
    let mut file = OpenOptions::new().create(true).append(true).open(output_path).expect("open css append");
    let need_leading = file.metadata().map(|m| m.len()>0).unwrap_or(false);
    let mut buf = String::new();
    if need_leading { buf.push_str("\n\n"); }
    for (i,r) in rules.iter().enumerate() { if i>0 { buf.push_str("\n\n"); } buf.push_str(r); }
    let _ = file.write_all(buf.as_bytes());
}

