use crate::engine::StyleEngine;
use lightningcss::stylesheet::{ParserOptions, PrinterOptions, StyleSheet};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

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
    // Prepend double newline if file not empty
    let need_leading = file.metadata().map(|m| m.len() > 0).unwrap_or(false);
    if need_leading { writeln!(file).ok(); writeln!(file).ok(); }
    // Write joined with double newline to match full generation formatting.
    for (i, rule) in rules.iter().enumerate() {
        if i > 0 { writeln!(file).ok(); writeln!(file).ok(); }
        file.write_all(rule.as_bytes()).ok();
    }
}

