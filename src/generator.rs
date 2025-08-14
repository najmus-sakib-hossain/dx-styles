use crate::engine::StyleEngine;
use crate::interner::ClassInterner;
use std::sync::Arc;
use lightningcss::stylesheet::{ParserOptions, PrinterOptions, StyleSheet};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Write, BufWriter};
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
        crate::utils::write_buffered(output_path, b"").expect("Failed to write empty CSS file");
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
        crate::utils::write_buffered(output_path, minified_css.code.as_bytes())
            .expect("Failed to write minified CSS");
    } else {
        crate::utils::write_buffered(output_path, css_content.as_bytes()).expect("Failed to write CSS file");
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
// Full generation (sorted) with optional formatting in non-production environments.
// When force_format is true we still run through lightningcss's parser/printer even if not minifying
// to achieve deterministic canonical formatting (used for initial scan to avoid diff churn).
pub fn generate_css_ids(
    class_ids: &HashSet<u32>,
    output_path: &Path,
    engine: &StyleEngine,
    interner: &ClassInterner,
    force_format: bool,
) {
    let mut sorted: Vec<u32> = class_ids.iter().cloned().collect();
    sorted.sort_unstable();
    let css_rules: Vec<Arc<String>> = engine.generate_css_for_ids(&sorted, interner);

    if css_rules.is_empty() {
        crate::utils::write_buffered(output_path, b"").expect("Failed to write empty CSS file");
        return;
    }

    let is_production = std::env::var("DX_ENV").map_or(false, |v| v == "production");
    let joined = css_rules.iter().map(|a| a.as_str()).collect::<Vec<_>>().join("\n\n");

    if is_production {
        // Production path: minify.
        let stylesheet = StyleSheet::parse(&joined, ParserOptions::default()).expect("Failed to parse CSS");
        let minified_css = stylesheet
            .to_css(PrinterOptions { minify: true, ..Default::default() })
            .expect("Failed to minify CSS");
        let mut with_trailing = minified_css.code;
        if !with_trailing.ends_with('\n') { with_trailing.push('\n'); }
        with_trailing.push('\n');
        crate::utils::write_buffered(output_path, with_trailing.as_bytes()).expect("Failed to write minified CSS");
        return;
    }

    if force_format {
        // Parse & re-print without minification for deterministic formatting.
        if let Ok(stylesheet) = StyleSheet::parse(&joined, ParserOptions::default()) {
            if let Ok(formatted) = stylesheet.to_css(PrinterOptions { minify: false, ..Default::default() }) {
                let mut code = formatted.code;
                if !code.ends_with('\n') { code.push('\n'); }
                crate::utils::write_buffered(output_path, code.as_bytes()).expect("Failed to write formatted CSS");
                return;
            }
        }
        // Fallback to raw write if parse/print fails.
    }

    // Default dev path: stream original rule order (already sorted) to disk.
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)
        .expect("Failed to open CSS file for writing");
    let mut writer = BufWriter::new(file);
    for (i, rule) in css_rules.iter().enumerate() {
        if i > 0 { writer.write_all(b"\n\n").expect("write separator"); }
        writer.write_all(rule.as_bytes()).expect("write rule");
    }
    writer.write_all(b"\n").expect("write trailing newline");
    writer.flush().expect("Failed to flush CSS writer");
}

pub fn append_new_classes_ids(
    new_ids: &[u32],
    output_path: &Path,
    engine: &StyleEngine,
    interner: &ClassInterner,
) {
    if new_ids.is_empty() { return; }
    let rules: Vec<Arc<String>> = engine.generate_css_for_ids(new_ids, interner);
    if rules.is_empty() { return; }
    let file = OpenOptions::new().create(true).append(true).open(output_path).expect("open css append");
    let mut writer = BufWriter::new(file);
    // Determine if we need to put separators before first appended rule
    let need_leading = writer.get_ref().metadata().map(|m| m.len() > 0).unwrap_or(false);
    if need_leading {
        writer.write_all(b"\n\n").expect("write leading separators");
    }
    for (i, r) in rules.iter().enumerate() {
        if i > 0 { writer.write_all(b"\n\n").expect("write separator"); }
        writer.write_all(r.as_bytes()).expect("write rule");
    }
    // Ensure trailing blank line (two newlines at EOF). We always add even if one existed.
    writer.write_all(b"\n\n").expect("write trailing blank line");
    writer.flush().expect("flush append");
}

