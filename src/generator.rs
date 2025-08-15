use crate::engine::StyleEngine;
use crate::interner::ClassInterner;
use lightningcss::stylesheet::{ParserOptions, PrinterOptions, StyleSheet};
use rayon::prelude::*;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// Post-generation normalization to prune or adjust unwanted blocks.
fn normalize_generated_css(css: &str) -> String {
    // Strategy: avoid broad DOTALL regex that can eat nested blocks and leave the CSS invalid.
    // We perform a few targeted, brace-balanced transforms.
    let mut out = css.to_string();

    // 1. Remove legacy hashed dx-class-* rules via balanced scan.
    out = remove_selector_blocks(&out, |sel| sel.starts_with(".dx-class-") && sel.len() >= 18);

    // 2. Remove base wrapper blocks for variant-only groups ( keep nested contextual versions like ".dark .dark\(").
    const VARIANTS: &[&str] = &[
        ".hover\\(", ".focus\\(", ".active\\(", ".focus-within\\(", ".focus-visible\\(", ".visited\\(",
        ".disabled\\(", ".checked\\(", ".group-hover\\(", ".group-focus\\(", ".group-active\\(",
        ".peer-hover\\(", ".peer-focus\\(", ".peer-active\\(", ".dark\\("
    ];
    out = remove_selector_blocks(&out, |sel| {
        // Only match if selector is single (no spaces) and exactly one of the variants.
        if sel.contains(' ') { return false; }
        VARIANTS.iter().any(|v| sel.starts_with(v))
    });

    // 3. Simplify local component groups ._name(...){ -> ._name { ... }
    if let Ok(re_local) = Regex::new(r"\._([a-zA-Z0-9_-]+)\\\([^{}]*?\\\)\s*\{") {
        out = re_local.replace_all(&out, |caps: &regex::Captures| format!("._{} {{", &caps[1])).into_owned();
    }

    // 4. Remove stray top-level conditional container group rules using existing structural scan.
    out = strip_top_level_container_rules(&out);

    // 5. Final sanity: attempt parse; if it fails, return original css (fail-safe) so we don't emit corrupt CSS.
    if let Ok(parsed) = lightningcss::stylesheet::StyleSheet::parse(&out, lightningcss::stylesheet::ParserOptions::default()) {
        // Re-print to normalize formatting lightly (non-minified path only).
        if let Ok(res) = parsed.to_css(lightningcss::stylesheet::PrinterOptions::default()) {
            return res.code;
        }
    }
    out
}

// Generic helper to remove complete selector blocks where predicate(selector) == true.
// Supports simple one-level blocks (it won't cross @media etc incorrectly because it balances braces).
fn remove_selector_blocks<F: Fn(&str) -> bool>(input: &str, predicate: F) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    while i < bytes.len() {
        if bytes[i] == b'.' { // potential class selector start
            let sel_start = i;
            // Read until '{' or newline / comma (we keep simple selectors only)
            while i < bytes.len() && bytes[i] != b'{' && bytes[i] != b'\n' { i += 1; }
            if i < bytes.len() && bytes[i] == b'{' {
                let selector = &input[sel_start..i].trim();
                if predicate(selector) {
                    // Skip balanced block
                    let mut depth = 0usize;
                    while i < bytes.len() {
                        if bytes[i] == b'{' { depth += 1; }
                        else if bytes[i] == b'}' {
                            depth -= 1; if depth == 0 { i += 1; break; }
                        }
                        i += 1;
                    }
                    // Skip trailing whitespace / newlines
                    while i < bytes.len() && (bytes[i] == b'\n' || bytes[i].is_ascii_whitespace()) { i += 1; }
                    continue; // don't copy removed block
                }
                // Not removed: copy selector + '{' and continue streaming rest by rewinding to sel_start logic
                // To keep code simple, fall through to generic copy below by resetting i to sel_start.
                i = sel_start; // reset for normal copy path
            } else {
                // newline or EOF, not a block; just fall through
                i = sel_start; // reset for normal copy path
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

// Remove rules beginning with .?@container... that occur outside any @container at-rule.
fn strip_top_level_container_rules(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut container_depth = 0usize; // depth of nested @container at-rules
    let mut result = String::with_capacity(input.len());
    while i < bytes.len() {
        // Detect @container to adjust depth when its block opens
        if bytes[i] == b'@' {
            if input[i..].starts_with("@container") {
                // copy '@container' and advance until '{'
                let start_i = i;
                while i < bytes.len() && bytes[i] != b'{' { i += 1; }
                if i < bytes.len() && bytes[i] == b'{' { container_depth += 1; i += 1; }
                // copy that segment
                result.push_str(&input[start_i..i]);
                continue;
            }
        }
        // Track closing brace for container depth
        if bytes[i] == b'}' {
            if container_depth > 0 { container_depth -= 1; }
            result.push('}');
            i += 1;
            continue;
        }
        // Potential start of a top-level conditional group rule
        if bytes[i] == b'.' && container_depth == 0 {
            // Check if next chars match '?@container'
            if input[i+1..].starts_with("?@container") {
                // Skip this entire rule block
                // Advance until first '{'
                while i < bytes.len() && bytes[i] != b'{' { i += 1; }
                if i < bytes.len() && bytes[i] == b'{' { i += 1; }
                let mut brace_depth = 1usize;
                while i < bytes.len() && brace_depth > 0 {
                    match bytes[i] { b'{' => brace_depth += 1, b'}' => brace_depth -= 1, _ => {} }
                    i += 1;
                }
                // Skip trailing whitespace/newlines
                while i < bytes.len() && (bytes[i] == b'\n' || bytes[i] == b'\r' || bytes[i].is_ascii_whitespace()) {
                    // Stop at next non-empty line start to avoid collapsing formatting too much
                    if bytes[i] == b'\n' { result.push('\n'); i += 1; break; } else { i += 1; }
                }
                continue;
            }
        }
        // Default: copy char
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

#[allow(dead_code)]
pub fn generate_css(
    class_names: &HashSet<String>,
    output_path: &Path,
    engine: &StyleEngine,
    _file_classnames: &HashMap<PathBuf, HashSet<String>>,
) {
    let is_production = std::env::var("DX_ENV").map_or(false, |v| v == "production");

    let mut sorted_class_names: Vec<_> = class_names.iter().collect();
    sorted_class_names.sort_unstable();

    let css_rules: Vec<String> = if sorted_class_names.len() < 512 {
        let refs: Vec<&str> = sorted_class_names.iter().map(|s| s.as_str()).collect();
        engine.generate_css_for_classes_batch(&refs)
    } else {
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
        let stylesheet = StyleSheet::parse(&css_content, ParserOptions::default()).expect("Failed to parse CSS");
        let minified_css = stylesheet
            .to_css(PrinterOptions { minify: true, ..Default::default() })
            .expect("Failed to minify CSS");
        let normalized = normalize_generated_css(&minified_css.code);
        crate::utils::write_buffered(output_path, normalized.as_bytes()).expect("Failed to write minified CSS");
    } else {
        let normalized = normalize_generated_css(&css_content);
        crate::utils::write_buffered(output_path, normalized.as_bytes()).expect("Failed to write CSS file");
    }
}

#[allow(dead_code)]
pub fn append_new_classes(
    new_classes: &[String],
    output_path: &Path,
    engine: &StyleEngine,
) {
    if new_classes.is_empty() { return; }
    let refs: Vec<&str> = new_classes.iter().map(|s| s.as_str()).collect();
    let rules = engine.generate_css_for_classes_batch(&refs);
    if rules.is_empty() { return; }
    let mut file = OpenOptions::new().create(true).append(true).open(output_path).expect("Failed to open CSS file for appending");
    let need_leading = file.metadata().map(|m| m.len() > 0).unwrap_or(false);
    let estimated: usize = rules.iter().map(|r| r.len() + 2).sum::<usize>() + 4;
    let mut buffer = String::with_capacity(estimated);
    if need_leading { buffer.push('\n'); }
    for (i, rule) in rules.iter().enumerate() {
        if i > 0 { buffer.push_str("\n\n"); }
        buffer.push_str(rule);
    }
    let _ = file.write_all(buffer.as_bytes());
}

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
        let stylesheet = StyleSheet::parse(&joined, ParserOptions::default()).expect("Failed to parse CSS");
        let minified_css = stylesheet
            .to_css(PrinterOptions { minify: true, ..Default::default() })
            .expect("Failed to minify CSS");
        let mut with_trailing = minified_css.code;
        if !with_trailing.ends_with('\n') { with_trailing.push('\n'); }
        with_trailing.push('\n');
        let normalized = normalize_generated_css(&with_trailing);
        crate::utils::write_buffered(output_path, normalized.as_bytes()).expect("Failed to write minified CSS");
        return;
    }

    if force_format {
        if let Ok(stylesheet) = StyleSheet::parse(&joined, ParserOptions::default()) {
            if let Ok(formatted) = stylesheet.to_css(PrinterOptions { minify: false, ..Default::default() }) {
                let mut code = formatted.code;
                if !code.ends_with('\n') { code.push('\n'); }
                let normalized = normalize_generated_css(&code);
                crate::utils::write_buffered(output_path, normalized.as_bytes()).expect("Failed to write formatted CSS");
                return;
            }
        }
    }

    let file = OpenOptions::new().create(true).write(true).truncate(true).open(output_path).expect("Failed to open CSS file for writing");
    let mut writer = BufWriter::new(file);
    for (i, rule) in css_rules.iter().enumerate() {
        if i > 0 { writer.write_all(b"\n\n").expect("write separator"); }
        let normalized = normalize_generated_css(rule);
        writer.write_all(normalized.as_bytes()).expect("write rule");
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
    let need_leading = writer.get_ref().metadata().map(|m| m.len() > 0).unwrap_or(false);
    if need_leading { writer.write_all(b"\n").expect("write leading separator"); }
    for (i, r) in rules.iter().enumerate() {
        if i > 0 { writer.write_all(b"\n\n").expect("write separator"); }
        writer.write_all(r.as_bytes()).expect("write rule");
    }
    writer.write_all(b"\n").expect("write trailing newline");
    writer.flush().expect("flush append");
}
