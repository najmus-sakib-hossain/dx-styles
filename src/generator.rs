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

    // Pre-pass: sanitize individual class selectors so lightningcss can parse them.
    out = sanitize_class_selectors(&out);

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

    // 4b. Inside @container blocks, expand grouped synthetic selectors
    // like .?@container>640px(bg-green-200\ text-green-900) -> .bg-green-200, .text-green-900
    out = expand_container_group_selectors(&out);

    // 5. Final sanity: attempt parse / re-print; if it fails, continue with current string.
    // Use a cloned copy to avoid borrow issues when replacing `out`.
    if let Ok(parsed) = lightningcss::stylesheet::StyleSheet::parse(&out.clone(), lightningcss::stylesheet::ParserOptions::default()) {
        if let Ok(res) = parsed.to_css(lightningcss::stylesheet::PrinterOptions::default()) {
            out = res.code;
        }
    }

    // 6. Remove orphan selector lines (e.g. stray `.dark` left after pruning its grouped block).
    out = remove_orphan_selectors(&out);
    out
}

// Expand selectors of the synthetic form .?@container>SIZE(token\ token2\ ... ) found inside an @container at-rule
// into a comma-delimited list of the inner tokens as standalone class selectors.
fn expand_container_group_selectors(input: &str) -> String {
    if !input.contains("?@container>") { return input.to_string(); }
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let sel_start = i;
            // Find first '(' or escaped \(
            let mut j = i + 1;
            let mut paren_pos: Option<usize> = None;
            while j < bytes.len() {
                if bytes[j] == b'(' { paren_pos = Some(j); break; }
                if bytes[j] == b'\\' && j + 1 < bytes.len() && bytes[j+1] == b'(' { paren_pos = Some(j); break; }
                if matches!(bytes[j], b'{' | b'\n') { break; }
                j += 1;
            }
            if let Some(p_pos) = paren_pos {
                // Raw or escaped open paren
                let escaped_paren = bytes[p_pos] == b'\\';
                let open_paren_idx = if escaped_paren { p_pos + 1 } else { p_pos }; // index of actual '('
                // Selector head substring
                let head = &input[sel_start..open_paren_idx];
                // Build a de-escaped copy for matching
                let mut marker = String::with_capacity(head.len());
                let mut chars = head.chars().peekable();
                while let Some(ch) = chars.next() {
                    if ch == '\\' { if let Some(nc) = chars.next() { marker.push(nc); } else { break; } } else { marker.push(ch); }
                }
                if marker.starts_with(".?@container>") {
                    // Scan for closing ) or \) balancing only depth 0 (no nesting expected)
                    let mut k = open_paren_idx + 1; // after '('
                    let mut close_idx: Option<usize> = None;
                    while k < bytes.len() {
                        if bytes[k] == b'\\' {
                            if k + 1 < bytes.len() {
                                if bytes[k + 1] == b')' { close_idx = Some(k + 1); break; }
                                k += 2; continue;
                            } else { break; }
                        }
                        if bytes[k] == b')' { close_idx = Some(k); break; }
                        if bytes[k] == b'{' || bytes[k] == b'\n' { break; }
                        k += 1;
                    }
                    if let Some(c_idx) = close_idx {
                        // Next non-space char after ) should be '{'
                        let mut after = c_idx + 1;
                        while after < bytes.len() && bytes[after].is_ascii_whitespace() { after += 1; }
                        if after < bytes.len() && bytes[after] == b'{' {
                            // Extract inner tokens between open_paren_idx+1 and c_idx
                            let inner = &input[open_paren_idx+1..c_idx];
                            // Tokens separated by escaped space sequences '\ '
                            let raw_tokens: Vec<&str> = if inner.contains("\\ ") {
                                inner.split("\\ ").filter(|t| !t.is_empty()).collect()
                            } else {
                                inner.split_whitespace().filter(|t| !t.is_empty()).collect()
                            };
                            if !raw_tokens.is_empty() {
                                out.push_str(&input[..sel_start]); // content up to selector
                                // Ensure we haven't duplicated earlier content
                                if sel_start > 0 { let already = out.len(); if already < sel_start { out.push_str(&input[out.len()..sel_start]); } }
                                let mut first = true;
                                for tok in raw_tokens {
                                    if !first { out.push_str(", "); } else { first = false; }
                                    // Remove remaining escape backslashes
                                    let mut cleaned = String::new();
                                    let mut tchars = tok.chars().peekable();
                                    while let Some(tc) = tchars.next() {
                                        if tc == '\\' { if let Some(&nc) = tchars.peek() { if nc == ' ' { tchars.next(); continue; } else { cleaned.push(nc); tchars.next(); continue; } } else { continue; } }
                                        cleaned.push(tc);
                                    }
                                    out.push('.');
                                    out.push_str(&cleaned);
                                }
                                out.push_str(" {");
                                // Advance i to after '{'
                                i = after + 1; // position after '{'
                                continue; // skip default copy for consumed slice
                            }
                        }
                    }
                }
            }
        }
        // Default copy path
        out.push(bytes[i] as char);
        i += 1;
    }
    if i < bytes.len() { out.push_str(&input[i..]); }
    out
}

// Insert missing CSS escapes for characters inside class selectors that are not valid ident chars.
// We purposefully do a lightweight single-pass scan rather than a heavy regex to avoid
// accidentally touching numeric literals (e.g. 1.5rem) or URLs.
// A class selector begins with '.' whose previous non-newline char is a selector delimiter
// (start / whitespace / combinator / comma / opening brace / another delimiter).
// We then read until a terminating delimiter for the simple selector.
fn sanitize_class_selectors(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut last_written = 0usize;
    let mut out = String::with_capacity(input.len());
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let prev = if i == 0 { b'\n' } else { bytes[i.saturating_sub(1)] };
            // Delimiters that allow a class selector start. Exclude ':' so we don't match pseudo classes after element names
            // but allow cases like space, combinators, newline, '{', ','.
            if matches!(prev, b'\n' | b' ' | b'\t' | b'{' | b'}' | b',' | b'>' | b'+' | b'~') {
                let start = i + 1; // after '.'
                let mut j = start;
                // Read ident segment (stop at selector / group delimiters)
                while j < bytes.len() {
                    let c = bytes[j];
                    if matches!(c, b' ' | b'\n' | b'\t' | b'{' | b'}' | b',' | b'>' | b'+' | b'~' | b':' | b'[') { break; }
                    // If escape, skip next char if any (already escaped)
                    if c == b'\\' { j += 1; if j < bytes.len() { j += 1; } else { break; } continue; }
                    j += 1;
                }
                if j > start { // we have a candidate ident
                    let ident = &input[start..j];
                    let mut needs_change = false;
                    let mut sanitized = String::with_capacity(ident.len() + 8);
                    let mut chars = ident.chars().peekable();
                    while let Some(ch) = chars.next() {
                        if ch == '\\' { // preserve existing escape and next char verbatim
                            sanitized.push(ch);
                            if let Some(nc) = chars.next() { sanitized.push(nc); }
                            continue;
                        }
                        let valid = matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_');
                        if !valid {
                            needs_change = true;
                            sanitized.push('\\');
                        }
                        sanitized.push(ch);
                    }
                    if needs_change {
                        out.push_str(&input[last_written..i+1]); // include the '.'
                        out.push_str(&sanitized);
                        last_written = j;
                    }
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    if last_written == 0 { return input.to_string(); }
    out.push_str(&input[last_written..]);
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

// Remove lines that are just a selector without an opening brace (likely left after earlier pruning).
fn remove_orphan_selectors(input: &str) -> String {
    let mut cleaned = String::with_capacity(input.len());
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('.') && !trimmed.contains('{') && !trimmed.is_empty() {
            // Skip orphan selector line
            continue;
        }
        cleaned.push_str(line);
        cleaned.push('\n');
    }
    cleaned
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_orphan_dark_selector() {
        let input = ".font-bold { font-weight:700; }\n.dark \n.other{a:b;}";
        let out = normalize_generated_css(input);
        assert!(!out.contains("\n.dark\n"), "orphan .dark selector should be removed: {out}");
    }

    #[test]
    fn removes_hashed_block() {
        let input = ".dx-class-12345678{color:red;}\n.ok{a:b;}";
        let out = normalize_generated_css(input);
        assert!(!out.contains("dx-class-12345678"));
        assert!(out.contains(".ok"));
    }

    #[test]
    fn removes_top_level_container_rule() {
        let input = ".?@container>640px(foo){color:red;}\n@container (min-width:640px){.?@container>640px(foo){color:blue;}}";
        let out = normalize_generated_css(input);
        // Should keep only the nested one
        assert!(out.contains("@container"));
        // Top-level occurrence should be gone
        let first_idx = out.find(".?@container>640px(foo)");
        let nested_idx = out.rfind(".?@container>640px(foo)");
        assert_eq!(first_idx, nested_idx, "only nested container rule should remain: {out}");
    }

    #[test]
    fn sanitizes_invalid_selector_chars() {
        // Contains parentheses inside the class name which must be escaped already; ensure we don't double escape
        let input = ".foo(bar){color:red;}\n.font-bold{font-weight:700;}";
        let out = normalize_generated_css(input);
        // lightningcss should parse sanitized output
        assert!(StyleSheet::parse(&out, ParserOptions::default()).is_ok(), "sanitized CSS failed to parse: {out}");
    }

    #[test]
    fn expands_container_group_selectors() {
        let input = "@container (min-width:640px){.?@container>640px(foo\\ bar\\ baz){color:red;}}";
        let out = normalize_generated_css(input);
        // Expect replacement selectors .foo, .bar, .baz
        assert!(out.contains(".foo, .bar, .baz"), "expected expanded selectors, got: {out}");
        assert!(!out.contains(".?@container>640px"), "synthetic selector should be removed: {out}");
        assert!(StyleSheet::parse(&out, ParserOptions::default()).is_ok(), "expanded CSS not parseable: {out}");
    }
}
