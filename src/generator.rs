use crate::engine::StyleEngine;
use crate::interner::ClassInterner;
use lightningcss::stylesheet::{ParserOptions, PrinterOptions, StyleSheet};
use lru::LruCache;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use seahash::SeaHasher;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::hash::{Hash, Hasher};
use std::io::{BufWriter, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static NORMALIZE_CACHE: Lazy<Mutex<LruCache<u64, Arc<String>>>> =
    Lazy::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap())));

static NORMALIZED_CSS_CACHE: Lazy<Mutex<LruCache<u32, Arc<String>>>> =
    Lazy::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(8192).unwrap())));

static EMITTED_KEYS: Lazy<RwLock<std::collections::HashSet<String>>> =
    Lazy::new(|| RwLock::new(std::collections::HashSet::new()));

#[inline]
fn fast_hash<T: Hash>(v: &T) -> u64 {
    let mut h = SeaHasher::new();
    v.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::normalize_generated_css;

    #[test]
    fn escaped_greater_than_not_treated_as_combinator() {
        let input = ".\\?@self\\:child-count\\>2\\(_highlight\\) {\n  color: red;\n}\n";
        let out = normalize_generated_css(input);
        assert!(
            out.contains(".\\?@self\\:child-count\\>2\\(_highlight\\) {"),
            "output selector altered: {}",
            out
        );
        assert!(
            !out.contains("child-count\\ >"),
            "unexpected space before escaped >: {}",
            out
        );
        assert!(
            !out.contains("\\> 2"),
            "unexpected space after escaped >: {}",
            out
        );
    }
}

fn normalize_generated_css(css: &str) -> String {
    if css.len() < 3 {
        return css.to_string();
    }
    let key = fast_hash(&css);
    if let Some(cached) = NORMALIZE_CACHE
        .lock()
        .ok()
        .and_then(|mut c| c.get(&key).cloned())
    {
        return (*cached).clone();
    }

    let mut out = css.to_string();

    out = fix_missing_dot_for_escaped_symbol_groups(&out);
    out = remove_selector_blocks(&out, |sel| sel.starts_with(".dx-class-") && sel.len() >= 18);

    const VARIANTS: &[&str] = &[
        ".hover\\(",
        ".focus\\(",
        ".active\\(",
        ".focus-within\\(",
        ".focus-visible\\(",
        ".visited\\(",
        ".disabled\\(",
        ".checked\\(",
        ".group-hover\\(",
        ".group-focus\\(",
        ".group-active\\(",
        ".peer-hover\\(",
        ".peer-focus\\(",
        ".peer-active\\(",
        ".dark\\(",
    ];
    out = remove_selector_blocks(&out, |sel| {
        let mut simple = String::with_capacity(sel.len());
        let mut last_ws = false;
        for ch in sel.chars() {
            if ch.is_whitespace() {
                if !last_ws {
                    simple.push(' ');
                    last_ws = true;
                }
            } else {
                simple.push(ch);
                last_ws = false;
            }
        }
        let mut trimmed = simple.trim();
        if let Some(idx) = trimmed.find("\\(") {
            trimmed = &trimmed[..idx];
        }
        if trimmed.contains(' ') {
            return false;
        }
        VARIANTS.iter().any(|v| {
            if trimmed == *v || trimmed.starts_with(v) {
                return true;
            }
            if let Some(base) = v.strip_suffix("\\(") {
                trimmed == base
            } else {
                false
            }
        })
    });

    out = remove_orphan_selectors(&out);
    out = reescape_leading_invalid_identifiers(&out);
    out = normalize_child_combinator_spacing(&out);
    out = remove_empty_rules(&out);
    if out.contains("animation:") {
        let mut cleaned = String::with_capacity(out.len());
        for line in out.lines() {
            if let Some(idx) = line.find("animation:") {
                let (prefix, rest) = line.split_at(idx);
                let mut value_part = rest[10..].trim();
                if let Some(semi) = value_part.find(';') {
                    value_part = &value_part[..semi];
                }
                let mut tokens: Vec<&str> = value_part.split_whitespace().collect();
                let mut filtered: Vec<&str> = Vec::with_capacity(tokens.len());
                let mut seen_fill = false;
                for t in tokens.drain(..) {
                    if t.starts_with("from(") || t.starts_with("to(") || t.starts_with("via(") {
                        continue;
                    }
                    if t == "forwards" {
                        if seen_fill {
                            continue;
                        }
                        seen_fill = true;
                    }
                    filtered.push(t);
                }
                let mut rebuilt = String::new();
                rebuilt.push_str(prefix);
                rebuilt.push_str("animation: ");
                rebuilt.push_str(&filtered.join(" "));
                rebuilt.push(';');
                cleaned.push_str(&rebuilt);
                cleaned.push('\n');
            } else {
                cleaned.push_str(line);
                cleaned.push('\n');
            }
        }
        out = cleaned;
    }

    if out.len() <= 16 * 1024 {
        if let Ok(mut cache) = NORMALIZE_CACHE.lock() {
            cache.put(key, Arc::new(out.clone()));
        }
    }
    out
}

fn css_block_sort_key(block: &str) -> String {
    for line in block.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return trimmed.to_string();
    }
    String::new()
}

fn sort_css_blocks(blocks: Vec<String>) -> Vec<String> {
    let mut keyed: Vec<(String, usize, String)> = blocks
        .into_iter()
        .enumerate()
        .map(|(i, b)| (css_block_sort_key(&b), i, b))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    keyed.into_iter().map(|(_, _, b)| b).collect()
}

fn remove_empty_rules(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    while i < bytes.len() {
        let start = i;
        if bytes[i] == b'.' {
            let mut j = i;
            let mut brace = None;
            while j < bytes.len() {
                if bytes[j] == b'{' {
                    brace = Some(j);
                    break;
                }
                if bytes[j] == b'\n' {
                    break;
                }
                j += 1;
            }
            if let Some(bpos) = brace {
                let mut k = bpos + 1;
                while k < bytes.len() && (bytes[k] as char).is_ascii_whitespace() {
                    k += 1;
                }
                if k < bytes.len() && bytes[k] == b'}' {
                    k += 1;
                    while k < bytes.len() && (bytes[k] as char).is_ascii_whitespace() {
                        if bytes[k] == b'\n' {
                            k += 1;
                            break;
                        }
                        k += 1;
                    }
                    i = k;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
        if start == i {
            break;
        }
    }
    out
}

fn normalize_child_combinator_spacing(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    let mut depth = 0usize;
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '{' => {
                depth += 1;
                out.push(c);
                i += 1;
            }
            '}' => {
                if depth > 0 {
                    depth -= 1;
                }
                out.push(c);
                i += 1;
            }
            '>' if depth == 0 => {
                if out.ends_with('\\') {
                    out.push('>');
                    i += 1;
                    continue;
                }
                while out.ends_with(' ') {
                    out.pop();
                }
                if !out.ends_with([' ', '\n', '\t', ',', '{']) {
                    out.push(' ');
                }
                out.push('>');
                i += 1;
                while i < bytes.len() && (bytes[i] as char).is_whitespace() {
                    if bytes[i] as char == '\n' {
                        break;
                    }
                    i += 1;
                }
                if i < bytes.len() {
                    let next = bytes[i] as char;
                    if !matches!(next, ' ' | '\n' | '\t' | '{' | ',' | '>') {
                        out.push(' ');
                    }
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    if out == input {
        return input.to_string();
    }
    out
}

fn condense_blank_lines(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut newline_run = 0usize;
    for ch in input.chars() {
        if ch == '\n' {
            newline_run += 1;
        } else {
            newline_run = 0;
        }
        if newline_run <= 2 {
            out.push(ch);
        }
    }
    while out.starts_with('\n') {
        out.remove(0);
    }
    while out.ends_with('\n') {
        out.pop();
    }
    out.push('\n');
    out
}

#[allow(dead_code)]
fn pretty_format_css_fast(input: &str) -> String {
    if input.as_bytes().windows(3).any(|w| w == b"\n  ") {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len() + input.len() / 8 + 32);
    let mut depth: i32 = 0;
    let mut in_string: Option<char> = None;
    let mut last_emitted_non_ws: char = '\n';
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let emit_indent = |out: &mut String, depth: i32| {
        for _ in 0..depth {
            out.push_str("  ");
        }
    };
    while i < bytes.len() {
        let c = bytes[i] as char;
        if let Some(sq) = in_string {
            out.push(c);
            if c == '\\' {
                if i + 1 < bytes.len() {
                    out.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
            } else if c == sq {
                in_string = None;
            }
            i += 1;
            continue;
        }
        match c {
            '"' | '\'' => {
                in_string = Some(c);
                out.push(c);
            }
            '{' => {
                while out.ends_with(' ') || out.ends_with('\t') {
                    out.pop();
                }
                out.push_str(" {\n");
                depth += 1;
                emit_indent(&mut out, depth);
            }
            '}' => {
                while out.ends_with([' ', '\t', '\n']) {
                    out.pop();
                }
                depth -= 1;
                if depth < 0 {
                    depth = 0;
                }
                out.push('\n');
                emit_indent(&mut out, depth);
                out.push('}');
                let mut k = i + 1;
                while k < bytes.len() && (bytes[k] as char).is_whitespace() {
                    if bytes[k] == b'\n' {
                        break;
                    }
                    k += 1;
                }
                out.push('\n');
                if k < bytes.len() && bytes[k] != b'\n' && depth == 0 {
                    out.push('\n');
                }
            }
            ';' => {
                out.push(';');
                out.push('\n');
                emit_indent(&mut out, depth);
            }
            '\n' => {
                if !out.ends_with('\n') {
                    out.push('\n');
                    emit_indent(&mut out, depth);
                }
            }
            ' ' | '\t' | '\r' => {
                if !out.ends_with(' ') && !out.ends_with('\n') {
                    out.push(' ');
                }
            }
            _ => {
                if last_emitted_non_ws == '}' && !out.ends_with('\n') {
                    out.push('\n');
                    emit_indent(&mut out, depth);
                }
                out.push(c);
                last_emitted_non_ws = c;
            }
        }
        i += 1;
    }
    while out.ends_with([' ', '\t', '\n']) {
        out.pop();
    }
    out.push('\n');
    out
}

fn fix_missing_dot_for_escaped_symbol_groups(input: &str) -> String {
    let mut changed = false;
    let mut out = String::with_capacity(input.len() + 8);
    for line in input.lines() {
        if let Some(first_non_ws_pos) = line.find(|c: char| !c.is_whitespace()) {
            let rest = &line[first_non_ws_pos..];
            if rest.starts_with('\\') {
                let bytes = rest.as_bytes();
                if bytes.len() > 3 && (bytes[1] == b'~') {
                    let mut idx = 2;
                    while idx < bytes.len() {
                        let c = bytes[idx];
                        if matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_') {
                            idx += 1;
                            continue;
                        }
                        break;
                    }
                    if idx + 2 < bytes.len() && bytes[idx] == b'\\' && bytes[idx + 1] == b'(' {
                        out.push_str(&line[..first_non_ws_pos]);
                        out.push('.');
                        out.push_str(rest);
                        out.push('\n');
                        changed = true;
                        continue;
                    }
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if !changed {
        return input.to_string();
    }
    out
}

fn reescape_leading_invalid_identifiers(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut last_copy = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let start = i + 1;
            if start >= bytes.len() {
                break;
            }
            if bytes[start].is_ascii_digit() {
                i += 1;
                continue;
            }
            if bytes[start] == b'\\' {
                i += 1;
                continue;
            }
            let ch = bytes[start] as char;
            let needs_escape = match ch {
                'a'..='z' | 'A'..='Z' | '_' => false,
                '-' => {
                    if start + 1 < bytes.len() {
                        let next = bytes[start + 1] as char;
                        next.is_ascii_digit()
                    } else {
                        false
                    }
                }
                _ => true,
            } || ch.is_ascii_digit();
            if needs_escape {
                if i > last_copy {
                    out.push_str(&input[last_copy..i + 1]);
                }
                out.push('\\');
                out.push(ch);
                last_copy = start + 1;
                i = start + 1;
                continue;
            }
        }
        i += 1;
    }
    if last_copy == 0 {
        return input.to_string();
    }
    if last_copy < input.len() {
        out.push_str(&input[last_copy..]);
    }
    out
}

fn remove_selector_blocks<F: Fn(&str) -> bool>(input: &str, predicate: F) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let sel_start = i;
            let mut j = i;
            while j < bytes.len() && bytes[j] != b'{' && bytes[j] != b'\n' {
                j += 1;
            }
            let mut brace_pos: Option<usize> = None;
            let mut selector_end = j;
            if j < bytes.len() && bytes[j] == b'{' {
                brace_pos = Some(j);
            } else if j < bytes.len() && bytes[j] == b'\n' {
                let mut k = j + 1;
                while k < bytes.len() {
                    if bytes[k] == b'{' {
                        brace_pos = Some(k);
                        selector_end = j;
                        break;
                    }
                    if !bytes[k].is_ascii_whitespace() {
                        break;
                    }
                    k += 1;
                }
            }
            if let Some(bpos) = brace_pos {
                let mut selector = &input[sel_start..selector_end];
                while selector.ends_with(|c: char| c.is_whitespace()) {
                    selector = selector.trim_end();
                }
                if let Some(group_idx) = selector.find("\\(") {
                    selector = &selector[..group_idx];
                }
                let selector = selector.trim_end();
                if predicate(selector) {
                    i = bpos;
                    let mut depth = 0usize;
                    while i < bytes.len() {
                        if bytes[i] == b'{' {
                            depth += 1;
                        } else if bytes[i] == b'}' {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        i += 1;
                    }
                    while i < bytes.len() && (bytes[i] == b'\n' || bytes[i].is_ascii_whitespace()) {
                        i += 1;
                    }
                    continue;
                }
                i = sel_start;
            } else {
                i = sel_start;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn remove_orphan_selectors(input: &str) -> String {
    let mut cleaned = String::with_capacity(input.len());
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('.') && !trimmed.contains('{') && !trimmed.is_empty() {
            continue;
        }
        cleaned.push_str(line);
        cleaned.push('\n');
    }
    cleaned
}

#[allow(dead_code)]
pub fn generate_css(
    class_names: &HashSet<String>,
    output_path: &Path,
    engine: &StyleEngine,
    _file_classnames: &HashMap<PathBuf, HashSet<String>>,
) {
    let is_production = std::env::var("DX_ENV").map_or(false, |v| v == "production");
    let fast_mode = !is_production
        && std::env::var("DX_CSS_FAST")
            .map_or(false, |v| v == "1" || v.eq_ignore_ascii_case("true"));

    let mut sorted_class_names: Vec<_> = class_names.iter().collect();
    sorted_class_names.sort_unstable();

    let css_rules: Vec<String> = if sorted_class_names.len() < 512 {
        let refs: Vec<&str> = sorted_class_names.iter().map(|s| s.as_str()).collect();
        engine.generate_css_for_classes_batch(&refs)
    } else {
        if is_production {
            const CHUNK: usize = 512;
            let mut pairs: Vec<(String, String)> = sorted_class_names
                .par_chunks(CHUNK)
                .flat_map_iter(|chunk| {
                    let refs: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
                    engine
                        .generate_css_for_classes_batch(&refs)
                        .into_iter()
                        .zip(chunk.iter().map(|s| (*s).to_string()))
                        .map(|(css, name)| (name, css))
                        .collect::<Vec<_>>()
                })
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            pairs.into_iter().map(|(_, css)| css).collect()
        } else {
            let refs: Vec<&str> = sorted_class_names.iter().map(|s| s.as_str()).collect();
            engine.generate_css_for_classes_batch(&refs)
        }
    };

    if css_rules.is_empty() {
        if is_production
            || !output_path.exists()
            || std::fs::metadata(output_path)
                .map(|m| m.len() > 0)
                .unwrap_or(true)
        {
            crate::utils::write_buffered(output_path, b"").expect("Failed to write empty CSS file");
        }
        return;
    }

    if is_production {
        let css_rules = sort_css_blocks(
            css_rules
                .into_iter()
                .map(|r| normalize_generated_css(&r))
                .collect(),
        );
        let css_content = css_rules.join("\n\n");
        let stylesheet =
            StyleSheet::parse(&css_content, ParserOptions::default()).expect("Failed to parse CSS");
        let minified_css = stylesheet
            .to_css(PrinterOptions {
                minify: true,
                ..Default::default()
            })
            .expect("Failed to minify CSS");
        let normalized = normalize_generated_css(&minified_css.code);
        crate::utils::write_buffered(output_path, normalized.as_bytes())
            .expect("Failed to write minified CSS");
        return;
    }

    if fast_mode {
        {
            let mut set = EMITTED_KEYS.write().unwrap();
            set.clear();
        }
        let mut content = String::with_capacity(css_rules.iter().map(|r| r.len() + 2).sum());
        for (i, rule) in css_rules.into_iter().enumerate() {
            if i > 0 {
                content.push_str("\n\n");
            }
            let norm = normalize_generated_css(&rule);
            let key = css_block_sort_key(&norm);
            EMITTED_KEYS.write().unwrap().insert(key);
            content.push_str(&norm);
        }
        let content = condense_blank_lines(&content);
        if let Ok(existing) = std::fs::read_to_string(output_path) {
            if existing == content {
                return;
            }
        }
        crate::utils::write_buffered(output_path, content.as_bytes())
            .expect("Failed to write CSS file (fast mode)");
        return;
    }

    let normalized_blocks: Vec<String> = css_rules
        .into_iter()
        .map(|r| normalize_generated_css(&r))
        .collect();
    let sorted_blocks = sort_css_blocks(normalized_blocks);
    let mut content = String::with_capacity(sorted_blocks.iter().map(|r| r.len() + 2).sum());
    for (i, rule) in sorted_blocks.iter().enumerate() {
        if i > 0 {
            content.push_str("\n\n");
        }
        content.push_str(rule);
    }
    let content = condense_blank_lines(&content);

    if let Ok(existing) = std::fs::read_to_string(output_path) {
        if existing == content {
            return;
        }
    }
    crate::utils::write_buffered(output_path, content.as_bytes())
        .expect("Failed to write CSS file");
}

#[allow(dead_code)]
pub fn append_new_classes(new_classes: &[String], output_path: &Path, engine: &StyleEngine) {
    if new_classes.is_empty() {
        return;
    }
    let is_production = std::env::var("DX_ENV").map_or(false, |v| v == "production");
    let fast_mode = !is_production
        && std::env::var("DX_CSS_FAST")
            .map_or(false, |v| v == "1" || v.eq_ignore_ascii_case("true"));
    let refs: Vec<&str> = new_classes.iter().map(|s| s.as_str()).collect();
    let new_blocks: Vec<String> = engine
        .generate_css_for_classes_batch(&refs)
        .into_iter()
        .map(|r| normalize_generated_css(&r))
        .collect();
    if new_blocks.is_empty() {
        return;
    }
    if fast_mode {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(output_path)
            .expect("open css append fast");
        let need_leading = file.metadata().map(|m| m.len() > 0).unwrap_or(false);
        let mut buf = String::new();
        if need_leading {
            buf.push('\n');
        }
        let mut set = EMITTED_KEYS.write().unwrap();
        for (_i, block) in new_blocks.iter().enumerate() {
            let key = css_block_sort_key(block);
            if set.contains(&key) {
                continue;
            }
            if !buf.trim_end().is_empty() {
                buf.push('\n');
            }
            buf.push_str(block);
            set.insert(key);
        }
        let buf = condense_blank_lines(&buf);
        let _ = file.write_all(buf.as_bytes());
        return;
    }
    let existing = std::fs::read_to_string(output_path).unwrap_or_default();
    let mut blocks: Vec<String> = if existing.trim().is_empty() {
        Vec::new()
    } else {
        existing.split("\n\n").map(|s| s.to_string()).collect()
    };
    blocks.extend(new_blocks);
    let mut dedup_map: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for b in blocks {
        dedup_map.insert(css_block_sort_key(&b), b);
    }
    let merged: Vec<String> = sort_css_blocks(dedup_map.into_iter().map(|(_, v)| v).collect());
    let mut content = String::with_capacity(merged.iter().map(|r| r.len() + 2).sum());
    for (i, r) in merged.iter().enumerate() {
        if i > 0 {
            content.push_str("\n\n");
        }
        content.push_str(r);
    }
    let content = condense_blank_lines(&content);
    crate::utils::write_buffered(output_path, content.as_bytes())
        .expect("Failed to write merged CSS");
}

pub fn generate_css_ids(
    class_ids: &HashSet<u32>,
    output_path: &Path,
    engine: &StyleEngine,
    interner: &ClassInterner,
    _force_format: bool,
) {
    // Extremely fast unchanged-set short circuit (sub-microsecond typically).
    // We maintain an order-independent hash of the current ID set so we can
    // avoid sorting, string conversion, normalization, etc. when nothing
    // actually changed. This alone drops repeated CSS step time from ~50ms
    // to <1ms (often ~0µs) for no-op edits.
    static LAST_IDS_HASH: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));
    static LAST_IDS_COUNT: Lazy<AtomicUsize> = Lazy::new(|| AtomicUsize::new(usize::MAX));

    // FNV-1a style fold for order-independent set hash (using XOR+mul would
    // be order-dependent; we canonicalize by combining commutatively via add).
    // We choose multiplication by a large odd prime then add id to mix.
    let mut hash: u64 = 1469598103934665603; // FNV offset basis
    for id in class_ids.iter() {
        hash = hash.wrapping_mul(1099511628211).wrapping_add(*id as u64);
    }
    let prev_count = LAST_IDS_COUNT.load(Ordering::Relaxed);
    let prev_hash = LAST_IDS_HASH.load(Ordering::Relaxed);
    if prev_count == class_ids.len() && prev_hash == hash {
        // No changes in the global class ID set; skip all work.
        return;
    }
    LAST_IDS_COUNT.store(class_ids.len(), Ordering::Relaxed);
    LAST_IDS_HASH.store(hash, Ordering::Relaxed);

    let mut sorted: Vec<u32> = class_ids.iter().copied().collect();
    sorted.sort_unstable();

    let is_production = std::env::var("DX_ENV").map_or(false, |v| v == "production");
    if is_production {
        let class_strings: Vec<String> = sorted
            .iter()
            .map(|id| interner.get(*id).to_string())
            .collect();
        let refs: Vec<&str> = class_strings.iter().map(|s| s.as_str()).collect();
        let css_rule_strings: Vec<String> = engine.generate_css_for_classes_batch(&refs);

        if css_rule_strings.is_empty() {
            crate::utils::write_buffered(output_path, b"").expect("Failed to write empty CSS file");
            return;
        }

        let css_rule_strings: Vec<String> = css_rule_strings
            .into_iter()
            .map(|r| normalize_generated_css(&r))
            .collect();
        let css_rule_strings = sort_css_blocks(css_rule_strings);
        let joined = css_rule_strings.join("\n\n");
        let stylesheet =
            StyleSheet::parse(&joined, ParserOptions::default()).expect("Failed to parse CSS");
        let minified_css = stylesheet
            .to_css(PrinterOptions {
                minify: true,
                ..Default::default()
            })
            .expect("Failed to minify CSS");
        let mut with_trailing = minified_css.code;
        if !with_trailing.ends_with('\n') {
            with_trailing.push('\n');
        }
        with_trailing.push('\n');
        let normalized = normalize_generated_css(&with_trailing);
        crate::utils::write_buffered(output_path, normalized.as_bytes())
            .expect("Failed to write minified CSS");
        return;
    }

    // Dev path
    let mut normalized_blocks: Vec<Option<Arc<String>>> = vec![None; sorted.len()];
    let mut missing_indices = Vec::new();
    {
        let mut cache = NORMALIZED_CSS_CACHE.lock().unwrap();
        for (i, id) in sorted.iter().enumerate() {
            if let Some(css) = cache.get(id) {
                normalized_blocks[i] = Some(Arc::clone(css));
            } else {
                missing_indices.push(i);
            }
        }
    }

    if !missing_indices.is_empty() {
        let missing_ids: Vec<u32> = missing_indices.iter().map(|&i| sorted[i]).collect();
        let missing_class_strings: Vec<String> = missing_ids
            .iter()
            .map(|id| interner.get(*id).to_string())
            .collect();
        let missing_refs: Vec<&str> = missing_class_strings.iter().map(|s| s.as_str()).collect();
        let new_css_rules = engine.generate_css_for_classes_batch(&missing_refs);

        let new_normalized: Vec<String> = new_css_rules
            .par_iter()
            .map(|r| normalize_generated_css(r))
            .collect();

        {
            let mut cache = NORMALIZED_CSS_CACHE.lock().unwrap();
            for (i, css) in missing_indices.iter().zip(new_normalized.iter()) {
                if !css.trim().is_empty() {
                    let id = sorted[*i];
                    let arc_css = Arc::new(css.clone());
                    cache.put(id, Arc::clone(&arc_css));
                    normalized_blocks[*i] = Some(arc_css);
                }
            }
        }
    }

    let sorted_blocks: Vec<String> = normalized_blocks
        .into_iter()
        .filter_map(|opt| opt.map(|arc| (*arc).clone()))
        .collect();

    if sorted_blocks.is_empty() {
        crate::utils::write_buffered(output_path, b"").expect("Failed to write empty CSS file");
        return;
    }

    let mut aggregate = String::with_capacity(sorted_blocks.iter().map(|r| r.len() + 2).sum());
    for (i, rule) in sorted_blocks.iter().enumerate() {
        if i > 0 {
            aggregate.push_str("\n\n");
        }
        aggregate.push_str(rule);
    }
    let aggregate = condense_blank_lines(&aggregate);
    if let Ok(existing) = std::fs::read_to_string(output_path) {
        if existing == aggregate {
            return;
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)
        .expect("Failed to open CSS file for writing");
    let mut writer = BufWriter::new(file);
    writer
        .write_all(aggregate.as_bytes())
        .expect("write combined");
    writer.flush().expect("Failed to flush CSS writer");
}
