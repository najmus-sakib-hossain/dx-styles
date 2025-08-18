use crate::engine::StyleEngine;
use crate::interner::ClassInterner;
use lightningcss::stylesheet::{ParserOptions, PrinterOptions, StyleSheet};
use lru::LruCache;
use once_cell::sync::{Lazy, OnceCell};
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
use std::cell::RefCell;
use std::time::Instant;

// Use cfg to make platform-specific code conditional
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use memmap2::{Mmap, MmapMut, MmapOptions};

static NORMALIZE_CACHE: Lazy<Mutex<LruCache<u64, Arc<String>>>> =
    Lazy::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap())));

static NORMALIZED_CSS_CACHE: Lazy<Mutex<LruCache<u32, Arc<String>>>> =
    Lazy::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(8192).unwrap())));

static EMITTED_KEYS: Lazy<RwLock<std::collections::HashSet<String>>> =
    Lazy::new(|| RwLock::new(std::collections::HashSet::new()));

// Ultra-fast output cache to avoid regenerating identical CSS
static OUTPUT_CACHE: Lazy<RwLock<HashMap<u64, (Vec<u8>, u64)>>> = 
    Lazy::new(|| RwLock::new(HashMap::new()));

// Cache for CSS content by path
static PATH_CONTENT_CACHE: Lazy<RwLock<HashMap<PathBuf, (u64, u64)>>> = 
    Lazy::new(|| RwLock::new(HashMap::new()));

// Last successful CSS generation timestamp
static LAST_GENERATION_TIME: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));

// New cache for tracking specific class changes
static _CLASS_CHANGE_TRACKER: Lazy<RwLock<HashMap<u32, u64>>> = 
    Lazy::new(|| RwLock::new(HashMap::new()));

// IDs tracking for optimization
static LAST_IDS_HASH: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));
static LAST_IDS_COUNT: Lazy<AtomicUsize> = Lazy::new(|| AtomicUsize::new(usize::MAX));

// Memory-mapped file cache to avoid disk I/O (platform independent version)
thread_local! {
    #[cfg(windows)]
    static MMAP_CACHE: RefCell<HashMap<PathBuf, (Mmap, u64, Instant)>> = RefCell::new(HashMap::new());
    
    #[cfg(not(windows))]
    static CONTENT_CACHE: RefCell<HashMap<PathBuf, (Vec<u8>, u64, Instant)>> = RefCell::new(HashMap::new());
}

// Store previous class IDs for efficient patching
static PREV_CLASS_IDS: Lazy<RwLock<HashSet<u32>>> = Lazy::new(|| RwLock::new(HashSet::new()));

// Ultra-fast hash function specific for class detection
#[inline]
fn fast_hash<T: Hash>(v: &T) -> u64 {
    let mut h = SeaHasher::new();
    v.hash(&mut h);
    h.finish()
}

// Preload common classes for fast access
pub fn preload_common_classes(engine: &StyleEngine, interner: &mut ClassInterner) {
    let common_classes = ["flex", "grid", "hidden", "block", 
                          "p-4", "m-4", "text-lg", "font-bold", 
                          "rounded", "border", "shadow"];
    
    let css_rules = engine.generate_css_for_classes_batch(&common_classes);
    
    for (class, css) in common_classes.iter().zip(css_rules.iter()) {
        if !css.is_empty() {
            let normalized = normalize_generated_css(css);
            if let Ok(mut cache) = NORMALIZED_CSS_CACHE.lock() {
                let id = interner.intern(class);
                cache.put(id, Arc::new(normalized));
            }
        }
    }
}

// Platform-specific file operations
#[cfg(windows)]
fn write_mmap(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .access_mode(0x40000000) // FILE_FLAG_SEQUENTIAL_SCAN for performance
        .open(path)?;
    
    file.set_len(content.len() as u64)?;
    
    let mut mmap = unsafe { MmapOptions::new().map_mut(&file)? };
    mmap.copy_from_slice(content);
    mmap.flush()?;
    
    Ok(())
}

// Cross-platform fallback for non-Windows systems
#[cfg(not(windows))]
fn write_mmap(path: &Path, content: &[u8]) -> std::io::Result<()> {
    // Use standard buffered write on non-Windows platforms
    crate::utils::write_buffered(path, content)
}

// Cross-platform file content checking
fn patch_css_file(path: &Path, old_ids: &HashSet<u32>, new_ids: &HashSet<u32>, 
                 engine: &StyleEngine, interner: &ClassInterner) -> bool {
    if !path.exists() {
        return false;
    }

    // Compute deltas
    let mut added_ids = Vec::new();
    let mut removed_ids = Vec::new();
    for &id in new_ids {
        if !old_ids.contains(&id) {
            added_ids.push(id);
        }
    }
    for &id in old_ids {
        if !new_ids.contains(&id) {
            removed_ids.push(id);
        }
    }

    // Nothing to do
    if added_ids.is_empty() && removed_ids.is_empty() {
        return true;
    }

    // Allow more changes for micro patching (was 10)
    if added_ids.len() + removed_ids.len() > 32 {
        return false;
    }

    let Ok(mut content) = std::fs::read_to_string(path) else {
        return false;
    };
    let original_len = content.len();
    let mut changed = false;

    // Helper: remove a class rule block robustly (handles multi-line + nested braces)
    fn remove_rule_block(src: &mut String, class_name: &str) -> bool {
        let needle = format!(".{}", class_name);
        let bytes = src.as_bytes();
        let mut pos = 0usize;
        let mut did_remove = false;
        while let Some(rel) = src[pos..].find(&needle) {
            let start = pos + rel;
            // Ensure it's a selector start (preceded by start/whitespace or double newline)
            if start > 0 {
                let prev = bytes[start - 1] as char;
                if !(prev.is_whitespace() || prev == '\n' || prev == '}' ) {
                    pos = start + needle.len();
                    continue;
                }
            }
            // Find first '{' after the selector (skip until '{')
            let mut brace_search = start + needle.len();
            let sb = src.as_bytes();
            let mut found_brace = None;
            while brace_search < sb.len() {
                let c = sb[brace_search] as char;
                if c == '{' {
                    found_brace = Some(brace_search);
                    break;
                }
                if c == '\n' && brace_search > start && sb[brace_search - 1] == b'\n' {
                    break; // blank line before '{' -> likely not a rule
                }
                brace_search += 1;
            }
            let Some(open_pos) = found_brace else {
                pos = start + needle.len();
                continue;
            };

            // Walk to matching closing brace depth
            let mut depth = 0i32;
            let mut i = open_pos;
            let mut end_pos = None;
            while i < sb.len() {
                let c = sb[i] as char;
                if c == '{' {
                    depth += 1;
                } else if c == '}' {
                    depth -= 1;
                    if depth == 0 {
                        end_pos = Some(i + 1);
                        break;
                    }
                }
                i += 1;
            }
            let Some(mut rule_end) = end_pos else {
                pos = start + needle.len();
                continue;
            };

            // Extend over trailing whitespace / blank lines
            while rule_end < sb.len() && (sb[rule_end] as char).is_whitespace() {
                rule_end += 1;
            }
            // Trim excessive blank lines collapse to at most one
            let slice = &src[start..rule_end];
            if !slice.is_empty() {
                src.replace_range(start..rule_end, "");
                did_remove = true;
                // Restart scanning from beginning as indices shifted
                pos = 0;
                continue;
            }
            pos = start + needle.len();
        }
        did_remove
    }

    // Remove old class rules
    for id in &removed_ids {
        let class_name = interner.get(*id);
        if remove_rule_block(&mut content, class_name) {
            changed = true;
        }
    }

    // Append new class rules
    if !added_ids.is_empty() {
        let added_class_names: Vec<String> = added_ids.iter().map(|id| interner.get(*id).to_string()).collect();
        let refs: Vec<&str> = added_class_names.iter().map(|s| s.as_str()).collect();
        let new_css = engine.generate_css_for_classes_batch(&refs);
        for css in new_css {
            let norm = normalize_generated_css(&css);
            if norm.trim().is_empty() {
                continue;
            }
            if !content.is_empty() && !content.ends_with("\n\n") {
                content.push_str("\n\n");
            }
            content.push_str(&norm);
            changed = true;
        }
    }

    // If we expected changes but nothing actually mutated the content, abort patch => force full regen
    if !changed && (added_ids.len() + removed_ids.len() > 0) {
        return false;
    }

    if changed && content.len() != original_len {
        if write_mmap(path, content.as_bytes()).is_ok() {
            return true;
        }
        return false;
    }

    true
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

pub fn generate_css_ids(
    class_ids: &HashSet<u32>,
    output_path: &Path,
    engine: &StyleEngine,
    interner: &ClassInterner,
    force_format: bool,
) {
    // Ultra-fast unchanged check using atomic state
    static LAST_STATE: OnceCell<AtomicU64> = OnceCell::new();
    let last_state = LAST_STATE.get_or_init(|| AtomicU64::new(0));
    
    // Skip all work if output was recently generated (debounce)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    
    let last_gen = LAST_GENERATION_TIME.load(Ordering::Relaxed);
    if !force_format && now - last_gen < 2 {  // Reduced from 5ms to 2ms
        return; // Skip if last generation was less than 2ms ago
    }
    
    // Compute a direct hash of class IDs for ultra-fast comparison
    let mut direct_hasher = SeaHasher::new();
    // Sort to ensure consistent hashing
    let mut sorted_for_hash: Vec<u32> = class_ids.iter().copied().collect();
    sorted_for_hash.sort_unstable();
    for id in &sorted_for_hash {
        direct_hasher.write_u32(*id);
    }
    let direct_hash = direct_hasher.finish();
    
    // Compare with last known state
    let last_hash = last_state.load(Ordering::Relaxed);
    if !force_format && last_hash == direct_hash && last_hash != 0 {
        // No changes, skip all work
        LAST_GENERATION_TIME.store(now, Ordering::Relaxed);
        return;
    }
    
    // If micro-patching is successful, we can skip full regeneration
    let should_try_patch = !force_format && output_path.exists() && direct_hash != 0 && last_hash != 0;
    
    if should_try_patch {
        let old_ids = PREV_CLASS_IDS.read().unwrap().clone();
        if patch_css_file(output_path, &old_ids, class_ids, engine, interner) {
            LAST_GENERATION_TIME.store(now, Ordering::Relaxed);
            last_state.store(direct_hash, Ordering::Relaxed);
            if let Ok(mut prev_ids) = PREV_CLASS_IDS.write() {
                *prev_ids = class_ids.clone();
            }
            return;
        }
    }

    // Rest of the original code for full regeneration
    let mut sorted: Vec<u32> = class_ids.iter().copied().collect();
    sorted.sort_unstable();
    
    LAST_IDS_COUNT.store(sorted.len(), Ordering::Relaxed);
    LAST_IDS_HASH.store(direct_hash, Ordering::Relaxed);

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
        // Process missing classes in batches for better performance
        const BATCH_SIZE: usize = 64;
        for chunk in missing_indices.chunks(BATCH_SIZE) {
            let missing_ids: Vec<u32> = chunk.iter().map(|&i| sorted[i]).collect();
            let missing_class_strings: Vec<String> = missing_ids
                .iter()
                .map(|id| interner.get(*id).to_string())
                .collect();
            let missing_refs: Vec<&str> = missing_class_strings.iter().map(|s| s.as_str()).collect();
            let new_css_rules = engine.generate_css_for_classes_batch(&missing_refs);

            let new_normalized: Vec<String> = new_css_rules
                .iter()
                .map(|r| normalize_generated_css(r))
                .collect();

            if let Ok(mut cache) = NORMALIZED_CSS_CACHE.lock() {
                for (i_ref, css) in chunk.iter().zip(new_normalized.iter()) {
                    if !css.trim().is_empty() {
                        let id = sorted[*i_ref];
                        let arc_css = Arc::new(css.clone());
                        cache.put(id, Arc::clone(&arc_css));
                        normalized_blocks[*i_ref] = Some(arc_css);
                    }
                }
            }
        }
    }

    // Calculate capacity and check if we actually have content
    let mut capacity = 0;
    let mut has_content = false;
    for block_opt in &normalized_blocks {
        if let Some(css_arc) = block_opt {
            capacity += css_arc.len() + 2;
            has_content = true;
        }
    }

    if !has_content {
        // Empty output - fast path
        if let Ok(existing) = std::fs::metadata(output_path) {
            if existing.len() > 0 {
                // Only write if not already empty
                crate::utils::write_buffered(output_path, b"").expect("Failed to write empty CSS file");
                
                // Update caches
                if let Ok(mut cache) = OUTPUT_CACHE.write() {
                    cache.insert(direct_hash, (Vec::new(), 0));
                }
                if let Ok(mut path_cache) = PATH_CONTENT_CACHE.write() {
                    path_cache.insert(output_path.to_path_buf(), (0, now));
                }
            }
        } else {
            // File doesn't exist, create empty file
            crate::utils::write_buffered(output_path, b"").expect("Failed to write empty CSS file");
            
            // Update caches
            if let Ok(mut cache) = OUTPUT_CACHE.write() {
                cache.insert(direct_hash, (Vec::new(), 0));
            }
            if let Ok(mut path_cache) = PATH_CONTENT_CACHE.write() {
                path_cache.insert(output_path.to_path_buf(), (0, now));
            }
        }
        
        // Store current class IDs for future patches
        if let Ok(mut prev_ids) = PREV_CLASS_IDS.write() {
            *prev_ids = class_ids.clone();
        }
        
        // Update state before returning
        last_state.store(direct_hash, Ordering::Relaxed);
        LAST_GENERATION_TIME.store(now, Ordering::Relaxed);
        return;
    }

    // Build final output string
    let mut aggregate = String::with_capacity(capacity);
    let mut first = true;
    for block_opt in normalized_blocks {
        if let Some(css_arc) = block_opt {
            if !first {
                aggregate.push_str("\n\n");
            }
            aggregate.push_str(&css_arc);
            first = false;
        }
    }

    let aggregate = condense_blank_lines(&aggregate);
    let content_hash = fast_hash(&aggregate);
    
    // Check if file already has this content
    let need_write = if let Ok(path_cache) = PATH_CONTENT_CACHE.read() {
        match path_cache.get(output_path) {
            Some((hash, _)) => *hash != content_hash,
            None => true
        }
    } else {
        true
    };
    
    if need_write {
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(output_path)
        {
            let mut writer = BufWriter::with_capacity(aggregate.len() + 256, file);
            if writer.write_all(aggregate.as_bytes()).is_ok() && writer.flush().is_ok() {
                // Cache the output for future use
                if let Ok(mut cache) = OUTPUT_CACHE.write() {
                    cache.insert(direct_hash, (aggregate.into_bytes(), content_hash));
                }
                if let Ok(mut path_cache) = PATH_CONTENT_CACHE.write() {
                    path_cache.insert(output_path.to_path_buf(), (content_hash, now));
                }
            }
        }
    }
    
    // Store current class IDs for future patches
    if let Ok(mut prev_ids) = PREV_CLASS_IDS.write() {
        *prev_ids = class_ids.clone();
    }
    
    // Update state before returning
    last_state.store(direct_hash, Ordering::Relaxed);
    LAST_GENERATION_TIME.store(now, Ordering::Relaxed);
}
