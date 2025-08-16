use crate::engine::StyleEngine;
use crate::interner::ClassInterner;
use lightningcss::stylesheet::{ParserOptions, PrinterOptions, StyleSheet};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use once_cell::sync::Lazy;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use lru::LruCache;
use seahash::SeaHasher;
use std::hash::{Hasher, Hash};

// Global LRU cache to avoid re-normalizing identical generated rules.
// Typical rule count can be large but individual rules repeat across incremental builds.
static NORMALIZE_CACHE: Lazy<Mutex<LruCache<u64, Arc<String>>>> = Lazy::new(|| {
    // 4096 entries * average ~200 bytes ≈ <1MB.
    Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap()))
});

#[inline]
fn fast_hash<T: Hash>(v: &T) -> u64 {
    let mut h = SeaHasher::new();
    v.hash(&mut h);
    h.finish()
}

fn normalize_generated_css(css: &str) -> String {
    // Ultra fast path: trivial short strings can't contain patterns we touch.
    if css.len() < 3 { return css.to_string(); }
    // Cached path.
    let key = fast_hash(&css);
    if let Some(cached) = NORMALIZE_CACHE.lock().ok().and_then(|mut c| c.get(&key).cloned()) {
        return (*cached).clone();
    }

    let mut out = css.to_string();

    out = fix_missing_dot_for_escaped_symbol_groups(&out);
    // IMPORTANT: Preserve full grouped selector names (e.g. .card\(p-13 ...\)).
    // Previous passes simplified/group-collapsed selectors causing collisions (.card, .from, etc.).
    // We intentionally skip those transforms to maintain 1:1 mapping with source TSX.
    // (If needed later, add an opt-in production minifier flag instead.)
    out = remove_selector_blocks(&out, |sel| sel.starts_with(".dx-class-") && sel.len() >= 18);

    const VARIANTS: &[&str] = &[
        ".hover\\(", ".focus\\(", ".active\\(", ".focus-within\\(", ".focus-visible\\(", ".visited\\(",
        ".disabled\\(", ".checked\\(", ".group-hover\\(", ".group-focus\\(", ".group-active\\(",
        ".peer-hover\\(", ".peer-focus\\(", ".peer-active\\(", ".dark\\("
    ];
    out = remove_selector_blocks(&out, |sel| {
        let mut simple = String::with_capacity(sel.len());
        let mut last_ws = false;
        for ch in sel.chars() {
            if ch.is_whitespace() { if !last_ws { simple.push(' '); last_ws = true; } } else { simple.push(ch); last_ws = false; }
        }
        let mut trimmed = simple.trim();
        if let Some(idx) = trimmed.find("\\(") {
            trimmed = &trimmed[..idx];
        }
        if trimmed.contains(' ') { return false; }
        VARIANTS.iter().any(|v| {
            if trimmed == *v || trimmed.starts_with(v) { return true; }
            if let Some(base) = v.strip_suffix("\\(") { trimmed == base }
            else { false }
        })
    });

    out = strip_top_level_container_rules(&out);
    out = expand_container_group_selectors(&out);
    out = remove_selector_blocks(&out, |sel| {
        let mut de = String::with_capacity(sel.len());
        let mut it = sel.chars().peekable();
        while let Some(c) = it.next() { if c == '\\' { if let Some(n) = it.next() { de.push(n); } } else { de.push(c); } }
        de.starts_with(".?@container>")
    });

    // NOTE: We intentionally removed the lightningcss parse + re-print step here.
    // Parsing was adding ~10-15ms for even modest CSS payloads. The normalizer now
    // performs only lightweight string transforms. Any full parsing (minify or
    // pretty format) is handled explicitly in the caller when required.

    out = remove_orphan_selectors(&out);
    out = reescape_leading_invalid_identifiers(&out);
    out = normalize_child_combinator_spacing(&out);

    // Insert into cache (ignore if poisoned)
    if out.len() <= 16 * 1024 { // don't cache very large blocks
        if let Ok(mut cache) = NORMALIZE_CACHE.lock() { cache.put(key, Arc::new(out.clone())); }
    }
    out
}

// Ensure there is a space on both sides of the child combinator '>' in selectors.
// We operate on the whole CSS text but skip regions that are clearly inside declaration blocks
// (naively tracked via brace depth) to reduce risk of touching values like content: ">".
fn normalize_child_combinator_spacing(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    let mut depth = 0usize; // counts nested '{' minus '}' to know if we're inside declarations
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '{' => { depth += 1; out.push(c); i += 1; },
            '}' => { if depth > 0 { depth -= 1; } out.push(c); i += 1; },
            '>' if depth == 0 => {
                // Normalize spacing around child combinator
                // Remove any trailing spaces just to re-insert single spacing consistently
                while out.ends_with(' ') { out.pop(); }
                // Ensure single space before '>' unless previous significant char is start of selector list delimiter
                if !out.ends_with([' ', '\n', '\t', ',', '{']) { out.push(' '); }
                out.push('>');
                // Skip any spaces already following in source
                i += 1;
                while i < bytes.len() && (bytes[i] as char).is_whitespace() { if bytes[i] as char == '\n' { break; } i += 1; }
                // Add space after '>' if next char is not whitespace, newline, '{', or ','
                if i < bytes.len() {
                    let next = bytes[i] as char;
                    if !matches!(next, ' ' | '\n' | '\t' | '{' | ',' | '>') { out.push(' '); }
                }
            }
            _ => { out.push(c); i += 1; }
        }
    }
    // If no change (sizes equal and identical) early return original to keep Arc reuse potential higher
    if out == input { return input.to_string(); }
    out
}

// Lightweight blank line condensing: collapse 3+ consecutive newlines to 2, trim leading/trailing.
fn condense_blank_lines(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut newline_run = 0usize;
    for ch in input.chars() {
        if ch == '\n' { newline_run += 1; } else { newline_run = 0; }
        if newline_run <= 2 { out.push(ch); }
    }
    // Trim leading blank lines
    while out.starts_with('\n') { out.remove(0); }
    // Ensure single trailing newline
    while out.ends_with('\n') { out.pop(); }
    out.push('\n');
    out
}

/// Extremely fast (approx O(n)) heuristic CSS pretty-printer intended only for
/// internally generated CSS we control. Avoids full parsing for <1ms latency.
/// It normalizes:
/// - One declaration per line
/// - Indentation with two spaces
/// - Blank line between top-level rules
/// It does NOT guarantee spec-compliant formatting for arbitrary user CSS.
#[allow(dead_code)]
fn pretty_format_css_fast(input: &str) -> String {
    // Small fast-path: if already looks formatted (has \n  ) just return.
    if input.as_bytes().windows(3).any(|w| w == b"\n  ") {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len() + input.len() / 8 + 32);
    let mut depth: i32 = 0;
    let mut in_string: Option<char> = None;
    let mut last_emitted_non_ws: char = '\n';
    let bytes = input.as_bytes();
    let mut i = 0usize;
    // Helper: emit indentation
    let emit_indent = |out: &mut String, depth: i32| {
        for _ in 0..depth { out.push_str("  "); }
    };
    while i < bytes.len() {
        let c = bytes[i] as char;
        if let Some(sq) = in_string {
            out.push(c);
            if c == '\\' { // escape next
                if i + 1 < bytes.len() { out.push(bytes[i+1] as char); i += 2; continue; }
            } else if c == sq { in_string = None; }
            i += 1;
            continue;
        }
        match c {
            '"' | '\'' => { in_string = Some(c); out.push(c); },
            '{' => {
                // Trim trailing spaces
                while out.ends_with(' ') || out.ends_with('\t') { out.pop(); }
                out.push_str(" {\n");
                depth += 1;
                emit_indent(&mut out, depth);
            },
            '}' => {
                // Remove trailing whitespace/newlines
                while out.ends_with([' ', '\t', '\n']) { out.pop(); }
                depth -= 1; if depth < 0 { depth = 0; }
                out.push('\n');
                emit_indent(&mut out, depth);
                out.push('}');
                // Peek next significant char
                let mut k = i + 1; while k < bytes.len() && (bytes[k] as char).is_whitespace() { if bytes[k] == b'\n' { break; } k += 1; }
                out.push('\n');
                if k < bytes.len() && bytes[k] != b'\n' && depth == 0 { out.push('\n'); }
            },
            ';' => {
                out.push(';');
                out.push('\n');
                emit_indent(&mut out, depth);
            },
            '\n' => {
                if !out.ends_with('\n') { out.push('\n'); emit_indent(&mut out, depth); }
            },
            ' ' | '\t' | '\r' => {
                // Collapse consecutive whitespace outside rules
                if !out.ends_with(' ') && !out.ends_with('\n') { out.push(' '); }
            },
            _ => {
                if last_emitted_non_ws == '}' && !out.ends_with('\n') { out.push('\n'); emit_indent(&mut out, depth); }
                out.push(c);
                last_emitted_non_ws = c;
            }
        }
        i += 1;
    }
    // Final trim
    while out.ends_with([' ', '\t', '\n']) { out.pop(); }
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
                        if matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_') { idx += 1; continue; }
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
        out.push_str(line); out.push('\n');
    }
    if !changed { return input.to_string(); }
    out
}

fn sanitize_class_selectors(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut last_written = 0usize;
    let mut out = String::with_capacity(input.len());
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let prev = if i == 0 { b'\n' } else { bytes[i.saturating_sub(1)] };
            if !matches!(prev, b'\n' | b' ' | b'\t' | b'{' | b'}' | b',' | b'>' | b'+' | b'~') {
                i += 1;
                continue;
            }

            let start = i + 1;
            let mut j = start;
            while j < bytes.len() {
                let c = bytes[j];
                if matches!(c, b' ' | b'\n' | b'\t' | b'{' | b'}' | b',' | b'>' | b'+' | b'~' | b':' | b'[') {
                    break;
                }
                j += 1;
            }

            if j > start {
                let ident = &input[start..j];
                let mut sanitized = String::with_capacity(ident.len() * 2);
                let mut needs_change = false;
                let mut chars = ident.chars().peekable();
                let mut char_index = 0;

                while let Some(ch) = chars.next() {
                    if ch == '\\' {
                        sanitized.push('\\');
                        if let Some(next_ch) = chars.next() {
                            sanitized.push(next_ch);
                        }
                        char_index += 2;
                        continue;
                    }

                    let is_standard_ident_char = matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_');
                    let is_invalid_start = (char_index == 0 && ch.is_ascii_digit()) ||
                                         (char_index == 0 && ch == '-' && chars.peek().map_or(false, |c| c.is_ascii_digit()));

                    if !is_standard_ident_char || is_invalid_start {
                        sanitized.push('\\');
                        sanitized.push(ch);
                        if !needs_change { needs_change = true; }
                    } else {
                        sanitized.push(ch);
                    }
                    char_index += 1;
                }

                if needs_change {
                    out.push_str(&input[last_written..i]);
                    out.push('.');
                    out.push_str(&sanitized);
                    last_written = j;
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }

    if last_written == 0 {
        return input.to_string();
    }

    out.push_str(&input[last_written..]);
    out
}


fn expand_container_group_selectors(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    let mut last_copied = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let sel_start = i;
            let mut j = i + 1;
            let mut paren_pos: Option<usize> = None;
            while j < bytes.len() {
                if bytes[j] == b'(' { paren_pos = Some(j); break; }
                if bytes[j] == b'\\' && j + 1 < bytes.len() && bytes[j+1] == b'(' { paren_pos = Some(j); break; }
                if matches!(bytes[j], b'{' | b'\n') { break; }
                j += 1;
            }
            if let Some(p_pos) = paren_pos {
                let escaped_paren = bytes[p_pos] == b'\\';
                let open_paren_idx = if escaped_paren { p_pos + 1 } else { p_pos };
                let head = &input[sel_start..open_paren_idx];
                let mut marker = String::with_capacity(head.len());
                let mut chars = head.chars().peekable();
                while let Some(ch) = chars.next() {
                    if ch == '\\' { if let Some(nc) = chars.next() { marker.push(nc); } else { break; } } else { marker.push(ch); }
                }
                if marker.starts_with(".?@container>") {
                    let mut k = open_paren_idx + 1;
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
                        let mut after = c_idx + 1;
                        while after < bytes.len() && bytes[after].is_ascii_whitespace() { after += 1; }
                        if after < bytes.len() && bytes[after] == b'{' {
                            let inner = &input[open_paren_idx+1..c_idx];
                            let raw_tokens: Vec<&str> = if inner.contains("\\ ") {
                                inner.split("\\ ").filter(|t| !t.is_empty()).collect()
                            } else {
                                inner.split_whitespace().filter(|t| !t.is_empty()).collect()
                            };
                            if !raw_tokens.is_empty() {
                                if sel_start > last_copied { out.push_str(&input[last_copied..sel_start]); }
                                let mut first = true;
                                for tok in raw_tokens {
                                    if !first { out.push_str(", "); } else { first = false; }
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
                                i = after + 1;
                                last_copied = i;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    if last_copied < input.len() { out.push_str(&input[last_copied..]); }
    out
}

fn simplify_local_component_groups(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    let mut last_emitted = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' && i + 2 < bytes.len() && bytes[i + 1] == b'_' {
            let ident_start = i + 2;
            let mut ident_end = ident_start;
            while ident_end < bytes.len() {
                let c = bytes[ident_end];
                if matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_') { ident_end += 1; continue; }
                break;
            }
            if ident_end + 1 < bytes.len() && bytes[ident_end] == b'\\' && bytes[ident_end + 1] == b'(' {
                let mut j = ident_end + 2;
                let mut closed = false;
                while j + 1 < bytes.len() {
                    if bytes[j] == b'\\' {
                        if j + 1 < bytes.len() && bytes[j + 1] == b')' { j += 2; closed = true; break; }
                        j += 2; continue;
                    }
                    if bytes[j] == b'{' { break; }
                    j += 1;
                }
                if closed {
                    let mut k = j;
                    while k < bytes.len() && matches!(bytes[k], b' ' | b'\t' | b'\n' | b'\r') { k += 1; }
                    if k < bytes.len() && bytes[k] == b'{' {
                        if i > last_emitted { out.push_str(&input[last_emitted..i]); }
                        out.push_str(&input[i..ident_end]);
                        out.push_str(" {");
                        i = k + 1;
                        last_emitted = i;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    if last_emitted == 0 { return input.to_string(); }
    if last_emitted < input.len() { out.push_str(&input[last_emitted..]); }
    out
}

fn simplify_known_group_patterns(input: &str) -> String {
    const NAMES: &[&str] = &["card", "transition", "mesh", "div", "from", "to"];
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    let mut last_emitted = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let ident_start = i + 1;
            let mut ident_end = ident_start;
            while ident_end < bytes.len() {
                let c = bytes[ident_end];
                if matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_') { ident_end += 1; continue; }
                break;
            }
            if ident_end > ident_start && ident_end + 1 < bytes.len() && bytes[ident_end] == b'\\' && bytes[ident_end + 1] == b'(' {
                let name = &input[ident_start..ident_end];
                if NAMES.iter().any(|n| *n == name) {
                    let mut j = ident_end + 2;
                    let mut closed = false;
                    while j + 1 < bytes.len() {
                        if bytes[j] == b'\\' {
                            if j + 1 < bytes.len() && bytes[j + 1] == b')' { j += 2; closed = true; break; }
                            j += 2; continue;
                        }
                        if bytes[j] == b'{' { break; }
                        j += 1;
                    }
                    if closed {
                        let mut k = j;
                        while k < bytes.len() && matches!(bytes[k], b' ' | b'\t' | b'\n' | b'\r') { k += 1; }
                        if k < bytes.len() && bytes[k] == b'{' {
                            if i > last_emitted { out.push_str(&input[last_emitted..i]); }
                            out.push_str(&input[i..ident_end]);
                            out.push_str(" {");
                            i = k + 1;
                            last_emitted = i;
                            continue;
                        }
                    }
                }
            }
        }
        i += 1;
    }
    if last_emitted == 0 { return input.to_string(); }
    if last_emitted < input.len() { out.push_str(&input[last_emitted..]); }
    out
}

fn simplify_group_parents_in_complex_selectors(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    let mut last_emit = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let name_start = i + 1;
            let mut name_end = name_start;
            while name_end < bytes.len() {
                let c = bytes[name_end];
                if c == b'\\' {
                    if name_end + 1 >= bytes.len() { break; }
                    let next = bytes[name_end + 1];
                    if next == b'(' { break; }
                    name_end += 2; continue;
                }
                if matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'*') { name_end += 1; continue; }
                break;
            }
            if name_end + 1 < bytes.len() && bytes[name_end] == b'\\' && bytes[name_end + 1] == b'(' {
                let mut depth = 0i32;
                let mut j = name_end;
                let mut valid = false;
                while j + 1 < bytes.len() {
                    if bytes[j] == b'\\' {
                        let next = bytes[j+1];
                        if next == b'(' { depth += 1; j += 2; continue; }
                        if next == b')' { depth -= 1; j += 2; if depth == 0 { valid = true; break; } continue; }
                        j += 2; continue;
                    }
                    if matches!(bytes[j], b'{' | b'\n') { break; }
                    j += 1;
                }
                if valid {
                    let group_end = j;
                    let mut group_after = group_end;
                    while group_after < bytes.len() && bytes[group_after].is_ascii_whitespace() { group_after += 1; }
                    let k = group_after;
                    if k < bytes.len() {
                        let next = bytes[k];
                        if matches!(next, b'>' | b'+' | b'~' | b'[') || next.is_ascii_alphanumeric() || next == b'.' || next == b'#' {
                            if i > last_emit { out.push_str(&input[last_emit..i]); }
                            out.push_str(&input[i..name_end]);
                            last_emit = group_after;
                            i = group_after;
                            continue;
                        }
                    }
                }
            }
        }
        i += 1;
    }
    if last_emit == 0 { return input.to_string(); }
    if last_emit < input.len() { out.push_str(&input[last_emit..]); }
    let mut coarse = String::with_capacity(out.len());
    let mut idx = 0usize;
    let ob = out.as_bytes();
    while idx < ob.len() {
        if ob[idx] == b'.' {
            let _start = idx;
            let mut k = idx + 1;
            while k < ob.len() && (ob[k].is_ascii_alphanumeric() || matches!(ob[k], b'-' | b'_' | b'*' | b'\\')) {
                if ob[k] == b'\\' && k + 1 < ob.len() && ob[k+1] == b'(' { break; }
                k += 1;
            }
            if k + 1 < ob.len() && ob[k] == b'\\' && ob[k+1] == b'(' {
                if let Some(rel) = out[k..].find("\\) >") {
                    let close_idx = k + rel;
                    if !out[k..close_idx].contains('{') {
                        coarse.push_str(&out[idx..k]);
                        coarse.push_str(" >");
                        idx = close_idx + 3;
                        continue;
                    }
                }
            }
        }
        coarse.push(ob[idx] as char);
        idx += 1;
    }
    coarse
}

fn reescape_leading_invalid_identifiers(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut last_copy = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let start = i + 1;
            if start >= bytes.len() { break; }
            if bytes[start].is_ascii_digit() { i += 1; continue; }
            if bytes[start] == b'\\' { i += 1; continue; }
            let ch = bytes[start] as char;
            let needs_escape = match ch {
                'a'..='z' | 'A'..='Z' | '_' => false,
                '-' => {
                    if start + 1 < bytes.len() {
                        let next = bytes[start + 1] as char;
                        next.is_ascii_digit()
                    } else { false }
                }
                _ => true,
            } || ch.is_ascii_digit();
            if needs_escape {
                if i > last_copy { out.push_str(&input[last_copy..i+1]); }
                out.push('\\');
                out.push(ch);
                last_copy = start + 1;
                i = start + 1;
                continue;
            }
        }
        i += 1;
    }
    if last_copy == 0 { return input.to_string(); }
    if last_copy < input.len() { out.push_str(&input[last_copy..]); }
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
            while j < bytes.len() && bytes[j] != b'{' && bytes[j] != b'\n' { j += 1; }
            let mut brace_pos: Option<usize> = None;
            let mut selector_end = j;
            if j < bytes.len() && bytes[j] == b'{' { brace_pos = Some(j); }
            else if j < bytes.len() && bytes[j] == b'\n' {
                let mut k = j + 1;
                while k < bytes.len() {
                    if bytes[k] == b'{' { brace_pos = Some(k); selector_end = j; break; }
                    if !bytes[k].is_ascii_whitespace() { break; }
                    k += 1;
                }
            }
            if let Some(bpos) = brace_pos {
                let mut selector = &input[sel_start..selector_end];
                while selector.ends_with(|c: char| c.is_whitespace()) { selector = selector.trim_end(); }
                if let Some(group_idx) = selector.find("\\(") { selector = &selector[..group_idx]; }
                let selector = selector.trim_end();
                if predicate(selector) {
                    i = bpos;
                    let mut depth = 0usize;
                    while i < bytes.len() {
                        if bytes[i] == b'{' { depth += 1; }
                        else if bytes[i] == b'}' { depth -= 1; if depth == 0 { i += 1; break; } }
                        i += 1;
                    }
                    while i < bytes.len() && (bytes[i] == b'\n' || bytes[i].is_ascii_whitespace()) { i += 1; }
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

fn strip_top_level_container_rules(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut container_depth = 0usize;
    let mut result = String::with_capacity(input.len());
    while i < bytes.len() {
        if bytes[i] == b'@' {
            if input[i..].starts_with("@container") {
                let start_i = i;
                while i < bytes.len() && bytes[i] != b'{' { i += 1; }
                if i < bytes.len() && bytes[i] == b'{' { container_depth += 1; i += 1; }
                result.push_str(&input[start_i..i]);
                continue;
            }
        }
        if bytes[i] == b'}' {
            if container_depth > 0 { container_depth -= 1; }
            result.push('}');
            i += 1;
            continue;
        }
        if bytes[i] == b'.' && container_depth == 0 {
            if input[i+1..].starts_with("?@container") {
                while i < bytes.len() && bytes[i] != b'{' { i += 1; }
                if i < bytes.len() && bytes[i] == b'{' { i += 1; }
                let mut brace_depth = 1usize;
                while i < bytes.len() && brace_depth > 0 {
                    match bytes[i] { b'{' => brace_depth += 1, b'}' => brace_depth -= 1, _ => {} }
                    i += 1;
                }
                while i < bytes.len() && (bytes[i] == b'\n' || bytes[i] == b'\r' || bytes[i].is_ascii_whitespace()) {
                    if bytes[i] == b'\n' { result.push('\n'); i += 1; break; } else { i += 1; }
                }
                continue;
            }
        }
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
    sorted_class_names.sort_unstable(); // stable deterministic order

    let css_rules: Vec<String> = if sorted_class_names.len() < 512 {
        let refs: Vec<&str> = sorted_class_names.iter().map(|s| s.as_str()).collect();
        engine.generate_css_for_classes_batch(&refs)
    } else {
        // In production keep parallel generation for speed, then re-order deterministically.
        if is_production {
            const CHUNK: usize = 512;
            let mut pairs: Vec<(String, String)> = sorted_class_names
                .par_chunks(CHUNK)
                .flat_map_iter(|chunk| {
                    let refs: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
                    engine.generate_css_for_classes_batch(&refs)
                        .into_iter()
                        .zip(chunk.iter().map(|s| (*s).to_string()))
                        .map(|(css, name)| (name, css))
                        .collect::<Vec<_>>()
                })
                .collect();
            pairs.sort_by(|a,b| a.0.cmp(&b.0));
            pairs.into_iter().map(|(_, css)| css).collect()
        } else {
            // Deterministic serial generation in dev for stability.
            let refs: Vec<&str> = sorted_class_names.iter().map(|s| s.as_str()).collect();
            engine.generate_css_for_classes_batch(&refs)
        }
    };

    if css_rules.is_empty() {
        // Only write (or truncate) if file not already empty to avoid needless FS churn in dev.
        if is_production || !output_path.exists() || std::fs::metadata(output_path).map(|m| m.len() > 0).unwrap_or(true) {
            crate::utils::write_buffered(output_path, b"").expect("Failed to write empty CSS file");
        }
        return;
    }

    if is_production {
        let css_content = css_rules.join("\n\n");
        let stylesheet = StyleSheet::parse(&css_content, ParserOptions::default()).expect("Failed to parse CSS");
        let minified_css = stylesheet
            .to_css(PrinterOptions { minify: true, ..Default::default() })
            .expect("Failed to minify CSS");
        let normalized = normalize_generated_css(&minified_css.code);
        crate::utils::write_buffered(output_path, normalized.as_bytes()).expect("Failed to write minified CSS");
        return;
    }

    // DEV MODE: Do NOT format / pretty print. We emit deterministic rule blocks only once.
    // We still apply structural normalization that impacts correctness (selector cleanup),
    // but skip any cosmetic pretty printing.
    let mut content = String::with_capacity(css_rules.iter().map(|r| r.len()+2).sum());
    for (i, rule) in css_rules.iter().enumerate() {
        if i > 0 { content.push_str("\n\n"); }
        content.push_str(&normalize_generated_css(rule));
    }
    let content = condense_blank_lines(&content);

    // Skip rewrite if unchanged to preserve existing formatting (watch mode stability).
    if let Ok(existing) = std::fs::read_to_string(output_path) {
        if existing == content { return; }
    }
    crate::utils::write_buffered(output_path, content.as_bytes()).expect("Failed to write CSS file");
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
    let is_production = std::env::var("DX_ENV").map_or(false, |v| v == "production");
    let mut processed: Vec<String> = rules.into_iter().map(|r| normalize_generated_css(&r)).collect();
    if !is_production { for r in &mut processed { *r = condense_blank_lines(r); } }
    let estimated: usize = processed.iter().map(|r| r.len() + 2).sum::<usize>() + 4;
    let mut buffer = String::with_capacity(estimated);
    if need_leading { buffer.push('\n'); }
    for (i, rule) in processed.iter().enumerate() {
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
    _force_format: bool, // kept for backward compatibility; ignored in dev per requirements
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

    // Dev: ignore force_format (only format in prod per requirement). Produce deterministic blocks.
    let mut aggregate = String::with_capacity(joined.len() + 64);
    for (i, rule) in css_rules.iter().enumerate() {
        if i > 0 { aggregate.push_str("\n\n"); }
        aggregate.push_str(&normalize_generated_css(rule));
    }
    let aggregate = condense_blank_lines(&aggregate);

    // Skip write if unchanged.
    if let Ok(existing) = std::fs::read_to_string(output_path) {
        if existing == aggregate { return; }
    }
    let file = OpenOptions::new().create(true).write(true).truncate(true).open(output_path).expect("Failed to open CSS file for writing");
    let mut writer = BufWriter::new(file);
    writer.write_all(aggregate.as_bytes()).expect("write combined");
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
    let is_production = std::env::var("DX_ENV").map_or(false, |v| v == "production");
    let mut aggregate = String::with_capacity(rules.iter().map(|r| r.len()).sum::<usize>() + 64);
    for (i, r) in rules.iter().enumerate() {
        if i > 0 { aggregate.push_str("\n\n"); }
        aggregate.push_str(&normalize_generated_css(r));
    }
    let aggregate = if is_production { aggregate } else { condense_blank_lines(&aggregate) };
    writer.write_all(aggregate.as_bytes()).expect("write aggregated");
    writer.flush().expect("flush append");
}
