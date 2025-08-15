use crate::engine::StyleEngine;
use crate::interner::ClassInterner;
use lightningcss::stylesheet::{ParserOptions, PrinterOptions, StyleSheet};
use rayon::prelude::*;
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
        // Normalize selector by collapsing internal whitespace sequences to single spaces to ensure newline before brace doesn't block detection.
        let mut simple = String::with_capacity(sel.len());
        let mut last_ws = false;
        for ch in sel.chars() {
            if ch.is_whitespace() { if !last_ws { simple.push(' '); last_ws = true; } } else { simple.push(ch); last_ws = false; }
        }
        let mut trimmed = simple.trim();
        // If selector ends with an escaped grouping suffix like \\) strip everything from first \\(
        if let Some(idx) = trimmed.find("\\(") {
            trimmed = &trimmed[..idx];
        }
        if trimmed.contains(' ') { return false; }
        // Accept either the escaped variant prefix (list above) or its base name without the escaped group.
        VARIANTS.iter().any(|v| {
            if trimmed == *v || trimmed.starts_with(v) { return true; }
            // Derive base variant (strip trailing '\(' sequence)
            if let Some(base) = v.strip_suffix("\\(") { trimmed == base }
            else { false }
        })
    });

    // 3. Simplify local component groups ._name(...){ -> ._name { ... } (manual scan, no regex)
    out = simplify_local_component_groups(&out);

    // 3b. Simplify known public group patterns .card\(tokens\){ -> .card { ... }
    out = simplify_known_group_patterns(&out);

    // 3b2. Simplify parametric symbol utilities like .\~text\(values\){ -> .\~text { ... }
    out = simplify_parametric_symbol_groups(&out);

    // 3c. Simplify grouped parent selectors used only as a wrapper in child selectors:
    // e.g. .div\(h1\(font-bold\)\ p\(mt-2\)\) > h1 { ... } -> .div > h1 { ... }
    out = simplify_group_parents_in_complex_selectors(&out);

    // 4. Remove stray top-level conditional container group rules using existing structural scan.
    out = strip_top_level_container_rules(&out);

    // 4b. Inside @container blocks, expand grouped synthetic selectors
    // like .?@container>640px(bg-green-200\ text-green-900) -> .bg-green-200, .text-green-900
    out = expand_container_group_selectors(&out);

    // 4c. After expansion, remove any leftover synthetic container grouping selectors that failed to expand (safety cleanup)
    out = remove_selector_blocks(&out, |sel| {
        // Unescape one layer for matching
        let mut de = String::with_capacity(sel.len());
        let mut it = sel.chars().peekable();
        while let Some(c) = it.next() { if c == '\\' { if let Some(n) = it.next() { de.push(n); } } else { de.push(c); } }
        de.starts_with(".?@container>")
    });

    // 5. Final sanity: attempt parse / re-print; if it fails, continue with current string.
    // Use a cloned copy to avoid borrow issues when replacing `out`.
    if let Ok(parsed) = lightningcss::stylesheet::StyleSheet::parse(&out.clone(), lightningcss::stylesheet::ParserOptions::default()) {
        if let Ok(res) = parsed.to_css(lightningcss::stylesheet::PrinterOptions::default()) {
            out = res.code;
        }
    }

    // 6. Remove orphan selector lines (e.g. stray `.dark` left after pruning its grouped block).
    out = remove_orphan_selectors(&out);
    // 7. Final re-escape pass for any leading invalid identifier chars the printer may have emitted raw.
    out = reescape_leading_invalid_identifiers(&out);
    out
}

// Expand selectors of the synthetic form .?@container>SIZE(token\ token2\ ... ) found inside an @container at-rule
// into a comma-delimited list of the inner tokens as standalone class selectors.
fn expand_container_group_selectors(input: &str) -> String {
    // Don't early-return; pattern may be escaped already (e.g. .\?\@container>) after sanitization.
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    let mut last_copied = 0usize;
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
                                // Copy any intermediate content not yet copied
                                if sel_start > last_copied { out.push_str(&input[last_copied..sel_start]); }
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
                                last_copied = i;
                                continue; // skip default copy for consumed slice
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
        // Skip if next char starts a decimal number (e.g. .5rem, .25) to avoid escaping numeric literals inside declarations.
        if i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() { i += 1; continue; }
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
                    let mut char_index = 0usize;
                    while let Some(ch) = chars.next() {
                        if ch == '\\' { // keep existing escape and next char
                            sanitized.push(ch);
                            if let Some(nc) = chars.next() { sanitized.push(nc); }
                            char_index += 1;
                            continue;
                        }
                        let valid = matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_');
                        if !valid || (char_index == 0 && ch.is_ascii_digit()) {
                            needs_change = true;
                            sanitized.push('\\');
                        }
                        sanitized.push(ch);
                        char_index += 1;
                    }
                    // Hyphen-digit start needs escaping of the digit per CSS identifier rules
                    if ident.starts_with('-') {
                        if let Some(second) = ident.chars().nth(1) {
                            if second.is_ascii_digit() && !ident.starts_with("-\\") {
                                needs_change = true;
                                // Insert escape after hyphen.
                                let mut rebuilt = String::with_capacity(sanitized.len() + 2);
                                // sanitized already mirrors ident (with escapes). Find first occurrence of '-' followed by second
                                let mut done = false;
                                let mut iter = sanitized.chars().peekable();
                                while let Some(c) = iter.next() {
                                    rebuilt.push(c);
                                    if !done && c == '-' {
                                        if let Some(&peek) = iter.peek() { if peek == second { rebuilt.push('\\'); done = true; } }
                                    }
                                }
                                sanitized = rebuilt;
                            }
                        }
                    }
                    if needs_change {
                        out.push_str(&input[last_written..i+1]); // include '.'
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

// Manual simplification: ._name\(tokens\) { -> ._name {
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
            // Expect escaped '(' sequence after identifier
            if ident_end + 1 < bytes.len() && bytes[ident_end] == b'\\' && bytes[ident_end + 1] == b'(' {
                let mut j = ident_end + 2; // skip \(
                let mut closed = false;
                while j + 1 < bytes.len() {
                    if bytes[j] == b'\\' {
                        if j + 1 < bytes.len() && bytes[j + 1] == b')' { j += 2; closed = true; break; }
                        j += 2; continue;
                    }
                    if bytes[j] == b'{' { break; } // malformed grouping, abort
                    j += 1;
                }
                if closed {
                    // Skip whitespace until '{'
                    let mut k = j;
                    while k < bytes.len() && matches!(bytes[k], b' ' | b'\t' | b'\n' | b'\r') { k += 1; }
                    if k < bytes.len() && bytes[k] == b'{' {
                        // Emit preceding untouched segment
                        if i > last_emitted { out.push_str(&input[last_emitted..i]); }
                        // Emit simplified selector ._identifier {
                        out.push_str(&input[i..ident_end]); // ._name
                        out.push_str(" {");
                        i = k + 1; // move past '{'
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

// Simplify whitelisted public group selectors like .card\(p-4\ m-2\){ -> .card { ... }
fn simplify_known_group_patterns(input: &str) -> String {
    // Whitelist of identifiers that if followed by an escaped grouping suffix should be simplified.
    const NAMES: &[&str] = &["card", "transition", "mesh", "div", "from", "to", "text"]; // 'from'/'to' for potential custom grouping usage
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    let mut last_emitted = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' { // potential class selector
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
                    // Scan ahead for closing \) prior to '{'
                    let mut j = ident_end + 2; // after \(
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
                        // Skip ws to '{'
                        let mut k = j;
                        while k < bytes.len() && matches!(bytes[k], b' ' | b'\t' | b'\n' | b'\r') { k += 1; }
                        if k < bytes.len() && bytes[k] == b'{' {
                            if i > last_emitted { out.push_str(&input[last_emitted..i]); }
                            out.push_str(&input[i..ident_end]); // include '.' + name
                            out.push_str(" {");
                            i = k + 1; // advance past '{'
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

// Simplify parametric utilities beginning with an escaped leading symbol (e.g. .\~text\(min\@md, max\@xl\){ ) to just .\~text { ... }
fn simplify_parametric_symbol_groups(input: &str) -> String {
    const BASE_NAMES: &[&str] = &["text"]; // extendable
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    let mut last_emitted = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let dot = i;
            let mut cursor = i + 1;
            if cursor < bytes.len() && bytes[cursor] == b'\\' && cursor + 1 < bytes.len() {
                let sym = bytes[cursor + 1];
                if sym == b'~' { // candidate symbol
                    cursor += 2; // skip escape + symbol
                    let name_start = cursor;
                    while cursor < bytes.len() {
                        let c = bytes[cursor];
                        if matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_') { cursor += 1; continue; }
                        break;
                    }
                    if cursor > name_start && cursor + 1 < bytes.len() && bytes[cursor] == b'\\' && bytes[cursor + 1] == b'(' {
                        let base = &input[name_start..cursor];
                        if BASE_NAMES.iter().any(|n| *n == base) {
                            // Scan balanced grouping
                            let mut depth = 1i32; // we are after \(
                            let mut j = cursor + 2;
                            let mut closed = false;
                            while j + 1 < bytes.len() && depth > 0 {
                                if bytes[j] == b'\\' {
                                    if j + 1 < bytes.len() {
                                        let n = bytes[j + 1];
                                        if n == b'(' { depth += 1; j += 2; continue; }
                                        if n == b')' { depth -= 1; j += 2; if depth == 0 { closed = true; break; } continue; }
                                        j += 2; continue;
                                    } else { break; }
                                }
                                if bytes[j] == b'{' { break; }
                                j += 1;
                            }
                            if closed {
                                let mut k = j;
                                while k < bytes.len() && matches!(bytes[k], b' ' | b'\t' | b'\n' | b'\r') { k += 1; }
                                if k < bytes.len() && bytes[k] == b'{' {
                                    if dot > last_emitted { out.push_str(&input[last_emitted..dot]); }
                                    out.push_str(&input[dot..cursor]); // .\~text
                                    out.push_str(" {");
                                    i = k + 1;
                                    last_emitted = i;
                                    continue;
                                }
                            }
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

// Collapse parent grouping like .div\(h1\(font-bold\)\ p\(mt-2\)\) > h1 into .div > h1 while preserving the rest.
fn simplify_group_parents_in_complex_selectors(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    let mut last_emit = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' { // candidate start
            let name_start = i + 1;
            let mut name_end = name_start;
            // Allow escapes in name (like \*loading) but stop at first grouping or delimiter
            while name_end < bytes.len() {
                let c = bytes[name_end];
                if c == b'\\' {
                    if name_end + 1 >= bytes.len() { break; }
                    let next = bytes[name_end + 1];
                    // If next is '(' we reached grouping start; do not consume
                    if next == b'(' { break; }
                    // Otherwise treat escaped char as part of name
                    name_end += 2; continue;
                }
                if matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'*') { name_end += 1; continue; }
                break;
            }
            // Expect escaped '(' starting a grouping right after name
            if name_end + 1 < bytes.len() && bytes[name_end] == b'\\' && bytes[name_end + 1] == b'(' {
                // Scan balanced escaped parens depth-aware
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
                    if matches!(bytes[j], b'{' | b'\n') { break; } // abort - not a pure grouping before block/combinator
                    j += 1;
                }
                if valid {
                    let group_end = j; // j positioned after processing closing \")" (points to index after the backslash? ensure adjustment)
                    // Move group_end forward past the final escaped ) if not already
                    let mut group_after = group_end;
                    // Skip any whitespace after group
                    while group_after < bytes.len() && bytes[group_after].is_ascii_whitespace() { group_after += 1; }
                    // Peek ahead after any whitespace
                    let mut k = group_after;
                    if k < bytes.len() {
                        let next = bytes[k];
                        // Only collapse when followed by combinator/attribute/child context, NOT '{' (block handled earlier)
                        if matches!(next, b'>' | b'+' | b'~' | b'[') || next.is_ascii_alphanumeric() || next == b'.' || next == b'#' {
                            // Emit preceding slice, then simplified .<name>
                            if i > last_emit { out.push_str(&input[last_emit..i]); }
                            out.push_str(&input[i..name_end]); // includes '.' prefix and full name (with escapes)
                            last_emit = group_after; // we drop the grouping tokens
                            i = group_after; // continue scanning from after group
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
    // Secondary coarse pass: collapse any residual .ident\( ... \) > pattern not handled (no nested braces inside)
    let mut coarse = String::with_capacity(out.len());
    let mut idx = 0usize;
    let ob = out.as_bytes();
    while idx < ob.len() {
        if ob[idx] == b'.' {
            let start = idx;
            let mut k = idx + 1;
            while k < ob.len() && (ob[k].is_ascii_alphanumeric() || matches!(ob[k], b'-' | b'_' | b'*' | b'\\')) {
                if ob[k] == b'\\' && k + 1 < ob.len() && ob[k+1] == b'(' { break; }
                k += 1;
            }
            if k + 1 < ob.len() && ob[k] == b'\\' && ob[k+1] == b'(' {
                // Find \") >" sequence
                if let Some(rel) = out[k..].find("\\) >") {
                    let close_idx = k + rel; // position of '\' before ')'
                    // Confirm there's no '{' between k and close_idx
                    if !out[k..close_idx].contains('{') {
                        // Emit prefix
                        coarse.push_str(&out[idx..k]);
                        coarse.push_str(" >");
                        idx = close_idx + 3; // skip '\) >'
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

// Re-escape any class selector whose first ident char would make the selector invalid if unescaped.
// We target edge cases where the printer normalized escapes away (e.g., leading '*', '%', '~', '#', '+', '/', or digit).
fn reescape_leading_invalid_identifiers(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut last_copy = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let start = i + 1;
            if start >= bytes.len() { break; }
            // Skip decimal numeric literal like .5rem or .75% inside declarations
            if bytes[start].is_ascii_digit() { i += 1; continue; }
            // Peek at first char (could be escape already)
            if bytes[start] == b'\\' { i += 1; continue; } // already escaped ident start
            let ch = bytes[start] as char;
            let needs_escape = match ch {
                'a'..='z' | 'A'..='Z' | '_' => false,
                '-' => { // '-digit' requires escape of digit; handle separately below
                    if start + 1 < bytes.len() {
                        let next = bytes[start + 1] as char;
                        next.is_ascii_digit()
                    } else { false }
                }
                _ => true,
            } || ch.is_ascii_digit();
            if needs_escape {
                // emit prior content then escaped char
                if i > last_copy { out.push_str(&input[last_copy..i+1]); } // include '.'
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

// Generic helper to remove complete selector blocks where predicate(selector) == true.
// Supports simple one-level blocks (it won't cross @media etc incorrectly because it balances braces).
fn remove_selector_blocks<F: Fn(&str) -> bool>(input: &str, predicate: F) -> String {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(input.len());
    while i < bytes.len() {
        if bytes[i] == b'.' { // potential class selector start
            let sel_start = i; // remember where selector started
            let mut j = i;
            // Move j until we hit '{' or a hard terminator for selector.
            while j < bytes.len() && bytes[j] != b'{' && bytes[j] != b'\n' { j += 1; }
            let mut brace_pos: Option<usize> = None;
            let mut selector_end = j; // end of selector slice (exclusive) ignoring trailing ws
            if j < bytes.len() && bytes[j] == b'{' { brace_pos = Some(j); }
            else if j < bytes.len() && bytes[j] == b'\n' {
                // Look ahead for '{' across whitespace/newlines
                let mut k = j + 1;
                while k < bytes.len() {
                    if bytes[k] == b'{' { brace_pos = Some(k); selector_end = j; break; }
                    if !bytes[k].is_ascii_whitespace() { break; }
                    k += 1;
                }
            }
            if let Some(bpos) = brace_pos {
                // selector span from sel_start to selector_end (exclude trailing whitespace/newlines before brace)
                let mut selector = &input[sel_start..selector_end];
                // Trim trailing whitespace
                while selector.ends_with(|c: char| c.is_whitespace()) { selector = selector.trim_end(); }
                // If selector contains an escaped group e.g. .hover\(foo\ bar\) truncate at first \(
                if let Some(group_idx) = selector.find("\\(") { selector = &selector[..group_idx]; }
                let selector = selector.trim_end();
                if predicate(selector) {
                    // Skip balanced block beginning at bpos
                    i = bpos; // position at '{'
                    let mut depth = 0usize;
                    while i < bytes.len() {
                        if bytes[i] == b'{' { depth += 1; }
                        else if bytes[i] == b'}' { depth -= 1; if depth == 0 { i += 1; break; } }
                        i += 1;
                    }
                    while i < bytes.len() && (bytes[i] == b'\n' || bytes[i].is_ascii_whitespace()) { i += 1; }
                    continue; // removed block
                }
                // Not removed: reset i to sel_start so normal copy proceeds char by char
                i = sel_start;
            } else {
                i = sel_start; // no brace found; fall through
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
            // Skip synthetic container artifact lines e.g. .\?\\\@container>
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

    #[test]
    fn simplifies_local_component_group() {
        let input = "._highlight\\(bg-yellow-200\\ text-yellow-900\\){color:red;}";
        let out = normalize_generated_css(input);
        assert!(out.contains("._highlight {"), "Expected simplified selector, got: {out}");
        assert!(!out.contains("_highlight\\(bg"), "Grouping suffix should be removed: {out}");
    }

    #[test]
    fn removes_variant_block_with_newline_before_brace() {
        // Selector line break before opening brace should still be pruned
        let input = ".hover\\(bg-blue-600\\ shadow-lg\\)\n{color:red;}\n.ok{a:b;}";
        let out = normalize_generated_css(input);
        assert!(!out.contains(".hover\\(bg-blue-600"), "Variant wrapper block should be removed even with newline before brace: {out}");
        assert!(out.contains(".ok"));
    }

    #[test]
    fn reescapes_leading_invalid_identifier_chars() {
        // Leading '*' should be escaped after normalization if printer emits it raw
        let input = ".*loading(bg-gray-400){color:red;}";
        let out = normalize_generated_css(input);
        assert!(out.contains(".\\*loading"), "Expected leading '*' to be escaped: {out}");
    }

    #[test]
    fn simplifies_known_group_pattern() {
        let input = ".card\\(p-4\\ m-2\\){color:red;}";
        let out = normalize_generated_css(input);
        assert!(out.contains(".card {"), "Expected simplified .card selector: {out}");
        assert!(!out.contains(".card\\(p-4"), "Grouped pattern suffix should be removed: {out}");
    }

    #[test]
    fn reescapes_other_leading_invalid_chars() {
    let input = ".%percent{width:10px;}\n.~tilde{color:red;}\n.+plus{color:blue;}";
        let out = normalize_generated_css(input);
    assert!(out.contains(".\\%percent"), "Expected % escape: {out}");
    assert!(out.contains(".\\~tilde"), "Expected ~ escape: {out}");
    assert!(out.contains(".\\+plus"), "Expected + escape: {out}");
    }

    #[test]
    fn does_not_escape_decimal_literals() {
        let input = ".opacity-75{opacity:.75;}\n.font-size{font-size:1.25rem;}";
        let out = normalize_generated_css(input);
    assert!(out.contains("opacity: .75") || out.contains("opacity:.75"), "Decimal literal .75 should remain (allow spacing): {out}");
    assert!(out.contains("font-size: 1.25rem") || out.contains("font-size:1.25rem"), "Decimal 1.25rem should remain: {out}");
    assert!(!out.contains("opacity:\\.75"), "Should not escape decimal point: {out}");
    }

    #[test]
    fn simplifies_group_parent_in_child_selector() {
        let input = ".div\\(div\\(mt-4\\)\\) > div{margin-top:1rem;}";
        let out = normalize_generated_css(input);
        assert!(out.contains(".div > div"), "Expected collapsed parent group: {out}");
        assert!(!out.contains("div\\(mt-4"), "Grouping tokens should be removed: {out}");
    }

    #[test]
    fn simplifies_group_parent_with_multiple_children() {
        let input = ".div\\(h1\\(font-bold\\)\\ p\\(mt-2\\)\\) > h1{font-weight:700;} .div\\(h1\\(font-bold\\)\\ p\\(mt-2\\)\\) > p{margin-top:.5rem;}";
        let out = normalize_generated_css(input);
        assert!(out.contains(".div > h1"), "h1 selector collapsed: {out}");
        assert!(out.contains(".div > p"), "p selector collapsed: {out}");
        assert!(!out.contains("p\\(mt-2"), "Inner grouping removed: {out}");
    }

    #[test]
    fn simplifies_parametric_symbol_group() {
        let input = ".\\~text\\(2.25rem\\@md,\\ 3rem\\@xl\\){font-size:clamp(2.25rem, calc(2.25rem + 0.75 * (100vw - 768px) / (1280 - 768)), 3rem);}";
        let out = normalize_generated_css(input);
    assert!(out.contains(".\\~text {") || out.contains(".\\~text{"), "Expected simplified parametric symbol group: {out}");
        assert!(!out.contains("~text\\(2.25rem"), "Grouping suffix should be removed: {out}");
    }
}
