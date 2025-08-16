use lru::LruCache;
use std::collections::HashMap;
use smallvec::SmallVec;
use rayon::prelude::*;
use std::fs;
use std::num::NonZeroUsize;
use std::sync::{Mutex, RwLock};
use std::sync::Arc;
use cssparser::serialize_identifier;
use std::fmt; // for serialize_identifier target impl

mod styles_generated {
    #![allow(
        dead_code,
        unused_imports,
        unsafe_op_in_unsafe_fn,
        mismatched_lifetime_syntaxes
    )]
    include!(concat!(env!("OUT_DIR"), "/styles_generated.rs"));
}
use styles_generated::style_schema;
use crate::composites;

#[derive(Default)]
struct PendingAnimation {
    duration: String,
    delay: String,
    fill_mode: String,
    from: Vec<String>,
    via: Vec<String>,
    to_: Vec<String>,
    has_main: bool,
}

pub struct StyleEngine {
    precompiled: HashMap<String, String>,
    buffer: Vec<u8>,
    screens: HashMap<String, String>,
    states: HashMap<String, String>,
    container_queries: HashMap<String, String>,
    colors: HashMap<String, String>,
    animation_templates: HashMap<String, String>,
    css_cache: Mutex<LruCache<u32, Arc<String>>>,
    precomputed: RwLock<Option<Arc<Vec<Option<Arc<String>>>>>>,
}

impl StyleEngine {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let buffer = fs::read(".dx/styles.bin")?;
        let config = flatbuffers::root::<style_schema::Config>(&buffer)
            .map_err(|e| format!("Failed to parse styles.bin: {}", e))?;

        let mut precompiled = HashMap::new();
        if let Some(styles) = config.styles() {
            for style in styles {
                let name = style.name();
                let css = style.css();
                if !name.is_empty() && !css.is_empty() {
                    precompiled.insert(
                        name.to_string(),
                        css.trim_end().trim_end_matches(';').to_string(),
                    );
                }
            }
        }

        if let Some(dynamics) = config.dynamics() {
            for dynamic in dynamics {
                if let Some(values) = dynamic.values() {
                    for value in values {
                        let key = dynamic.key();
                        let suffix = value.suffix();
                        let property = dynamic.property();
                        let value_str = value.value();

                        let name = if suffix.is_empty() {
                            key.to_string()
                        } else {
                            format!("{}-{}", key, suffix)
                        };
                        if !name.is_empty() {
                            let css = format!(
                                "{}: {}",
                                property,
                                value_str.trim_end().trim_end_matches(';')
                            );
                            precompiled.insert(name, css);
                        }
                    }
                }
            }
        }

        let screens = config.screens().map_or_else(HashMap::new, |s| {
            s.iter()
                .map(|screen| (screen.name().to_string(), screen.value().to_string()))
                .collect()
        });

        let states = config.states().map_or_else(HashMap::new, |s| {
            s.iter()
                .map(|state| (state.name().to_string(), state.value().to_string()))
                .collect()
        });

        let container_queries =
            config.container_queries().map_or_else(HashMap::new, |c| {
                c.iter()
                    .map(|cq| (cq.name().to_string(), cq.value().to_string()))
                    .collect()
            });

        let colors = config.colors().map_or_else(HashMap::new, |c| {
            c.iter()
                .map(|color| (color.name().to_string(), color.value().to_string()))
                .collect()
        });

        let animation_templates = config.animation_generators().map_or_else(HashMap::new, |a| {
            a.iter()
                .map(|ag| (ag.name().to_string(), ag.template().to_string()))
                .collect()
        });

        Ok(Self {
            precompiled,
            buffer,
            screens,
            states,
            container_queries,
            colors,
            animation_templates,
            css_cache: Mutex::new(LruCache::new(NonZeroUsize::new(8192).unwrap())),
            precomputed: RwLock::new(None),
        })
    }

    #[allow(dead_code)]
    pub fn prewarm(&self, interner: &crate::interner::ClassInterner) {
        let len = interner.len();
        let mut vec: Vec<Option<Arc<String>>> = Vec::with_capacity(len);
        for id in 0..len {
            let id_u32 = id as u32;
            let raw = interner.get(id_u32).to_string();
            let esc = interner.escaped(id_u32).to_string();
            if let Some(css) = self.compute_css_from_raw_and_escaped(&raw, &esc) {
                vec.push(Some(Arc::new(css)));
            } else {
                vec.push(None);
            }
        }
        let arc = Arc::new(vec);
        let mut w = self.precomputed.write().unwrap();
        *w = Some(arc);
    }

    pub fn ensure_prewarm(&self, interner: &crate::interner::ClassInterner) {
        let current_len_opt = {
            let r = self.precomputed.read().unwrap();
            match &*r { Some(pre) => Some(pre.len()), None => None }
        };
        match current_len_opt {
            None => {
                self.prewarm(interner);
            }
            Some(existing) => {
                let target = interner.len();
                if target > existing {
                    let mut w = self.precomputed.write().unwrap();
                    if let Some(pre_arc) = &mut *w {
                        let current_len = pre_arc.len();
                        if current_len < target {
                            let vec_mut = Arc::make_mut(pre_arc);
                            for id in current_len..target {
                                let id_u32 = id as u32;
                                let raw = interner.get(id_u32);
                                let esc = interner.escaped(id_u32);
                                if let Some(css) = self.compute_css_from_raw_and_escaped(raw, esc) {
                                    vec_mut.push(Some(Arc::new(css)));
                                } else {
                                    vec_mut.push(None);
                                }
                            }
                        }
                    } else {
                        drop(w);
                        self.prewarm(interner);
                    }
                }
            }
        }
    }

    fn compute_css(&self, class_name: &str) -> Option<String> {
        // Skip standalone animation stage utility classes (from(...), to(...), via(...)) so they don't emit empty rules.
        if class_name.starts_with("from(") || class_name.starts_with("to(") || class_name.starts_with("via(") {
            return None;
        }
        let mut last_colon = None;
        for (i, b) in class_name.as_bytes().iter().enumerate() {
            if *b == b':' { last_colon = Some(i); }
        }
        let (prefix_segment, base_class) = if let Some(idx) = last_colon {
            (&class_name[..idx], &class_name[idx+1..])
        } else {
            ("", class_name)
        };

        let mut media_queries: SmallVec<[String; 4]> = SmallVec::new();
        let mut pseudo_classes = String::new();
        let mut wrappers: SmallVec<[String; 2]> = SmallVec::new();

        if !prefix_segment.is_empty() {
            for part in prefix_segment.split(':') {
                if let Some(screen_value) = self.screens.get(part) {
                    media_queries.push(format!("@media (min-width: {})", screen_value));
                } else if let Some(cq_value) = self.container_queries.get(part) {
                    media_queries.push(format!("@container (min-width: {})", cq_value));
                } else if let Some(state_value) = self.states.get(part) {
                    if state_value.contains('&') { wrappers.push(state_value.to_string()); } else { pseudo_classes.push_str(state_value); }
                } else if part == "dark" {
                    wrappers.push(".dark &".to_string());
                } else if part == "light" {
                    wrappers.push(":root &".to_string());
                }
            }
        }

        let core_css_raw = self
            .precompiled
            .get(base_class)
            .cloned()
            .or_else(|| self.generate_color_css(base_class))
            .or_else(|| self.generate_animation_css(class_name))
            .or_else(|| self.generate_dynamic_css(base_class))
            .or_else(|| self.expand_composite(base_class));
        core_css_raw.map(|mut css| {
            css = sanitize_declarations(&css);
            // Build escaped selector using cssparser just like interner.
            let mut escaped_ident = String::with_capacity(class_name.len() + 8);
            struct Acc<'a> { buf: &'a mut String }
            impl<'a> fmt::Write for Acc<'a> { fn write_str(&mut self, s:&str)->fmt::Result { self.buf.push_str(s); Ok(()) } }
            if serialize_identifier(class_name, &mut Acc { buf: &mut escaped_ident }).is_err() {
                // Fallback: minimal legacy escaping
                for ch in class_name.chars() {
                    match ch { ':'=>escaped_ident.push_str("\\:"), '@'=>escaped_ident.push_str("\\@"), '('=>escaped_ident.push_str("\\("), ')'=>escaped_ident.push_str("\\)"), ' '=>escaped_ident.push_str("\\ "), '/' => escaped_ident.push_str("\\/"), '\\'=>escaped_ident.push_str("\\\\"), _=>escaped_ident.push(ch) }
                }
            }
            let mut selector = String::with_capacity(escaped_ident.len() + pseudo_classes.len() + 2);
            selector.push('.');
            selector.push_str(&escaped_ident);
            selector.push_str(&pseudo_classes);
            let blocks = self.decode_encoded_css(&css, &selector, &wrappers);
            self.wrap_media_queries(blocks, &media_queries)
        })
    }

    #[allow(dead_code)]
    fn compute_css_id(&self, id: u32, interner: &crate::interner::ClassInterner) -> Option<String> {
        let class_name = interner.get(id);
        let esc = interner.escaped(id);
        self.compute_css_from_raw_and_escaped(class_name, esc)
    }

    fn compute_css_from_raw_and_escaped(&self, class_name: &str, escaped: &str) -> Option<String> {
    if class_name.starts_with("from(") || class_name.starts_with("to(") || class_name.starts_with("via(") { return None; }
        // Container grouping syntax: ?@container>SIZE(utilA utilB ...)
        // Required behavior: single rule inside @container with the FULL escaped grouping selector.
        if class_name.starts_with("?@container>") && class_name.contains('(') && class_name.ends_with(')') {
            if let Some(block) = self.generate_container_group(class_name, escaped) { return Some(block); }
        }
        let last_colon = class_name.rfind(':');
        let (prefix_segment, base_class) = if let Some(idx) = last_colon {
            (&class_name[..idx], &class_name[idx + 1..])
        } else {
            ("", class_name)
        };

    let mut media_queries: SmallVec<[String; 4]> = SmallVec::new();
    let mut pseudo_classes = String::new();
    let mut wrappers: SmallVec<[String; 2]> = SmallVec::new();

        if !prefix_segment.is_empty() {
            for part in prefix_segment.split(':') {
                if let Some(screen_value) = self.screens.get(part) {
                    media_queries.push(format!("@media (min-width: {})", screen_value));
                } else if let Some(cq_value) = self.container_queries.get(part) {
                    media_queries.push(format!("@container (min-width: {})", cq_value));
                } else if let Some(state_value) = self.states.get(part) {
                    if state_value.contains('&') { wrappers.push(state_value.to_string()); } else { pseudo_classes.push_str(state_value); }
                } else if part == "dark" {
                    wrappers.push(".dark &".to_string());
                } else if part == "light" {
                    wrappers.push(":root &".to_string());
                }
            }
        }

        let core_css_raw = self
            .precompiled
            .get(base_class)
            .cloned()
            .or_else(|| self.generate_color_css(base_class))
            .or_else(|| self.generate_animation_css(class_name))
            .or_else(|| self.generate_dynamic_css(base_class))
            .or_else(|| self.expand_composite(base_class));
        core_css_raw.map(|mut css| {
            css = sanitize_declarations(&css);
            let mut selector = String::with_capacity(escaped.len() + pseudo_classes.len() + 1);
            selector.push('.');
            // Treat provided 'escaped' as mostly sanitized; only ensure single escaping for ':' and '@'.
            let mut prev_src_char: Option<char> = None;
            for ch in escaped.chars() {
                match ch {
                    ':' => {
                        if prev_src_char != Some('\\') { selector.push_str("\\:"); } else { selector.push(':'); }
                    }
                    '@' => {
                        if prev_src_char != Some('\\') { selector.push_str("\\@"); } else { selector.push('@'); }
                    }
                    _ => selector.push(ch)
                }
                prev_src_char = Some(ch);
            }
            selector.push_str(&pseudo_classes);
            let blocks = self.decode_encoded_css(&css, &selector, &wrappers);
            self.wrap_media_queries(blocks, &media_queries)
        })
    }

    // Build aggregated container query block for grouping classes of the form:
    // ?@container>640px(bg-green-200 text-green-900)
    // Output:
    // @container (min-width: 640px) {
    //   .\?\@container\>640px\(bg-green-200\ text-green-900\) { <merged decls> }
    // }
    fn generate_container_group(&self, raw: &str, escaped_selector: &str) -> Option<String> {
        const PREFIX: &str = "?@container>";
        let after_prefix = &raw[PREFIX.len()..];
        let paren_idx = after_prefix.find('(')?;
        let size_part = after_prefix[..paren_idx].trim();
        if size_part.is_empty() { return None; }
        let inner_raw = after_prefix[paren_idx+1..].strip_suffix(')')?;
        // Normalize size: allow bare number or with px. If user supplies expression keep as-is.
        let size_expr = if size_part.chars().all(|c| c.is_ascii_digit()) {
            format!("{}px", size_part)
        } else if size_part.ends_with("px") || size_part.contains(|c: char| c == ' ' || c == '(' || c == ')') {
            size_part.to_string()
        } else {
            // Assume px if trailing alpha not present
            size_part.to_string()
        };
        // Split utilities inside parentheses by whitespace
        let inner_utils: Vec<&str> = inner_raw.split(|c: char| c.is_whitespace()).filter(|s| !s.is_empty()).collect();
        if inner_utils.is_empty() { return None; }
        use std::collections::HashMap;
        let mut decls: HashMap<String, (usize, String)> = HashMap::new();
        let mut order: usize = 0;
        for util in &inner_utils {
            if let Some(raw_css) = self.compute_css(util) { // recursive compute existing utility
                // Extract declarations from first block only
                if let Some(open) = raw_css.find('{') { if let Some(close) = raw_css.find('}') { if close > open {
                    let body = &raw_css[open+1..close];
                    for seg in body.split(';') {
                        let seg = seg.trim(); if seg.is_empty() { continue; }
                        if let Some(colon) = seg.find(':') {
                            let prop = seg[..colon].trim().to_string();
                            let value = seg[colon+1..].trim().trim_end_matches(';').to_string();
                            decls.insert(prop, (order, value));
                            order += 1;
                        }
                    }
                }}}
            }
        }
        if decls.is_empty() { return None; }
        let mut ordered: Vec<(String, (usize, String))> = decls.into_iter().collect();
        ordered.sort_by_key(|(_, (ord, _))| *ord);
        let mut body = String::new();
        for (prop, (_, val)) in ordered { body.push_str("    "); body.push_str(&prop); body.push_str(": "); body.push_str(&val); body.push_str(";\n"); }
        let mut out = String::with_capacity(body.len() + escaped_selector.len() + 64);
        out.push_str("@container (min-width: "); out.push_str(&size_expr); out.push_str(") {\n  .");
        out.push_str(escaped_selector); out.push_str(" {\n");
        out.push_str(&body);
        out.push_str("  }\n}\n");
        Some(out)
    }

    fn expand_composite(&self, class_name: &str) -> Option<String> {
        // New direct syntax mapping: grouping expressions are stored verbatim.
        // Try direct lookup; if not found fall back to legacy hashed naming.
        let comp = if let Some(c) = composites::get(class_name) {
            c
        } else if class_name.starts_with("dx-class-") {
            composites::get(class_name)?
        } else {
            return None;
        };
        let resolve_tokens = |tokens: &[String]| -> Vec<String> {
            let mut out = Vec::new();
            for t in tokens {
                if let Some(rest) = t.strip_prefix("animfill:") { // carry fill mode into animation system via ANIM line
                    out.push(format!("ANIM|fill|{}", rest));
                    continue;
                }
                if let Some(rest) = t.strip_prefix("fluid:") {
                    let parts: Vec<&str> = rest.split(':').collect();
                    if parts.len() >= 5 { // fluid:prop:min:minBp:max:maxBp
                        let prop = parts[0];
                        let min_v = parts[1];
                        let min_bp_key = parts[2];
                        let max_v = parts[3];
                        let max_bp_key = parts[4];
                        let lookup_bp = |key: &str| -> Option<f32> {
                            if key.chars().all(|c| c.is_ascii_digit()) { return key.parse::<f32>().ok(); }
                            self.screens.get(key).and_then(|v| {
                                if let Some(px) = v.strip_suffix("px") { px.parse().ok() } else { None }
                            })
                        };
                        if let (Some(min_bp), Some(max_bp)) = (lookup_bp(min_bp_key), lookup_bp(max_bp_key)) {
                            let parse_val = |val: &str| -> Option<f32> {
                                let digits: String = val.chars().take_while(|c| (c.is_ascii_digit() || *c == '.')).collect();
                                digits.parse().ok()
                            };
                            if let (Some(min_num), Some(max_num)) = (parse_val(min_v), parse_val(max_v)) {
                                let formula = format!("clamp({}, calc({} + {} * (100vw - {}px) / ({} - {})), {})", min_v, min_v, (max_num - min_num), min_bp, max_bp, min_bp, max_v);
                                out.push(format!("{}: {}", prop, formula));
                                continue;
                            }
                        }
                        out.push(format!("{}: clamp({}, {}, {})", prop, min_v, min_v, max_v));
                        continue;
                    }
                } else if let Some(rest) = t.strip_prefix("motion:") {
                    let hash = format!("{:x}", seahash::hash(rest.as_bytes()));
                    let kf_name = format!("dx-motion-keyframe-{}", &hash[..6]);
                    let mut keyframes = String::from("@keyframes "); keyframes.push_str(&kf_name); keyframes.push_str(" {\n  0% { transform: translateY(0) scale(1); }\n  60% { transform: translateY(-6px) scale(1.04); }\n  80% { transform: translateY(2px) scale(0.98); }\n  100% { transform: translateY(0) scale(1); }\n}\n");
                    out.push(format!("animation: {} 600ms cubic-bezier(0.34,1.56,0.64,1)", kf_name));
                    out.push(keyframes); // Will be emitted as RAW block
                    continue;
                } else if let Some(rest) = t.strip_prefix("gradient:mesh:") {
                    let colors: Vec<&str> = rest.split('+').filter(|c| !c.trim().is_empty()).collect();
                    if colors.len() >= 2 {
                        let phi = std::f32::consts::PI * (3.0 - (5.0_f32).sqrt());
                        let mut layers: Vec<String> = Vec::new();
                        let n = colors.len() as f32;
                        for (i, c) in colors.iter().enumerate() {
                            let i_f = i as f32 + 0.5;
                            let r = i_f / n; // radius fraction
                            let theta = i_f * phi;
                            let x = 50.0 + r * 40.0 * theta.cos();
                            let y = 50.0 + r * 40.0 * theta.sin();
                            let sz = 120.0 - r * 40.0;
                            layers.push(format!("radial-gradient(circle at {:.1}% {:.1}%, {} {:.0}%)", x, y, c.trim(), sz.max(25.0)));
                        }
                        out.push(format!("background-image: {}", layers.join(", ")));
                        out.push("background-size: cover".to_string());
                        out.push("background-blend-mode: screen, lighten".to_string());
                    }
                    continue;
                }
                if let Some(rule) = self.precompiled.get(t) { out.push(rule.clone()); }
                else if let Some(c) = self.generate_color_css(t) { out.push(c); }
                else if let Some(d) = self.generate_dynamic_css(t) { out.push(d); }
                else if let Some(a) = self.generate_animation_css(t) { out.push(a); }
            }
            out
        };

        let mut sections: Vec<String> = Vec::new();
        let base = resolve_tokens(&comp.base).join("; ");
        if !base.is_empty() { sections.push(format!("BASE|{}", base)); }
        for (child, toks) in &comp.child_rules { let decls = resolve_tokens(toks).join("; "); if !decls.is_empty() { sections.push(format!("CHILD|{}|{}", child, decls)); } }
        for (state, toks) in &comp.state_rules { let decls = resolve_tokens(toks).join("; "); if !decls.is_empty() { sections.push(format!("STATE|{}|{}", state, decls)); } }
        for (attr, toks) in &comp.data_attr_rules { let decls = resolve_tokens(toks).join("; "); if !decls.is_empty() { sections.push(format!("DATA|{}|{}", attr, decls)); } }
        for (cond, toks) in &comp.conditional_blocks { let decls = resolve_tokens(toks).join("; "); if !decls.is_empty() { sections.push(format!("COND|{}|{}", cond, decls)); } }
        // Animation lines stored in comp.animations use parser formats:
        //   animate: utility encoded earlier as base token (animate:duration[:delay]) -> handled via generate_animation_css
        //   from|token+token  / to|token+token / via|token+token  (stage declarations)
        //   animfill:forwards stored in base tokens -> already in comp.base as animfill:forwards
    for anim in &comp.animations {
            // Prefix with ANIM| <type>|<decls-or-metadata>
            sections.push(format!("ANIM|{}", anim));
        }
        for raw in &comp.extra_raw { sections.push(format!("RAW|{}", raw)); }
        if sections.is_empty() { return None; }
        Some(sections.join("\n"))
    }

    #[allow(dead_code)]
    pub fn generate_css_for_classes_batch<'a>(&self, class_names: &[&'a str]) -> Vec<String> {
        let mut out = Vec::with_capacity(class_names.len());
        for &name in class_names { if let Some(css)= self.compute_css(name) { out.push(css); } }
        out
    }

    pub fn generate_css_for_ids(&self, ids: &[u32], interner: &crate::interner::ClassInterner) -> Vec<Arc<String>> {
        {
            let r = self.precomputed.read().unwrap();
            if r.is_some() {
                let max_id = ids.iter().copied().max();
                if let (Some(pre), Some(max_id)) = (r.as_ref(), max_id) {
                    if (max_id as usize) >= pre.len() { drop(r); self.ensure_prewarm(interner); }
                }
            }
        }
        if let Some(pre) = self.precomputed.read().unwrap().as_ref() {
            let mut out: Vec<Arc<String>> = Vec::with_capacity(ids.len());
            for &id in ids {
                let idx = id as usize;
                if idx < pre.len() { if let Some(a) = &pre[idx] { out.push(Arc::clone(a)); } }
            }
            return out;
        }

        let mut result_slots: Vec<Option<Arc<String>>> = vec![None; ids.len()];
        let mut misses: Vec<(usize, u32)> = Vec::new();

        {
            let mut cache = self.css_cache.lock().unwrap();
            for (idx, &id) in ids.iter().enumerate() {
                if let Some(c) = cache.get(&id) {
                    result_slots[idx] = Some(Arc::clone(c));
                } else {
                    misses.push((idx, id));
                }
            }
        }

        if !misses.is_empty() {
            let miss_sources: Vec<(usize, u32, String, String)> = misses
                .iter()
                .map(|(idx, id)| (*idx, *id, interner.get(*id).to_string(), interner.escaped(*id).to_string()))
                .collect();

            let computed: Vec<(usize, Arc<String>)> = miss_sources
                .into_par_iter()
                .filter_map(|(idx, _id, raw, esc)| {
                    self.compute_css_from_raw_and_escaped(&raw, &esc).map(|css| (idx, Arc::new(css)))
                })
                .collect();

            let mut cache = self.css_cache.lock().unwrap();
            for (idx, css_arc) in &computed {
                cache.put(ids[*idx], Arc::clone(css_arc));
                result_slots[*idx] = Some(Arc::clone(css_arc));
            }
        }

        result_slots.into_iter().filter_map(|opt| opt).collect()
    }

    fn generate_dynamic_css(&self, class_name: &str) -> Option<String> {
        // Special meta utility: transition(<duration>) sets standard transition props.
        if let Some(arg) = class_name.strip_prefix("transition(") {
            if let Some(end) = arg.find(')') {
                let dur = &arg[..end];
                let duration = if dur.is_empty() { "150ms" } else { dur };
                return Some(format!("transition-property: all; transition-duration: {}; transition-timing-function: cubic-bezier(0.4,0,0.2,1)", duration));
            }
        }
        let config = flatbuffers::root::<style_schema::Config>(&self.buffer).ok()?;
        if let Some(generators) = config.generators() {
            for generator in generators {
                let prefix = generator.prefix();
                let property = generator.property();
                let unit = generator.unit();

                if class_name.starts_with(&format!("{}-", prefix)) {
                    let value_str = &class_name[prefix.len() + 1..];
                    let (value_str, is_negative) =
                        if let Some(stripped) = value_str.strip_prefix('-') {
                            (stripped, true)
                        } else {
                            (value_str, false)
                        };

                    let num_val: f32 = if value_str.is_empty() {
                        1.0
                    } else if let Ok(num) = value_str.parse::<f32>() {
                        num
                    } else {
                        continue;
                    };

                    let final_value =
                        num_val * generator.multiplier() * if is_negative { -1.0 } else { 1.0 };
                    let css_value = if unit.is_empty() {
                        format!("{}", final_value)
                    } else {
                        format!("{}{}", final_value, unit)
                    };
                    return Some(format!("{}: {}", property, css_value));
                }
            }
        }

        None
    }

    fn generate_color_css(&self, class_name: &str) -> Option<String> {
        if let Some(name) = class_name.strip_prefix("bg-") {
            if let Some(val) = self.colors.get(name) { return Some(format!("background-color: {}", val)); }
        }
        if let Some(name) = class_name.strip_prefix("text-") {
            if let Some(val) = self.colors.get(name) { return Some(format!("color: {}", val)); }
        }
        None
    }

    fn generate_animation_css(&self, full_class: &str) -> Option<String> {
    // Only handle animate:duration[:delay] utility; do not emit frames here (handled during decode).
    if !full_class.starts_with("animate:") { return None; }
    let rest = &full_class[8..];
    let mut parts = rest.split(':');
    let duration = parts.next().unwrap_or("1s");
    let delay = parts.next().unwrap_or("0s");
    // Encode as ANIM|animate|duration|delay so decode stage can consolidate with from()/to()/via()
    Some(format!("ANIM|animate|{}|{}", duration, delay))
    }
}

impl StyleEngine {
    fn decode_encoded_css(&self, css: &str, selector: &str, wrappers: &[String]) -> String {
        let is_encoded = css.contains("BASE|") || css.contains("STATE|") || css.contains("CHILD|") || css.contains("COND|") || css.contains("DATA|") || css.contains("RAW|") || css.contains("ANIM|");
        if !is_encoded {
            if wrappers.is_empty() { return build_block(selector, css); }
            let mut out = String::new();
            for w in wrappers { let sel = w.replace('&', selector); out.push_str(&build_block(&sel, css)); out.push('\n'); }
            if out.ends_with('\n') { out.pop(); }
            return out;
        }
        let mut out = String::new();
    let mut pending_anim: Option<PendingAnimation> = None;
        let lines: Vec<&str> = if css.contains('\n') { css.lines().collect() } else { vec![css] };
        for line in lines {
            if line.is_empty() { continue; }
                if let Some(rest) = line.strip_prefix("BASE|") {
                    // If the original grouping started with a breakpoint (e.g. lg(...)) we do NOT emit a base rule.
                    // Heuristic: after the leading dot we will have the literal breakpoint token followed by an escaped '('.
                    // Known breakpoints: collect from self.screens keys.
                    let is_responsive_group = self.screens.keys().any(|bp| selector.starts_with(&format!(".{}\\(", bp)));
                    if !is_responsive_group {
                        if wrappers.is_empty() { out.push_str(&build_block(selector, rest)); }
                        else {
                            for w in wrappers { let sel = w.replace('&', selector); out.push_str(&build_block(&sel, rest)); out.push('\n'); }
                            if out.ends_with('\n') { out.pop(); }
                        }
                        out.push('\n');
                    }
            } else if let Some(rest) = line.strip_prefix("STATE|") {
                let mut parts = rest.splitn(2,'|'); let state = parts.next().unwrap_or(""); let decls = parts.next().unwrap_or("");
                if state == "dark" { out.push_str(&build_block(&format!(".dark {}", selector), decls)); }
                else if state == "light" { out.push_str(&build_block(&format!(":root {}", selector), decls)); out.push('\n'); out.push_str(&build_block(&format!(".light {}", selector), decls)); }
                else { out.push_str(&build_block(&format!("{}:{}", selector, state), decls)); }
                out.push('\n');
            } else if let Some(rest) = line.strip_prefix("CHILD|") {
                let mut parts = rest.splitn(2,'|'); let child = parts.next().unwrap_or(""); let decls = parts.next().unwrap_or("");
                out.push_str(&build_block(&format!("{} > {}", selector, child), decls)); out.push('\n');
            } else if let Some(rest) = line.strip_prefix("DATA|") {
                let mut parts = rest.splitn(2,'|'); let data = parts.next().unwrap_or(""); let decls = parts.next().unwrap_or("");
                out.push_str(&build_block(&format!("{}[data-{}]", selector, data), decls)); out.push('\n');
            } else if let Some(rest) = line.strip_prefix("COND|") {
                let mut parts = rest.splitn(2,'|'); let cond = parts.next().unwrap_or(""); let decls = parts.next().unwrap_or("");
                if let Some(val) = cond.strip_prefix("@container>") {
                    // Single grouped selector within container
                    out.push_str(&format!("@container (min-width: {}) {{\n", val));
                    for l in build_block(selector, decls).lines() { out.push_str("  "); out.push_str(l); out.push('\n'); }
                    out.push_str("}\n");
                } else if let Some(bp) = cond.strip_prefix("screen:") { if let Some(v) = self.screens.get(bp) {
                    out.push_str(&format!("@media (min-width: {}) {{\n", v));
                    for l in build_block(selector, decls).lines() { out.push_str("  "); out.push_str(l); out.push('\n'); }
                    out.push_str("}\n");
                }} else if let Some(rest) = cond.strip_prefix("self:child-count>") {
                    if let Ok(threshold) = rest.parse::<usize>() {
                        if threshold > 0 { let hashed = format!("{}:has(> :nth-last-child(n+{}):first-child)", selector, threshold); out.push_str(&build_block(&hashed, decls)); out.push('\n'); }
                        else { out.push_str(&build_block(selector, decls)); out.push('\n'); }
                    }
                }
            } else if let Some(rest) = line.strip_prefix("ANIM|") {
                // Formats after parser/composite:
                //   ANIM|animate|duration|delay
                //   ANIM|from|token+token
                //   ANIM|to|token+token
                //   ANIM|via|token+token
                let parts: Vec<&str> = rest.split('|').collect();
                if parts.is_empty() { continue; }
                match parts[0] {
                    "animate" => {
                        let duration_val = parts.get(1).copied().unwrap_or("1s").to_string();
                        let delay_val = parts.get(2).copied().unwrap_or("0s").to_string();
                        let pa = pending_anim.get_or_insert(PendingAnimation{ duration: duration_val.clone(), delay: delay_val.clone(), fill_mode: String::new(), from:Vec::new(), via:Vec::new(), to_:Vec::new(), has_main: true });
                        pa.duration = duration_val; pa.delay = delay_val; pa.has_main = true;
                    }
                    "fill" => {
                        if let Some(mode) = parts.get(1) {
                            let pa = pending_anim.get_or_insert(PendingAnimation{ duration: "1s".into(), delay: "0s".into(), fill_mode: String::new(), from:Vec::new(), via:Vec::new(), to_:Vec::new(), has_main: false });
                            pa.fill_mode = (*mode).to_string();
                        }
                    }
                    "from" | "to" | "via" => {
                        if let Some(tokens) = parts.get(1) {
                            let pa = pending_anim.get_or_insert(PendingAnimation{ duration: "1s".into(), delay: "0s".into(), fill_mode:String::new(), from:Vec::new(), via:Vec::new(), to_:Vec::new(), has_main: false });
                            match parts[0] { "from" => pa.from.push((*tokens).to_string()), "to" => pa.to_.push((*tokens).to_string()), "via" => pa.via.push((*tokens).to_string()), _=>{} }
                        }
                    }
                    _ => {}
                }
            } else if let Some(raw) = line.strip_prefix("RAW|") {
                out.push_str(raw); if !raw.ends_with('\n') { out.push('\n'); }
            }
        }
        if let Some(pa) = pending_anim.take() {
            // If no animate: utility was present (only stages), skip emitting keyframes/animation to avoid empty rulesets.
            if !pa.has_main { if out.ends_with('\n') { out.pop(); } return out; }
            // Consolidate frames into single keyframes per requirements.
            let hash = format!("{:x}", seahash::hash(selector.as_bytes()));
            let mut frames: Vec<(u32,String)> = Vec::new();
            if !pa.from.is_empty() { frames.push((0, self.resolve_animation_tokens(&pa.from))); }
            if !pa.to_.is_empty() { frames.push((100, self.resolve_animation_tokens(&pa.to_))); }
            // Insert via stages evenly spaced if present
            if !pa.via.is_empty() {
                let count = pa.via.len();
                for (i, v) in pa.via.iter().enumerate() {
                    let pct = ((i + 1) as f32) / ((count + 1) as f32) * 100.0;
                    frames.push((pct as u32, self.resolve_animation_tokens(&[v.clone()] )));
                }
            }
            frames.sort_by_key(|(p, _)| *p);
            let mut kf = String::new();
            kf.push_str("@keyframes dx-anim-");
            kf.push_str(&hash);
            kf.push_str(" {\n");
            for (pct, decls) in frames { kf.push_str(&format!("  {}% {{ {} }}\n", pct, decls)); }
            kf.push_str("}\n\n");
            out.push_str(&kf);
            // Apply animation to the selector itself: animation: <duration> <delay> both dx-anim-hash
            let fill = if pa.fill_mode.is_empty() { "both" } else { pa.fill_mode.as_str() };
            out.push_str(&build_block(selector, &format!("animation: {} {} {} dx-anim-{}", pa.duration, pa.delay, fill, hash)));
        }
        if out.ends_with('\n') { out.pop(); }
        out
    }

    // Resolve animation stage tokens (like opacity-0, translate-y-4) into declarations using existing generation paths.
    fn resolve_animation_tokens(&self, tokens: &[String]) -> String {
        let mut decls: Vec<String> = Vec::new();
        for t in tokens {
            for piece in t.split('+') {
                let piece = piece.trim(); if piece.is_empty() { continue; }
                if let Some(css) = self.precompiled.get(piece) { decls.push(css.clone()); continue; }
                if let Some(c) = self.generate_color_css(piece) { decls.push(c); continue; }
                if let Some(d) = self.generate_dynamic_css(piece) { decls.push(d); continue; }
            }
        }
        // Deduplicate later properties by name
        let mut last_for: HashMap<&str, usize> = HashMap::new();
        for (i, d) in decls.iter().enumerate() { if let Some(idx) = d.find(':') { let name = d[..idx].trim(); last_for.insert(name, i); } }
        let mut out = String::new();
        for (i, d) in decls.iter().enumerate() { if let Some(idx) = d.find(':') { let name = d[..idx].trim(); if last_for.get(name) == Some(&i) { if !out.is_empty() { out.push_str("; "); } out.push_str(d.trim().trim_end_matches(';')); } } }
        out
    }

    fn wrap_media_queries(&self, mut css_body: String, media_queries: &[String]) -> String {
        for mq in media_queries.iter().rev() {
            let mut wrapped = String::new();
            wrapped.push_str(mq);
            wrapped.push_str(" {\n");
            for line in css_body.trim_end().lines() {
                if line.is_empty() { continue; }
                wrapped.push_str("  ");
                wrapped.push_str(line);
                wrapped.push('\n');
            }
            wrapped.push_str("}\n"); // closing for this media/container
            css_body = wrapped;
        }
        if !css_body.ends_with('\n') { css_body.push('\n'); }
        css_body
    }
}

fn build_block(selector: &str, declarations: &str) -> String {
    let decl_raw = declarations.trim().trim_end_matches(';').trim();
    let mut seen: HashMap<&str, usize> = HashMap::new();
    let parts: Vec<&str> = if decl_raw.is_empty() { Vec::new() } else if decl_raw.contains(';') { decl_raw.split(';').collect() } else { vec![decl_raw] };
    for (i,p) in parts.iter().enumerate() { if let Some(idx)=p.find(':') { seen.insert(p[..idx].trim(), i); } }
    let mut s = String::with_capacity(selector.len() + decl_raw.len() + 16);
    s.push_str(selector);
    s.push_str(" {\n");
    for (i,p) in parts.iter().enumerate() {
        let pt = p.trim(); if pt.is_empty() { continue; }
        let name = pt.split(':').next().unwrap_or("").trim();
        if seen.get(name)==Some(&i) { // last occurrence
            s.push_str("  ");
            s.push_str(pt.trim_end_matches(';'));
            s.push_str(";\n");
        }
    }
    s.push_str("}\n");
    s
}

fn sanitize_declarations(input: &str) -> String {
    let mut out = input.trim().to_string();
    while out.ends_with(";;") { out.pop(); }
    if let Some(pos) = out.find("--transform-scale-x, --transform-scale-y:") {
        if let Some(val_start) = out[pos..].find(':') { let val_start_abs = pos + val_start + 1; if val_start_abs < out.len() {
            let value = out[val_start_abs..].split(';').next().unwrap_or("").trim();
            let replacement = format!("--transform-scale-x: {v}; --transform-scale-y: {v}", v=value);
            if let Some(end_seg) = out[val_start_abs..].find(';') {
                let end_abs = val_start_abs + end_seg + 1;
                out.replace_range(pos..end_abs, &replacement);
            } else {
                out.replace_range(pos..out.len(), &replacement);
            }
        }}
    }
    out
}

