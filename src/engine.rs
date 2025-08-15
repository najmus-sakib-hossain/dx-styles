use lru::LruCache;
use std::collections::HashMap;
use smallvec::SmallVec;
use rayon::prelude::*;
use std::fs;
use std::num::NonZeroUsize;
use std::sync::{Mutex, RwLock};
use std::sync::Arc;

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
            let mut selector = String::with_capacity(class_name.len() + pseudo_classes.len() + 1);
            selector.push('.');
            for ch in class_name.chars() {
                match ch { ':' => selector.push_str("\\:"), '@' => selector.push_str("\\@"), _ => selector.push(ch) }
            }
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
            for ch in escaped.chars() { match ch { ':' => selector.push_str("\\:"), '@' => selector.push_str("\\@"), _ => selector.push(ch) } }
            selector.push_str(&pseudo_classes);
            let blocks = self.decode_encoded_css(&css, &selector, &wrappers);
            self.wrap_media_queries(blocks, &media_queries)
        })
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
        for anim in &comp.animations { sections.push(format!("ANIM|{}", anim)); }
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
        if !full_class.contains("animate:") { return None; }
        let parts: Vec<&str> = full_class.split(':').collect();
        let pos = parts.iter().position(|p| *p == "animate")?;
        let duration = parts.get(pos + 1).unwrap_or(&"1s");
        let mut delay = "0s";
        if let Some(next) = parts.get(pos + 2) {
            if next.ends_with("ms") || next.ends_with('s') { delay = next; }
        }
        let hash = format!("{:x}", seahash::hash(full_class.as_bytes()));
        if let Some(tpl) = self.animation_templates.get("animate") {
            let out = tpl.replace("{hash}", &hash)
                .replace("{value1|1s}", duration)
                .replace("{value2|0s}", delay);
            return Some(out.trim_end_matches(';').to_string());
        }
        None
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
        let lines: Vec<&str> = if css.contains('\n') { css.lines().collect() } else { vec![css] };
        let mut anim_stage_map: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for line in lines {
            if line.is_empty() { continue; }
            if let Some(rest) = line.strip_prefix("BASE|") {
                if wrappers.is_empty() { out.push_str(&build_block(selector, rest)); }
                else { for w in wrappers { let sel = w.replace('&', selector); out.push_str(&build_block(&sel, rest)); out.push('\n'); } if out.ends_with('\n') { out.pop(); } }
                out.push('\n');
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
                    out.push_str(&format!("@container (min-width: {}) {{\n  {}\n}}\n", val, build_block(selector, decls)));
                }
                else if let Some(bp) = cond.strip_prefix("screen:") { if let Some(v) = self.screens.get(bp) { out.push_str(&format!("@media (min-width: {}) {{\n  {}\n}}\n", v, build_block(selector, decls))); } }
                else if let Some(rest) = cond.strip_prefix("self:child-count>") {
                    if let Ok(threshold) = rest.parse::<usize>() {
                        if threshold > 0 {
                            let hashed = format!("{}:has(> :nth-last-child(n+{}):first-child)", selector, threshold);
                            out.push_str(&build_block(&hashed, decls)); out.push('\n');
                        } else {
                            out.push_str(&build_block(selector, decls)); out.push('\n');
                        }
                    }
                }
            } else if let Some(rest) = line.strip_prefix("ANIM|") {
                let spec = rest; let parts: Vec<&str> = spec.split('|').collect();
                if parts.len() >= 3 && parts[0] == "animstage" {
                    let anim_name = format!("dx-keyframe-{:x}", seahash::hash(selector.as_bytes()));
                    let stage = parts[1].to_string();
                    let toks = parts[2].to_string();
                    anim_stage_map.entry(anim_name).or_default().push((stage, toks));
                }
            } else if let Some(raw) = line.strip_prefix("RAW|") {
                out.push_str(raw); if !raw.ends_with('\n') { out.push('\n'); }
            }
        }
        for (name, mut stages) in anim_stage_map.into_iter() {
            let mut froms = Vec::new(); let mut vias = Vec::new(); let mut tos = Vec::new();
            for (stage, toks) in stages.drain(..) { match stage.as_str() { "from" => froms.push(toks), "via" => vias.push(toks), "to" => tos.push(toks), _ => {} } }
            let resolve_util_list = |raw: &str| -> String {
                let mut decls: Vec<String> = Vec::new();
                for ut in raw.split('+') { let u=ut.trim(); if u.is_empty(){continue;} if let Some(rule)=self.precompiled.get(u){decls.push(rule.clone());} else if let Some(c)=self.generate_color_css(u){decls.push(c);} else if let Some(d)=self.generate_dynamic_css(u){decls.push(d);} }
                decls.join("; ")
            };
            let mut frames: Vec<(u32,String)> = Vec::new();
            if !froms.is_empty() { frames.push((0, resolve_util_list(&froms.join("+")))); }
            if !vias.is_empty() { let count = vias.len(); for (i,v) in vias.iter().enumerate() { let pct = ((i+1) as f32)/((count+1) as f32)*100.0; frames.push((pct as u32, resolve_util_list(v))); } }
            if !tos.is_empty() { frames.push((100, resolve_util_list(&tos.join("+")))); }
            frames.sort_by_key(|(p,_)| *p);
            let mut kf = String::new(); kf.push_str("@keyframes "); kf.push_str(&name); kf.push_str(" {\n"); for (pct,decls) in frames { kf.push_str(&format!("  {}% {{ {} }}\n", pct, decls)); } kf.push_str("}\n"); out.push_str(&kf);
            out.push_str(&build_block(selector, &format!("animation: {} 1s both", name))); out.push('\n');
        }
        if out.ends_with('\n') { out.pop(); }
        out
    }

    fn wrap_media_queries(&self, mut css_body: String, media_queries: &[String]) -> String {
        for mq in media_queries.iter().rev() {
            let mut wrapped = String::new(); wrapped.push_str(mq); wrapped.push_str(" {\n");
            for line in css_body.lines() { wrapped.push_str("  "); wrapped.push_str(line); wrapped.push('\n'); }
            wrapped.push('}'); css_body = wrapped;
        }
        css_body
    }
}

fn build_block(selector: &str, declarations: &str) -> String {
    let mut s = String::new();
    s.push_str(selector);
    s.push_str(" {\n  ");
    let decl = declarations.trim().trim_end_matches(';').to_string();
    let parts: Vec<&str> = if decl.contains(';') { decl.split(';').collect() } else { vec![decl.as_str()] };
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for (i,p) in parts.iter().enumerate() { if let Some(idx)=p.find(':') { let name=p[..idx].trim(); counts.insert(name, i); } }
    for (i,p) in parts.iter().enumerate() {
        let p_trim = p.trim(); if p_trim.is_empty() { continue; }
        let prop_name = p_trim.split(':').next().unwrap_or("").trim();
        if counts.get(prop_name)==Some(&i) {
            s.push_str(p_trim.trim_end_matches(';'));
            s.push_str(";\n  ");
        }
    }
    if s.ends_with("\n  ") { s.truncate(s.len()-3); }
    s.push_str("}\n");
    while s.ends_with("\n\n") { s.pop(); }
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
