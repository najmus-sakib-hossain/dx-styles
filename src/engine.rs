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
            // sanitize duplicate trailing semicolons & invalid combined transform scale declaration pattern
            css = sanitize_declarations(&css);
            let mut selector = String::from(".");
            for ch in class_name.chars() {
                match ch { ':' => selector.push_str("\\:"), '@' => selector.push_str("\\@"), _ => selector.push(ch) }
            }
            selector.push_str(&pseudo_classes);
            let mut blocks = String::new();
            if css.contains('\n') && css.contains("BASE|") {
                // multi-block encoded composite
                for line in css.lines() {
                    if line.starts_with("BASE|") {
                        let decls = &line[5..];
                        blocks.push_str(&build_block(&selector, decls));
                        blocks.push('\n');
                    } else if line.starts_with("STATE|") {
                        let parts: Vec<&str> = line.splitn(3,'|').collect();
                        if parts.len()==3 { let state = parts[1]; let decls=parts[2]; blocks.push_str(&build_block(&format!("{}:{}", selector, state), decls)); blocks.push('\n'); }
                    } else if line.starts_with("CHILD|") {
                        let parts: Vec<&str> = line.splitn(3,'|').collect();
                        if parts.len()==3 { let child = parts[1]; let decls=parts[2]; blocks.push_str(&build_block(&format!("{} > {}", selector, child), decls)); blocks.push('\n'); }
                    } else if line.starts_with("DATA|") {
                        let parts: Vec<&str> = line.splitn(3,'|').collect();
                        if parts.len()==3 { let attr = parts[1]; let decls=parts[2]; blocks.push_str(&build_block(&format!("{}[data-{}]", selector, attr), decls)); blocks.push('\n'); }
                    } else if line.starts_with("COND|") {
                        let parts: Vec<&str> = line.splitn(3,'|').collect();
                        if parts.len()==3 { let cond = parts[1]; let decls=parts[2];
                            if let Some(rest) = cond.strip_prefix("@container>") {
                                blocks.push_str(&format!("@container (min-width: {}) {{\n  {}\n}}\n", rest, build_block(&selector, decls)));
                            } else if let Some(bp) = cond.strip_prefix("screen:") {
                                // map screen key to value using screens map
                                if let Some(val) = self.screens.get(bp) {
                                    blocks.push_str(&format!("@media (min-width: {}) {{\n  {}\n}}\n", val, build_block(&selector, decls)));
                                }
                            }
                        }
                    } else if line.starts_with("ANIM|") {
                        // animstage|stage|props+props
                        // aggregate stages into keyframes (skip here - placeholder)
                        // TODO implement aggregation
                    }
                }
                if blocks.ends_with('\n') { blocks.pop(); }
            } else {
                if wrappers.is_empty() {
                    blocks.push_str(&build_block(&selector, &css));
                } else {
                    for w in &wrappers { let replaced = w.replace('&', &selector); blocks.push_str(&build_block(&replaced, &css)); blocks.push('\n'); }
                    if blocks.ends_with('\n') { blocks.pop(); }
                }
            }
            let mut css_body = blocks;
            for mq in media_queries.iter().rev() {
                let mut wrapped = String::new();
                wrapped.push_str(mq);
                wrapped.push_str(" {\n");
                for line in css_body.lines() { wrapped.push_str("  "); wrapped.push_str(line); wrapped.push('\n'); }
                wrapped.push('}');
                css_body = wrapped;
            }
            css_body
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
            selector.push_str(escaped);
            selector.push_str(&pseudo_classes);
            let mut blocks = String::new();
        if css.contains('\n') && css.contains("BASE|") {
                for line in css.lines() {
                    if line.starts_with("BASE|") { let decls=&line[5..]; blocks.push_str(&build_block(&selector, decls)); blocks.push('\n'); }
                    else if line.starts_with("STATE|") { let p: Vec<&str>=line.splitn(3,'|').collect(); if p.len()==3 { blocks.push_str(&build_block(&format!("{}:{}", selector,p[1]), p[2])); blocks.push('\n'); }}
                    else if line.starts_with("CHILD|") { let p: Vec<&str>=line.splitn(3,'|').collect(); if p.len()==3 { blocks.push_str(&build_block(&format!("{} > {}", selector,p[1]), p[2])); blocks.push('\n'); }}
                    else if line.starts_with("DATA|") { let p: Vec<&str>=line.splitn(3,'|').collect(); if p.len()==3 { blocks.push_str(&build_block(&format!("{}[data-{}]", selector,p[1]), p[2])); blocks.push('\n'); }}
            else if line.starts_with("COND|") { let p: Vec<&str>=line.splitn(3,'|').collect(); if p.len()==3 { if let Some(rest)=p[1].strip_prefix("@container>") { blocks.push_str(&format!("@container (min-width: {}) {{\n  {}\n}}\n", rest, build_block(&selector,p[2]))); } else if let Some(bp)=p[1].strip_prefix("screen:") { if let Some(val)=self.screens.get(bp) { blocks.push_str(&format!("@media (min-width: {}) {{\n  {}\n}}\n", val, build_block(&selector,p[2]))); } } }}
                }
                if blocks.ends_with('\n') { blocks.pop(); }
            } else {
                if wrappers.is_empty() { blocks.push_str(&build_block(&selector, &css)); }
                else { for w in &wrappers { let replaced = w.replace('&', &selector); blocks.push_str(&build_block(&replaced, &css)); blocks.push('\n'); } if blocks.ends_with('\n') { blocks.pop(); } }
            }
            let mut css_body = blocks;
            for mq in media_queries.iter().rev() {
                let mut wrapped = String::new();
                wrapped.push_str(mq);
                wrapped.push_str(" {\n");
                for line in css_body.lines() { wrapped.push_str("  "); wrapped.push_str(line); wrapped.push('\n'); }
                wrapped.push('}');
                css_body = wrapped;
            }
            css_body
        })
    }

    fn expand_composite(&self, class_name: &str) -> Option<String> {
        if !class_name.starts_with("dx-c-") { return None; }
        let comp = composites::get(class_name)?;
        // helper closure to resolve utility tokens into declarations
        let mut resolve_tokens = |tokens: &[String]| -> Vec<String> {
            let mut out = Vec::new();
            for t in tokens {
                if let Some(rest) = t.strip_prefix("fluid:") {
                    let parts: Vec<&str> = rest.split(':').collect();
                    if parts.len() >= 4 { // fluid:prop:min:minBp:max
                        let prop = parts[0];
                        let min_v = parts[1];
                        let max_v = parts[3];
                        out.push(format!("{}: clamp({}, calc(({} + {})/2), {})", prop, min_v, min_v, max_v, max_v));
                        continue;
                    }
                } else if let Some(rest) = t.strip_prefix("motion:") {
                    let hash = format!("{:x}", seahash::hash(rest.as_bytes()));
                    out.push(format!("transition-timing-function: cubic-bezier(0.34,1.56,0.64,1); /* motion:{} */", hash));
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

    // Generate color utilities bg-* and text-* from colors table
    fn generate_color_css(&self, class_name: &str) -> Option<String> {
        if let Some(name) = class_name.strip_prefix("bg-") {
            if let Some(val) = self.colors.get(name) { return Some(format!("background-color: {}", val)); }
        }
        if let Some(name) = class_name.strip_prefix("text-") {
            if let Some(val) = self.colors.get(name) { return Some(format!("color: {}", val)); }
        }
        None
    }

    // Parse animation sentence utilities. This is an initial minimal implementation:
    // animate:duration[:delay] + optional from:/to:/via: pieces.
    fn generate_animation_css(&self, full_class: &str) -> Option<String> {
        if !full_class.contains("animate:") { return None; }
        // Split on spaces not present in a single class (classes are single tokens). We only process the animate:* token here.
        // Pattern: [state prefixes already handled]:animate:dur[:delay]
        let parts: Vec<&str> = full_class.split(':').collect();
        // find "animate" position
        let pos = parts.iter().position(|p| *p == "animate")?;
        // duration in next segment if exists
        let duration = parts.get(pos + 1).unwrap_or(&"1s");
        let mut delay = "0s";
        if let Some(next) = parts.get(pos + 2) {
            if next.ends_with("ms") || next.ends_with('s') { delay = next; }
        }
        // Basic hash (poor mans) - could hash the class string
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

// Helpers ------------------------------------------------------------------

fn build_block(selector: &str, declarations: &str) -> String {
    let mut s = String::new();
    s.push_str(selector);
    s.push_str(" {\n  ");
    // ensure single trailing semicolon inside block
    let mut decl = declarations.trim().trim_end_matches(';').to_string();
    // split combined declarations separated by ';' and join with ';\n  ' for readability
    if decl.contains(';') {
        let parts: Vec<&str> = decl.split(';').filter(|p| !p.trim().is_empty()).collect();
        s.push_str(&parts.join(";\n  "));
        s.push_str(";\n}");
    } else {
        s.push_str(&decl);
        s.push_str(";\n}");
    }
    s
}

fn sanitize_declarations(input: &str) -> String {
    let mut out = input.trim().to_string();
    // collapse multiple semicolons
    while out.ends_with(";;") { out.pop(); }
    // fix combined transform scale pattern '--transform-scale-x, --transform-scale-y: VALUE'
    if let Some(pos) = out.find("--transform-scale-x, --transform-scale-y:") {
        // capture value after colon
        if let Some(val_start) = out[pos..].find(':') { let val_start_abs = pos + val_start + 1; if val_start_abs < out.len() {
            let value = out[val_start_abs..].split(';').next().unwrap_or("").trim();
            let replacement = format!("--transform-scale-x: {v}; --transform-scale-y: {v}", v=value);
            // remove the original segment up to first semicolon
            if let Some(end_seg) = out[val_start_abs..].find(';') {
                let end_abs = val_start_abs + end_seg + 1; // include semicolon
                out.replace_range(pos..end_abs, &replacement);
            } else {
                out.replace_range(pos..out.len(), &replacement);
            }
        }}
    }
    out
}

