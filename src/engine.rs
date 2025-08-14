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

        if !prefix_segment.is_empty() {
            for part in prefix_segment.split(':') {
                if let Some(screen_value) = self.screens.get(part) {
                    media_queries.push(format!("@media (min-width: {})", screen_value));
                } else if let Some(cq_value) = self.container_queries.get(part) {
                    media_queries.push(format!("@container (min-width: {})", cq_value));
                } else if let Some(state_value) = self.states.get(part) {
                    pseudo_classes.push_str(state_value);
                }
            }
        }

        let core_css = self
            .precompiled
            .get(base_class)
            .cloned()
            .or_else(|| self.generate_color_css(base_class))
            .or_else(|| self.generate_animation_css(class_name))
            .or_else(|| self.generate_dynamic_css(base_class))
            .or_else(|| self.expand_composite(base_class));

        core_css.map(|css| {
            let mut selector = String::from(".");
            for ch in class_name.chars() {
                match ch { ':' => selector.push_str("\\:"), '@' => selector.push_str("\\@"), _ => selector.push(ch) }
            }
            selector.push_str(&pseudo_classes);
            let mut css_body = String::new();
            css_body.push_str(&selector);
            css_body.push_str(" {\n  ");
            css_body.push_str(&css);
            css_body.push_str(";\n}");
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

        if !prefix_segment.is_empty() {
            for part in prefix_segment.split(':') {
                if let Some(screen_value) = self.screens.get(part) {
                    media_queries.push(format!("@media (min-width: {})", screen_value));
                } else if let Some(cq_value) = self.container_queries.get(part) {
                    media_queries.push(format!("@container (min-width: {})", cq_value));
                } else if let Some(state_value) = self.states.get(part) {
                    pseudo_classes.push_str(state_value);
                }
            }
        }

        let core_css = self
            .precompiled
            .get(base_class)
            .cloned()
            .or_else(|| self.generate_color_css(base_class))
            .or_else(|| self.generate_animation_css(class_name))
            .or_else(|| self.generate_dynamic_css(base_class))
            .or_else(|| self.expand_composite(base_class));

        core_css.map(|css| {
            let mut selector = String::with_capacity(escaped.len() + pseudo_classes.len() + 1);
            selector.push('.');
            selector.push_str(escaped);
            selector.push_str(&pseudo_classes);

            let mut css_body = String::with_capacity(selector.len() + css.len() + 16);
            css_body.push_str(&selector);
            css_body.push_str(" {\n  ");
            css_body.push_str(&css);
            css_body.push_str(";\n}");

            for mq in media_queries.iter().rev() {
                let mut wrapped = String::with_capacity(mq.len() + css_body.len() + 8);
                wrapped.push_str(mq);
                wrapped.push_str(" {\n");
                for line in css_body.lines() {
                    wrapped.push_str("  ");
                    wrapped.push_str(line);
                    wrapped.push('\n');
                }
                wrapped.push('}');
                css_body = wrapped;
            }
            css_body
        })
    }

    fn expand_composite(&self, class_name: &str) -> Option<String> {
        // Composite classes start with dx-c-
        if !class_name.starts_with("dx-c-") { return None; }
        // Retrieve tokens
        let pairs = composites::iter_pairs();
        for (cname, tokens) in pairs {
            if cname == class_name {
                // Build merged declarations concatenated by semicolons (each utility will itself expand separately; we re-query engine for each token)
                let mut decls: Vec<String> = Vec::new();
                for t in tokens {
                    if let Some(rule) = self.precompiled.get(&t) {
                        decls.push(rule.clone());
                    } else if let Some(c) = self.generate_color_css(&t) {
                        decls.push(c);
                    } else if let Some(d) = self.generate_dynamic_css(&t) {
                        decls.push(d);
                    }
                }
                if decls.is_empty() { return None; }
                // Join while stripping trailing semicolons to avoid duplication
                let mut merged = String::new();
                for (i, d) in decls.iter().enumerate() {
                    let trimmed = d.trim_end_matches(';');
                    if i > 0 { merged.push(' '); }
                    merged.push_str(trimmed);
                    merged.push(';');
                }
                return Some(merged);
            }
        }
        None
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
