use lru::LruCache;
use std::collections::HashMap;
use smallvec::SmallVec;
use std::fs;
use std::num::NonZeroUsize;
use std::sync::Mutex;
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

pub struct StyleEngine {
    precompiled: HashMap<String, String>,
    buffer: Vec<u8>,
    screens: HashMap<String, String>,
    states: HashMap<String, String>,
    container_queries: HashMap<String, String>,
    css_cache: Mutex<LruCache<u32, Arc<String>>>,
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

        Ok(Self {
            precompiled,
            buffer,
            screens,
            states,
            container_queries,
            // Larger cache to reduce recomputation frequency during dev hot-reloads.
            css_cache: Mutex::new(LruCache::new(NonZeroUsize::new(8192).unwrap())),
        })
    }

    // Internal: compute CSS without consulting / mutating the cache (allocation-light)
    fn compute_css(&self, class_name: &str) -> Option<String> {
        // Fast path: no prefixes
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
            .or_else(|| self.generate_dynamic_css(base_class));

        core_css.map(|css| {
            let mut selector = String::from(".");
            // Escape ':' and '@'
            for ch in class_name.chars() {
                match ch { ':' => selector.push_str("\\:"), '@' => selector.push_str("\\@"), _ => selector.push(ch) }
            }
            selector.push_str(&pseudo_classes);
            let mut css_body = String::new();
            css_body.push_str(&selector);
            css_body.push_str(" {\n  ");
            css_body.push_str(&css);
            css_body.push_str(";\n}");
            for mq in media_queries.iter().rev() { // reverse fold
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

    // ID-based compute path: use interner's pre-escaped selector and avoid per-char work.
    fn compute_css_id(&self, id: u32, interner: &crate::interner::ClassInterner) -> Option<String> {
        let class_name = interner.get(id);
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
                    // states usually contain a pseudo-class like ":hover" or similar; append to selector
                    pseudo_classes.push_str(state_value);
                }
            }
        }

        let core_css = self
            .precompiled
            .get(base_class)
            .cloned()
            .or_else(|| self.generate_dynamic_css(base_class));

        core_css.map(|css| {
            // Use interner's precomputed escaped selector for the full class name.
            let esc = interner.escaped(id);
            let mut selector = String::with_capacity(esc.len() + pseudo_classes.len() + 1);
            selector.push('.');
            selector.push_str(esc);
            selector.push_str(&pseudo_classes);

            // Estimate capacity for final CSS to reduce reallocations
            let mut css_body = String::with_capacity(selector.len() + css.len() + 16);
            css_body.push_str(&selector);
            css_body.push_str(" {\n  ");
            css_body.push_str(&css);
            css_body.push_str(";\n}");

            // Wrap with media queries (reverse order)
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

    // Batch variant: drastically reduces mutex contention by performing two short lock phases.
    #[allow(dead_code)] // Legacy string batch path; replaced by ID-based cache path.
    pub fn generate_css_for_classes_batch<'a>(&self, class_names: &[&'a str]) -> Vec<String> {
        // First lock: gather cached & identify misses
        // Temporarily bypass u32 cache path since this function still works on &str (used on initial full pass).
        // TODO: Remove when all callers switched to ID-based API.
        let mut out = Vec::with_capacity(class_names.len());
        for &name in class_names { if let Some(css)= self.compute_css(name) { out.push(css); } }
        out
    }

    pub fn generate_css_for_ids(&self, ids: &[u32], interner: &crate::interner::ClassInterner) -> Vec<Arc<String>> {
        // Preallocate result slots to avoid sorting and intermediate vectors.
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
            // Compute misses and insert into cache in one locked phase.
            let mut computed: Vec<(usize, Arc<String>)> = Vec::with_capacity(misses.len());
            for (idx, id) in &misses {
                if let Some(css) = self.compute_css_id(*id, interner) {
                    computed.push((*idx, Arc::new(css)));
                }
            }
            let mut cache = self.css_cache.lock().unwrap();
            for (idx, css_arc) in &computed {
                cache.put(ids[*idx], Arc::clone(css_arc));
                result_slots[*idx] = Some(Arc::clone(css_arc));
            }
        }

        // Collect and return only generated rules (skip ids that produced no CSS).
        result_slots
            .into_iter()
            .filter_map(|opt| opt)
            .collect()
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
}

