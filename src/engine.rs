use lru::LruCache;
use std::collections::HashMap;
use smallvec::SmallVec;
use std::fs;
use std::num::NonZeroUsize;
use std::sync::Mutex;

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
    css_cache: Mutex<LruCache<u32, String>>,
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

    pub fn generate_css_for_ids(&self, ids: &[u32], interner: &crate::interner::ClassInterner) -> Vec<String> {
        let mut cache = self.css_cache.lock().unwrap();
        let mut results: Vec<(usize, String)> = Vec::with_capacity(ids.len());
        let mut misses: Vec<(usize, u32)> = Vec::new();
        for (idx, &id) in ids.iter().enumerate() {
            if let Some(c) = cache.get(&id) { results.push((idx, c.clone())); } else { misses.push((idx, id)); }
        }
        drop(cache);
        if !misses.is_empty() {
            let mut computed: Vec<(usize, String)> = Vec::with_capacity(misses.len());
            for (idx, id) in misses { if let Some(css)= self.compute_css(interner.get(id)) { computed.push((idx, css)); } }
            let mut cache = self.css_cache.lock().unwrap();
            for (idx, css) in &computed { cache.put(ids[*idx], css.clone()); }
            results.extend(computed);
        }
        results.sort_unstable_by_key(|(i, _)| *i);
        results.into_iter().map(|(_, css)| css).collect()
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

