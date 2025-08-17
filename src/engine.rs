use cssparser::serialize_identifier;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::sync::Arc;
use std::sync::RwLock;

mod styles_generated {
    #![allow(
        dead_code,
        unused_imports,
        unsafe_op_in_unsafe_fn,
        mismatched_lifetime_syntaxes
    )]
    include!(concat!(env!("OUT_DIR"), "/styles_generated.rs"));
}
use crate::composites;
use styles_generated::style_schema;

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
    _animation_templates: HashMap<String, String>,
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

        let container_queries = config.container_queries().map_or_else(HashMap::new, |c| {
            c.iter()
                .map(|cq| (cq.name().to_string(), cq.value().to_string()))
                .collect()
        });

        let colors = config.colors().map_or_else(HashMap::new, |c| {
            c.iter()
                .map(|color| (color.name().to_string(), color.value().to_string()))
                .collect()
        });

        let _animation_templates = config
            .animation_generators()
            .map_or_else(HashMap::new, |a| {
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
            _animation_templates,
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

    fn compute_css(&self, class_name: &str) -> Option<String> {
        if class_name.starts_with("from(")
            || class_name.starts_with("to(")
            || class_name.starts_with("via(")
        {
            return None;
        }
        let mut last_colon = None;
        for (i, b) in class_name.as_bytes().iter().enumerate() {
            if *b == b':' {
                last_colon = Some(i);
            }
        }
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
                    if state_value.contains('&') {
                        wrappers.push(state_value.to_string());
                    } else {
                        pseudo_classes.push_str(state_value);
                    }
                } else if part == "dark" {
                    wrappers.push(".dark &".to_string());
                } else if part == "light" {
                    wrappers.push(":root &".to_string());
                }
            }
        }

        let core_css_raw = self
            .expand_composite(class_name)
            .or_else(|| self.precompiled.get(base_class).cloned())
            .or_else(|| self.generate_color_css(base_class))
            .or_else(|| {
                if class_name.contains(' ') {
                    None
                } else {
                    self.generate_animation_css(class_name)
                }
            })
            .or_else(|| self.generate_dynamic_css(base_class))
            .or_else(|| self.expand_composite(base_class));
        core_css_raw.map(|mut css| {
            css = sanitize_declarations(&css);
            let mut escaped_ident = String::with_capacity(class_name.len() + 8);
            struct Acc<'a> {
                buf: &'a mut String,
            }
            impl<'a> fmt::Write for Acc<'a> {
                fn write_str(&mut self, s: &str) -> fmt::Result {
                    self.buf.push_str(s);
                    Ok(())
                }
            }
            if serialize_identifier(
                class_name,
                &mut Acc {
                    buf: &mut escaped_ident,
                },
            )
            .is_err()
            {
                for ch in class_name.chars() {
                    match ch {
                        ':' => escaped_ident.push_str("\\:"),
                        '@' => escaped_ident.push_str("\\@"),
                        '(' => escaped_ident.push_str("\\("),
                        ')' => escaped_ident.push_str("\\)"),
                        ' ' => escaped_ident.push_str("\\ "),
                        '/' => escaped_ident.push_str("\\/"),
                        '\\' => escaped_ident.push_str("\\\\"),
                        _ => escaped_ident.push(ch),
                    }
                }
            }
            let mut selector =
                String::with_capacity(escaped_ident.len() + pseudo_classes.len() + 2);
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
        if class_name.starts_with("from(")
            || class_name.starts_with("to(")
            || class_name.starts_with("via(")
        {
            return None;
        }
        if class_name.starts_with("?@container>")
            && class_name.contains('(')
            && class_name.ends_with(')')
        {
            if let Some(block) = self.generate_container_group(class_name, escaped) {
                return Some(block);
            }
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
                    if state_value.contains('&') {
                        wrappers.push(state_value.to_string());
                    } else {
                        pseudo_classes.push_str(state_value);
                    }
                } else if part == "dark" {
                    wrappers.push(".dark &".to_string());
                } else if part == "light" {
                    wrappers.push(":root &".to_string());
                }
            }
        }

        let core_css_raw = self
            .expand_composite(class_name)
            .or_else(|| self.precompiled.get(base_class).cloned())
            .or_else(|| self.generate_color_css(base_class))
            .or_else(|| {
                if class_name.contains(' ') {
                    None
                } else {
                    self.generate_animation_css(class_name)
                }
            })
            .or_else(|| self.generate_dynamic_css(base_class))
            .or_else(|| self.expand_composite(base_class));
        core_css_raw.map(|mut css| {
            css = sanitize_declarations(&css);
            let mut selector = String::with_capacity(escaped.len() + pseudo_classes.len() + 1);
            selector.push('.');
            let mut prev_src_char: Option<char> = None;
            for ch in escaped.chars() {
                match ch {
                    ':' => {
                        if prev_src_char != Some('\\') {
                            selector.push_str("\\:");
                        } else {
                            selector.push(':');
                        }
                    }
                    '@' => {
                        if prev_src_char != Some('\\') {
                            selector.push_str("\\@");
                        } else {
                            selector.push('@');
                        }
                    }
                    _ => selector.push(ch),
                }
                prev_src_char = Some(ch);
            }
            selector.push_str(&pseudo_classes);
            let blocks = self.decode_encoded_css(&css, &selector, &wrappers);
            self.wrap_media_queries(blocks, &media_queries)
        })
    }

    fn generate_container_group(&self, raw: &str, escaped_selector: &str) -> Option<String> {
        const PREFIX: &str = "?@container>";
        let after_prefix = &raw[PREFIX.len()..];
        let paren_idx = after_prefix.find('(')?;
        let size_part = after_prefix[..paren_idx].trim();
        if size_part.is_empty() {
            return None;
        }
        let inner_raw = after_prefix[paren_idx + 1..].strip_suffix(')')?;
        let size_expr = if size_part.chars().all(|c| c.is_ascii_digit()) {
            format!("{}px", size_part)
        } else if size_part.ends_with("px")
            || size_part.contains(|c: char| c == ' ' || c == '(' || c == ')')
        {
            size_part.to_string()
        } else {
            size_part.to_string()
        };
        let inner_utils: Vec<&str> = inner_raw
            .split(|c: char| c.is_whitespace())
            .filter(|s| !s.is_empty())
            .collect();
        if inner_utils.is_empty() {
            return None;
        }
        use std::collections::HashMap;
        let mut decls: HashMap<String, (usize, String)> = HashMap::new();
        let mut order: usize = 0;
        for util in &inner_utils {
            if let Some(raw_css) = self.compute_css(util) {
                if let Some(open) = raw_css.find('{') {
                    if let Some(close) = raw_css.find('}') {
                        if close > open {
                            let body = &raw_css[open + 1..close];
                            for seg in body.split(';') {
                                let seg = seg.trim();
                                if seg.is_empty() {
                                    continue;
                                }
                                if let Some(colon) = seg.find(':') {
                                    let prop = seg[..colon].trim().to_string();
                                    let value =
                                        seg[colon + 1..].trim().trim_end_matches(';').to_string();
                                    decls.insert(prop, (order, value));
                                    order += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        if decls.is_empty() {
            return None;
        }
        let mut ordered: Vec<(String, (usize, String))> = decls.into_iter().collect();
        ordered.sort_by_key(|(_, (ord, _))| *ord);
        let mut body = String::new();
        for (prop, (_, val)) in ordered {
            body.push_str("    ");
            body.push_str(&prop);
            body.push_str(": ");
            body.push_str(&val);
            body.push_str(";\n");
        }
        let mut out = String::with_capacity(body.len() + escaped_selector.len() + 64);
        out.push_str("@container (min-width: ");
        out.push_str(&size_expr);
        out.push_str(") {\n  .");
        out.push_str(escaped_selector);
        out.push_str(" {\n");
        out.push_str(&body);
        out.push_str("  }\n}\n");
        Some(out)
    }

    fn expand_composite(&self, class_name: &str) -> Option<String> {
        let comp = if let Some(c) = composites::get(class_name) {
            c
        } else if class_name.starts_with("dx-class-") {
            composites::get(class_name)?
        } else {
            return None;
        };
        let resolve_tokens = |tokens: &[String]| -> (Vec<String>, Vec<String>) {
            let mut base_rules: Vec<String> = Vec::new();
            let mut anim_lines: Vec<String> = Vec::new();
            for t in tokens {
                if let Some(rest) = t.strip_prefix("animfill:") {
                    anim_lines.push(format!("ANIM|fill|{}", rest));
                    continue;
                }
                if let Some(rest) = t.strip_prefix("fluid:") {
                    let parts: Vec<&str> = rest.split(':').collect();
                    if parts.len() >= 5 {
                        let prop = parts[0];
                        let min_v = parts[1];
                        let min_bp_key = parts[2];
                        let max_v = parts[3];
                        let max_bp_key = parts[4];
                        let lookup_bp = |key: &str| -> Option<f32> {
                            if key.chars().all(|c| c.is_ascii_digit()) {
                                return key.parse::<f32>().ok();
                            }
                            self.screens.get(key).and_then(|v| {
                                if let Some(px) = v.strip_suffix("px") {
                                    px.parse().ok()
                                } else {
                                    None
                                }
                            })
                        };
                        if let (Some(min_bp), Some(max_bp)) =
                            (lookup_bp(min_bp_key), lookup_bp(max_bp_key))
                        {
                            let parse_val = |val: &str| -> Option<f32> {
                                let digits: String = val
                                    .chars()
                                    .take_while(|c| (c.is_ascii_digit() || *c == '.'))
                                    .collect();
                                digits.parse().ok()
                            };
                            if let (Some(min_num), Some(max_num)) =
                                (parse_val(min_v), parse_val(max_v))
                            {
                                let formula = format!(
                                    "clamp({}, calc({} + {} * (100vw - {}px) / ({} - {})), {})",
                                    min_v,
                                    min_v,
                                    (max_num - min_num),
                                    min_bp,
                                    max_bp,
                                    min_bp,
                                    max_v
                                );
                                base_rules.push(format!("{}: {}", prop, formula));
                                continue;
                            }
                        }
                        base_rules
                            .push(format!("{}: clamp({}, {}, {})", prop, min_v, min_v, max_v));
                        continue;
                    }
                } else if let Some(rest) = t.strip_prefix("motion:") {
                    let hash = format!("{:x}", seahash::hash(rest.as_bytes()));
                    let kf_name = format!("dx-motion-keyframe-{}", &hash[..6]);
                    let mut keyframes = String::from("@keyframes ");
                    keyframes.push_str(&kf_name);
                    keyframes.push_str(" {\n  0% { transform: translateY(0) scale(1); }\n  60% { transform: translateY(-6px) scale(1.04); }\n  80% { transform: translateY(2px) scale(0.98); }\n  100% { transform: translateY(0) scale(1); }\n}\n");
                    base_rules.push(format!(
                        "animation: {} 600ms cubic-bezier(0.34,1.56,0.64,1)",
                        kf_name
                    ));
                    base_rules.push(keyframes);
                    continue;
                } else if let Some(rest) = t.strip_prefix("gradient:mesh:") {
                    let colors: Vec<&str> =
                        rest.split('+').filter(|c| !c.trim().is_empty()).collect();
                    if colors.len() >= 2 {
                        let phi = std::f32::consts::PI * (3.0 - (5.0_f32).sqrt());
                        let mut layers: Vec<String> = Vec::new();
                        let n = colors.len() as f32;
                        for (i, c) in colors.iter().enumerate() {
                            let i_f = i as f32 + 0.5;
                            let r = i_f / n;
                            let theta = i_f * phi;
                            let x = 50.0 + r * 40.0 * theta.cos();
                            let y = 50.0 + r * 40.0 * theta.sin();
                            let sz = 120.0 - r * 40.0;
                            layers.push(format!(
                                "radial-gradient(circle at {:.1}% {:.1}%, {} {:.0}%)",
                                x,
                                y,
                                c.trim(),
                                sz.max(25.0)
                            ));
                        }
                        base_rules.push(format!("background-image: {}", layers.join(", ")));
                        base_rules.push("background-size: cover".to_string());
                        base_rules.push("background-blend-mode: screen, lighten".to_string());
                    }
                    continue;
                }
                if let Some(rule) = self.precompiled.get(t) {
                    base_rules.push(rule.clone());
                } else if let Some(c) = self.generate_color_css(t) {
                    base_rules.push(c);
                } else if let Some(d) = self.generate_dynamic_css(t) {
                    base_rules.push(d);
                } else if let Some(a) = self.generate_animation_css(t) {
                    if a.starts_with("ANIM|") {
                        anim_lines.push(a);
                    } else {
                        base_rules.push(a);
                    }
                }
            }
            (base_rules, anim_lines)
        };

        let mut sections: Vec<String> = Vec::new();
        let (base_rules, base_anim_lines) = resolve_tokens(&comp.base);
        let base_join = base_rules.join("; ");
        if !base_join.is_empty() {
            sections.push(format!("BASE|{}", base_join));
        }
        for (child, toks) in &comp.child_rules {
            let (decl_vec, anim_lines_child) = resolve_tokens(toks);
            let decls = decl_vec.join("; ");
            if !decls.is_empty() {
                sections.push(format!("CHILD|{}|{}", child, decls));
            }
            for a in anim_lines_child {
                sections.push(a);
            }
        }
        for (state, toks) in &comp.state_rules {
            let (decl_vec, anim_lines_state) = resolve_tokens(toks);
            let decls = decl_vec.join("; ");
            if !decls.is_empty() {
                sections.push(format!("STATE|{}|{}", state, decls));
            }
            for a in anim_lines_state {
                sections.push(a);
            }
        }
        for (attr, toks) in &comp.data_attr_rules {
            let (decl_vec, anim_lines_data) = resolve_tokens(toks);
            let decls = decl_vec.join("; ");
            if !decls.is_empty() {
                sections.push(format!("DATA|{}|{}", attr, decls));
            }
            for a in anim_lines_data {
                sections.push(a);
            }
        }
        for (cond, toks) in &comp.conditional_blocks {
            let (decl_vec, anim_lines_cond) = resolve_tokens(toks);
            let decls = decl_vec.join("; ");
            if !decls.is_empty() {
                sections.push(format!("COND|{}|{}", cond, decls));
            }
            for a in anim_lines_cond {
                sections.push(a);
            }
        }
        for line in base_anim_lines {
            sections.push(line);
        }
        for anim in &comp.animations {
            sections.push(format!("ANIM|{}", anim));
        }
        for raw in &comp.extra_raw {
            sections.push(format!("RAW|{}", raw));
        }
        if sections.is_empty() {
            return None;
        }
        Some(sections.join("\n"))
    }

    #[allow(dead_code)]
    pub fn generate_css_for_classes_batch<'a>(&self, class_names: &[&'a str]) -> Vec<String> {
        use std::collections::{HashMap, HashSet};
        let mut consumed: HashSet<&str> = HashSet::new();
        let mut out: Vec<String> = Vec::with_capacity(class_names.len());

        let mut index_map: HashMap<&str, usize> = HashMap::new();
        for (i, &c) in class_names.iter().enumerate() {
            index_map.insert(c, i);
        }

        for &name in class_names {
            if !name.starts_with("animate:") {
                continue;
            }
            if consumed.contains(name) {
                continue;
            }
            let rest = &name[8..];
            let mut parts = rest.split(':');
            let first_segment = parts.next().unwrap_or("1s").trim();
            let duration = first_segment;
            let delay = parts.next().unwrap_or("0s").trim();
            let mut inline_from: Vec<String> = Vec::new();
            let mut inline_to: Vec<String> = Vec::new();
            let mut inline_via: Vec<Vec<String>> = Vec::new();
            let mut inline_fill: Option<&str> = None;
            let base_token = name.split_whitespace().next().unwrap_or(name);
            if name.contains(' ') {
                for token in name.split_whitespace().skip(1) {
                    if token == "forwards" {
                        inline_fill = Some("forwards");
                        continue;
                    }
                    if let Some(inner) = token.strip_prefix("from(") {
                        if let Some(body) = inner.strip_suffix(')') {
                            if !body.is_empty() {
                                inline_from
                                    .push(body.split_whitespace().collect::<Vec<_>>().join("+"));
                            }
                            continue;
                        }
                    }
                    if let Some(inner) = token.strip_prefix("to(") {
                        if let Some(body) = inner.strip_suffix(')') {
                            if !body.is_empty() {
                                inline_to
                                    .push(body.split_whitespace().collect::<Vec<_>>().join("+"));
                            }
                            continue;
                        }
                    }
                    if let Some(inner) = token.strip_prefix("via(") {
                        if let Some(body) = inner.strip_suffix(')') {
                            if !body.is_empty() {
                                inline_via.push(vec![
                                    body.split_whitespace().collect::<Vec<_>>().join("+"),
                                ]);
                            }
                            continue;
                        }
                    }
                }
            }
            let mut from_tokens: Vec<String> = Vec::new();
            let mut to_tokens: Vec<String> = Vec::new();
            let mut via_groups: Vec<Vec<String>> = Vec::new();
            let mut fill_mode: Option<&str> = None;
            for &other in class_names {
                if other == name {
                    continue;
                }
                if other == "forwards" {
                    fill_mode = Some("forwards");
                    consumed.insert(other);
                    continue;
                }
                if let Some(inner) = other.strip_prefix("from(") {
                    if let Some(body) = inner.strip_suffix(')') {
                        let toks = body
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>();
                        if !toks.is_empty() {
                            from_tokens.push(toks.join("+"));
                        }
                        consumed.insert(other);
                        continue;
                    }
                }
                if let Some(inner) = other.strip_prefix("to(") {
                    if let Some(body) = inner.strip_suffix(')') {
                        let toks = body
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>();
                        if !toks.is_empty() {
                            to_tokens.push(toks.join("+"));
                        }
                        consumed.insert(other);
                        continue;
                    }
                }
                if let Some(inner) = other.strip_prefix("via(") {
                    if let Some(body) = inner.strip_suffix(')') {
                        let toks = body
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>();
                        if !toks.is_empty() {
                            via_groups.push(vec![toks.join("+")]);
                        }
                        consumed.insert(other);
                        continue;
                    }
                }
            }
            if !inline_from.is_empty()
                || !inline_to.is_empty()
                || !inline_via.is_empty()
                || inline_fill.is_some()
            {
                from_tokens.extend(inline_from);
                to_tokens.extend(inline_to);
                via_groups.extend(inline_via);
                if inline_fill.is_some() {
                    fill_mode = inline_fill;
                }
            }
            if from_tokens.is_empty() && to_tokens.is_empty() && via_groups.is_empty() {
                if let Some(css) = self.compute_css(name) {
                    out.push(css);
                }
                continue;
            }
            consumed.insert(name);
            let mut encoded_lines: Vec<String> = Vec::new();
            encoded_lines.push(format!("ANIM|animate|{}|{}", duration, delay));
            if let Some(f) = fill_mode {
                encoded_lines.push(format!("ANIM|fill|{}", f));
            }
            for ft in &from_tokens {
                encoded_lines.push(format!("ANIM|from|{}", ft));
            }
            for tg in &to_tokens {
                encoded_lines.push(format!("ANIM|to|{}", tg));
            }
            for vg in &via_groups {
                for v in vg {
                    encoded_lines.push(format!("ANIM|via|{}", v));
                }
            }
            let encoded_css = encoded_lines.join("\n");
            let mut escaped_ident = String::with_capacity(base_token.len() + 8);
            struct Acc<'a> {
                buf: &'a mut String,
            }
            impl<'a> fmt::Write for Acc<'a> {
                fn write_str(&mut self, s: &str) -> fmt::Result {
                    self.buf.push_str(s);
                    Ok(())
                }
            }
            if serialize_identifier(
                base_token,
                &mut Acc {
                    buf: &mut escaped_ident,
                },
            )
            .is_err()
            {
                for ch in base_token.chars() {
                    match ch {
                        ':' => escaped_ident.push_str("\\:"),
                        '@' => escaped_ident.push_str("\\@"),
                        '(' => escaped_ident.push_str("\\("),
                        ')' => escaped_ident.push_str("\\)"),
                        ' ' => escaped_ident.push_str("\\ "),
                        '/' => escaped_ident.push_str("\\/"),
                        '\\' => escaped_ident.push_str("\\\\"),
                        _ => escaped_ident.push(ch),
                    }
                }
            }
            let selector = format!(".{}", escaped_ident);
            let decoded = self.decode_encoded_css(&encoded_css, &selector, &[]);
            out.push(decoded);
        }

        for &name in class_names {
            if consumed.contains(name) {
                continue;
            }
            if name.starts_with("from(")
                || name.starts_with("to(")
                || name.starts_with("via(")
                || name == "forwards"
            {
                continue;
            }
            if let Some(css) = self.compute_css(name) {
                out.push(css);
            }
        }
        out
    }

    fn generate_dynamic_css(&self, class_name: &str) -> Option<String> {
        if let Some(arg) = class_name.strip_prefix("transition(") {
            if let Some(end) = arg.find(')') {
                let dur = &arg[..end];
                let duration = if dur.is_empty() { "150ms" } else { dur };
                return Some(format!(
                    "transition-property: all; transition-duration: {}; transition-timing-function: cubic-bezier(0.4,0,0.2,1)",
                    duration
                ));
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
            if let Some(val) = self.colors.get(name) {
                return Some(format!("background-color: {}", val));
            }
        }
        if let Some(name) = class_name.strip_prefix("text-") {
            if let Some(val) = self.colors.get(name) {
                return Some(format!("color: {}", val));
            }
        }
        None
    }

    fn generate_animation_css(&self, full_class: &str) -> Option<String> {
        if !full_class.starts_with("animate:") {
            return None;
        }
        let rest = &full_class[8..];
        let mut parts = rest.split(':');
        let duration = parts.next().unwrap_or("1s");
        let delay = parts.next().unwrap_or("0s");
        Some(format!("ANIM|animate|{}|{}", duration, delay))
    }
}

impl StyleEngine {
    fn decode_encoded_css(&self, css: &str, selector: &str, wrappers: &[String]) -> String {
        let is_encoded = css.contains("BASE|")
            || css.contains("STATE|")
            || css.contains("CHILD|")
            || css.contains("COND|")
            || css.contains("DATA|")
            || css.contains("RAW|")
            || css.contains("ANIM|");
        if !is_encoded {
            if wrappers.is_empty() {
                return build_block(selector, css);
            }
            let mut out = String::new();
            for w in wrappers {
                let sel = w.replace('&', selector);
                out.push_str(&build_block(&sel, css));
                out.push('\n');
            }
            if out.ends_with('\n') {
                out.pop();
            }
            return out;
        }
        let mut out = String::new();
        let mut pending_anim: Option<PendingAnimation> = None;
        let lines: Vec<&str> = if css.contains('\n') {
            css.lines().collect()
        } else {
            vec![css]
        };
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("BASE|") {
                let is_responsive_group = self
                    .screens
                    .keys()
                    .any(|bp| selector.starts_with(&format!(".{}\\(", bp)));
                if !is_responsive_group {
                    if wrappers.is_empty() {
                        out.push_str(&build_block(selector, rest));
                    } else {
                        for w in wrappers {
                            let sel = w.replace('&', selector);
                            out.push_str(&build_block(&sel, rest));
                            out.push('\n');
                        }
                        if out.ends_with('\n') {
                            out.pop();
                        }
                    }
                    out.push('\n');
                }
            } else if let Some(rest) = line.strip_prefix("STATE|") {
                let mut parts = rest.splitn(2, '|');
                let state = parts.next().unwrap_or("");
                let decls = parts.next().unwrap_or("");
                if state == "dark" {
                    out.push_str(&build_block(&format!(".dark {}", selector), decls));
                } else if state == "light" {
                    out.push_str(&build_block(&format!(":root {}", selector), decls));
                    out.push('\n');
                    out.push_str(&build_block(&format!(".light {}", selector), decls));
                } else {
                    out.push_str(&build_block(&format!("{}:{}", selector, state), decls));
                }
                out.push('\n');
            } else if let Some(rest) = line.strip_prefix("CHILD|") {
                let mut parts = rest.splitn(2, '|');
                let child = parts.next().unwrap_or("");
                let decls = parts.next().unwrap_or("");
                out.push_str(&build_block(&format!("{} > {}", selector, child), decls));
                out.push('\n');
            } else if let Some(rest) = line.strip_prefix("DATA|") {
                let mut parts = rest.splitn(2, '|');
                let data = parts.next().unwrap_or("");
                let decls = parts.next().unwrap_or("");
                out.push_str(&build_block(&format!("{}[data-{}]", selector, data), decls));
                out.push('\n');
            } else if let Some(rest) = line.strip_prefix("COND|") {
                let mut parts = rest.splitn(2, '|');
                let cond = parts.next().unwrap_or("");
                let decls = parts.next().unwrap_or("");
                if let Some(val) = cond.strip_prefix("@container>") {
                    out.push_str(&format!("@container (min-width: {}) {{\n", val));
                    for l in build_block(selector, decls).lines() {
                        out.push_str("  ");
                        out.push_str(l);
                        out.push('\n');
                    }
                    out.push_str("}\n");
                } else if let Some(bp) = cond.strip_prefix("screen:") {
                    if let Some(v) = self.screens.get(bp) {
                        out.push_str(&format!("@media (min-width: {}) {{\n", v));
                        for l in build_block(selector, decls).lines() {
                            out.push_str("  ");
                            out.push_str(l);
                            out.push('\n');
                        }
                        out.push_str("}\n");
                    }
                } else if let Some(rest) = cond.strip_prefix("self:child-count>") {
                    if let Ok(threshold) = rest.parse::<usize>() {
                        if threshold > 0 {
                            let hashed = format!(
                                "{}:has(> :nth-last-child(n+{}):first-child)",
                                selector, threshold
                            );
                            out.push_str(&build_block(&hashed, decls));
                            out.push('\n');
                        } else {
                            out.push_str(&build_block(selector, decls));
                            out.push('\n');
                        }
                    }
                }
            } else if let Some(rest) = line.strip_prefix("ANIM|") {
                let parts: Vec<&str> = rest.split('|').collect();
                if parts.is_empty() {
                    continue;
                }
                match parts[0] {
                    "animate" => {
                        let duration_val = parts.get(1).copied().unwrap_or("1s").to_string();
                        let delay_val = parts.get(2).copied().unwrap_or("0s").to_string();
                        let pa = pending_anim.get_or_insert(PendingAnimation {
                            duration: duration_val.clone(),
                            delay: delay_val.clone(),
                            fill_mode: String::new(),
                            from: Vec::new(),
                            via: Vec::new(),
                            to_: Vec::new(),
                            has_main: true,
                        });
                        pa.duration = duration_val;
                        pa.delay = delay_val;
                        pa.has_main = true;
                    }
                    "fill" => {
                        if let Some(mode) = parts.get(1) {
                            let pa = pending_anim.get_or_insert(PendingAnimation {
                                duration: "1s".into(),
                                delay: "0s".into(),
                                fill_mode: String::new(),
                                from: Vec::new(),
                                via: Vec::new(),
                                to_: Vec::new(),
                                has_main: false,
                            });
                            pa.fill_mode = (*mode).to_string();
                        }
                    }
                    "from" | "to" | "via" => {
                        if let Some(tokens) = parts.get(1) {
                            let pa = pending_anim.get_or_insert(PendingAnimation {
                                duration: "1s".into(),
                                delay: "0s".into(),
                                fill_mode: String::new(),
                                from: Vec::new(),
                                via: Vec::new(),
                                to_: Vec::new(),
                                has_main: false,
                            });
                            match parts[0] {
                                "from" => pa.from.push((*tokens).to_string()),
                                "to" => pa.to_.push((*tokens).to_string()),
                                "via" => pa.via.push((*tokens).to_string()),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            } else if let Some(raw) = line.strip_prefix("RAW|") {
                out.push_str(raw);
                if !raw.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
        if let Some(pa) = pending_anim.take() {
            if !pa.has_main {
                if out.ends_with('\n') {
                    out.pop();
                }
                return out;
            }
            let base_selector = if let Some(space_idx) = selector.find("\\ ") {
                &selector[..space_idx]
            } else {
                selector
            };
            let hash = format!("{:x}", seahash::hash(base_selector.as_bytes()));
            let mut frames: Vec<(u32, String)> = Vec::new();
            if !pa.from.is_empty() {
                frames.push((0, self.resolve_animation_tokens(&pa.from)));
            }
            if !pa.to_.is_empty() {
                frames.push((100, self.resolve_animation_tokens(&pa.to_)));
            }
            if !pa.via.is_empty() {
                let count = pa.via.len();
                for (i, v) in pa.via.iter().enumerate() {
                    let pct = ((i + 1) as f32) / ((count + 1) as f32) * 100.0;
                    frames.push((pct as u32, self.resolve_animation_tokens(&[v.clone()])));
                }
            }
            frames.sort_by_key(|(p, _)| *p);
            let mut kf_body = String::new();
            for (pct, decls) in &frames {
                let dtrim = decls.trim();
                if dtrim.is_empty() {
                    continue;
                }
                let line = if dtrim.ends_with(';') {
                    dtrim.to_string()
                } else {
                    format!("{};", dtrim)
                };
                kf_body.push_str(&format!("  {}% {{ {} }}\n", pct, line));
            }
            if !kf_body.is_empty() {
                out.push_str("@keyframes dx-animation-");
                out.push_str(&hash);
                out.push_str(" {\n");
                out.push_str(&kf_body);
                out.push_str("}\n\n");
                let mut parts: Vec<String> = Vec::new();
                parts.push(pa.duration.clone());
                if pa.delay != "0s" {
                    parts.push(pa.delay.clone());
                }
                if !pa.fill_mode.is_empty() {
                    parts.push(pa.fill_mode.clone());
                }
                parts.push(format!("dx-animation-{}", hash));
                let mut filtered: Vec<String> = Vec::new();
                let mut seen_fill = false;
                for p in parts.into_iter() {
                    if p.starts_with("from(") || p.starts_with("to(") || p.starts_with("via(") {
                        continue;
                    }
                    if p == "forwards" {
                        if seen_fill {
                            continue;
                        }
                        seen_fill = true;
                    }
                    filtered.push(p);
                }
                let value = filtered.join(" ");
                out.push_str(&build_block(
                    base_selector,
                    &format!("animation: {}", value),
                ));
            }
        }
        if out.ends_with('\n') {
            out.pop();
        }
        out
    }

    fn resolve_animation_tokens(&self, tokens: &[String]) -> String {
        let mut decls: Vec<String> = Vec::new();
        for t in tokens {
            for piece in t.split('+') {
                let piece = piece.trim();
                if piece.is_empty() {
                    continue;
                }
                if let Some(css) = self.precompiled.get(piece) {
                    decls.push(css.clone());
                    continue;
                }
                if let Some(rest) = piece.strip_prefix("opacity-") {
                    if let Ok(num) = rest.parse::<u32>() {
                        let val = if num >= 100 {
                            "1".to_string()
                        } else {
                            format!("{}", (num as f32) / 100.0)
                        };
                        decls.push(format!("opacity: {}", val));
                        continue;
                    }
                }
                if let Some(c) = self.generate_color_css(piece) {
                    decls.push(c);
                    continue;
                }
                if let Some(d) = self.generate_dynamic_css(piece) {
                    decls.push(d);
                    continue;
                }
            }
        }
        let mut last_for: HashMap<&str, usize> = HashMap::new();
        for (i, d) in decls.iter().enumerate() {
            if let Some(idx) = d.find(':') {
                let name = d[..idx].trim();
                last_for.insert(name, i);
            }
        }
        let mut out = String::new();
        for (i, d) in decls.iter().enumerate() {
            if let Some(idx) = d.find(':') {
                let name = d[..idx].trim();
                if last_for.get(name) == Some(&i) {
                    if !out.is_empty() {
                        out.push_str("; ");
                    }
                    out.push_str(d.trim().trim_end_matches(';'));
                }
            }
        }
        out
    }

    fn wrap_media_queries(&self, mut css_body: String, media_queries: &[String]) -> String {
        for mq in media_queries.iter().rev() {
            let mut wrapped = String::new();
            wrapped.push_str(mq);
            wrapped.push_str(" {\n");
            for line in css_body.trim_end().lines() {
                if line.is_empty() {
                    continue;
                }
                wrapped.push_str("  ");
                wrapped.push_str(line);
                wrapped.push('\n');
            }
            wrapped.push_str("}\n");
            css_body = wrapped;
        }
        if !css_body.ends_with('\n') {
            css_body.push('\n');
        }
        css_body
    }
}

fn build_block(selector: &str, declarations: &str) -> String {
    let decl_raw = declarations.trim().trim_end_matches(';').trim();
    let mut seen: HashMap<&str, usize> = HashMap::new();
    let parts: Vec<&str> = if decl_raw.is_empty() {
        Vec::new()
    } else if decl_raw.contains(';') {
        decl_raw.split(';').collect()
    } else {
        vec![decl_raw]
    };
    for (i, p) in parts.iter().enumerate() {
        if let Some(idx) = p.find(':') {
            seen.insert(p[..idx].trim(), i);
        }
    }
    let mut s = String::with_capacity(selector.len() + decl_raw.len() + 16);
    s.push_str(selector);
    s.push_str(" {\n");
    for (i, p) in parts.iter().enumerate() {
        let pt = p.trim();
        if pt.is_empty() {
            continue;
        }
        let name = pt.split(':').next().unwrap_or("").trim();
        if seen.get(name) == Some(&i) {
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
    while out.ends_with(";;") {
        out.pop();
    }
    if let Some(pos) = out.find("--transform-scale-x, --transform-scale-y:") {
        if let Some(val_start) = out[pos..].find(':') {
            let val_start_abs = pos + val_start + 1;
            if val_start_abs < out.len() {
                let value = out[val_start_abs..].split(';').next().unwrap_or("").trim();
                let replacement = format!(
                    "--transform-scale-x: {v}; --transform-scale-y: {v}",
                    v = value
                );
                if let Some(end_seg) = out[val_start_abs..].find(';') {
                    let end_abs = val_start_abs + end_seg + 1;
                    out.replace_range(pos..end_abs, &replacement);
                } else {
                    out.replace_range(pos..out.len(), &replacement);
                }
            }
        }
    }
    out
}
