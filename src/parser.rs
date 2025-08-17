use crate::composites::{self, Composite};
use crate::interner::ClassInterner;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    self, ExportDefaultDeclarationKind, JSXAttributeItem, JSXOpeningElement, Program,
};
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

pub fn parse_classnames(path: &Path) -> HashSet<String> {
    let source_text = fs::read_to_string(path).unwrap_or_default();
    if source_text.is_empty() {
        return HashSet::new();
    }

    if matches!(path.extension().and_then(|s| s.to_str()), Some("html")) {
        let mut set = HashSet::new();
        static CLASS_RE: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
            Regex::new(r#"(?i)class\s*=\s*(?:"([^"]+)"|'([^']+)')"#).unwrap()
        });
        for caps in CLASS_RE.captures_iter(&source_text) {
            if let Some(val) = caps.get(1).or_else(|| caps.get(2)) {
                for token in val.as_str().split(|c: char| c.is_whitespace()) {
                    let token = token.trim();
                    if !token.is_empty() {
                        set.insert(token.to_string());
                    }
                }
            }
        }
        return set;
    }

    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_jsx(true);
    let ret = Parser::new(&allocator, &source_text, source_type).parse();

    let mut visitor = ClassNameVisitor {
        class_names: HashSet::new(),
        components: HashMap::new(),
    };
    visitor.visit_program(&ret.program);
    visitor.class_names
}

pub fn parse_classnames_ids(path: &Path, interner: &mut ClassInterner) -> HashSet<u32> {
    let raw = parse_classnames(path);
    raw.into_iter().map(|s| interner.intern(&s)).collect()
}

struct ClassNameVisitor {
    class_names: HashSet<String>,
    components: HashMap<String, Vec<String>>,
}

impl ClassNameVisitor {
    fn expand_grouping(&mut self, raw: &str) -> Vec<String> {
        const SCREENS: &[&str] = &["xs", "sm", "md", "lg", "xl", "2xl"];
        const STATES: &[&str] = &[
            "hover",
            "focus",
            "focus-within",
            "focus-visible",
            "active",
            "visited",
            "disabled",
            "checked",
            "first",
            "last",
            "odd",
            "even",
            "required",
            "optional",
            "valid",
            "invalid",
            "read-only",
            "before",
            "after",
            "placeholder",
            "file",
            "marker",
            "selection",
            "group-hover",
            "group-focus",
            "group-active",
            "group-visited",
            "peer-checked",
            "peer-focus",
            "peer-active",
            "peer-hover",
            "empty",
            "target",
        ];
        const CQS: &[&str] = &[
            "@xs", "@sm", "@md", "@lg", "@xl", "@2xl", "@3xl", "@4xl", "@5xl", "@6xl", "@7xl",
            "@8xl", "@9xl",
        ];
        let screens: HashSet<&str> = SCREENS.iter().copied().collect();
        let states: HashSet<&str> = STATES.iter().copied().collect();
        let cqs: HashSet<&str> = CQS.iter().copied().collect();

        let mut out = Vec::new();
        let mut pending: Option<Composite> = None;
        let mut local_components: HashMap<String, Vec<String>> = HashMap::new();
        let ensure = |pending: &mut Option<Composite>| {
            if pending.is_none() {
                *pending = Some(Composite::default());
            }
        };
        let mut i = 0usize;
        let bytes = raw.as_bytes();
        let mut animate_mode = false;
        let mut animate_group_start: Option<usize> = None;
        while i < bytes.len() {
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() {
                break;
            }
            let start = i;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if c == '(' || c.is_ascii_whitespace() {
                    break;
                }
                i += 1;
            }
            let ident = &raw[start..i];
            if i < bytes.len() && bytes[i] as char == '(' {
                i += 1;
                let inner_start = i;
                let mut depth = 1;
                while i < bytes.len() && depth > 0 {
                    let c = bytes[i] as char;
                    if c == '(' {
                        depth += 1;
                    } else if c == ')' {
                        depth -= 1;
                    }
                    i += 1;
                }
                let inner_end = i.saturating_sub(1);
                let inner = &raw[inner_start..inner_end];
                let mut nested_children: Vec<(String, Vec<String>)> = Vec::new();
                let _simple_inner_source = inner.to_string();
                {
                    let chars: Vec<char> = inner.chars().collect();
                    let mut j = 0usize;
                    while j < chars.len() {
                        if chars[j].is_alphabetic() {
                            let start_tag = j;
                            while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '-')
                            {
                                j += 1;
                            }
                            if j < chars.len() && chars[j] == '(' {
                                j += 1;
                                let content_start = j;
                                let mut d = 1;
                                while j < chars.len() && d > 0 {
                                    if chars[j] == '(' {
                                        d += 1;
                                    } else if chars[j] == ')' {
                                        d -= 1;
                                    }
                                    j += 1;
                                }
                                let content_end = j.saturating_sub(1);
                                let tag = inner[start_tag..]
                                    .split('(')
                                    .next()
                                    .unwrap_or("")
                                    .to_string();
                                let content = &inner[content_start..content_end];
                                let toks: Vec<String> = content
                                    .split_whitespace()
                                    .filter(|s| !s.is_empty())
                                    .map(|s| s.to_string())
                                    .collect();
                                if !tag.is_empty() && !toks.is_empty() {
                                    nested_children.push((tag, toks));
                                }
                            }
                        } else {
                            j += 1;
                        }
                    }
                }
                if !nested_children.is_empty() {}
                let inner_tokens: Vec<String> = inner
                    .split(|c: char| c.is_whitespace() || c == ',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.trim().trim_end_matches(',').to_string())
                    .collect();
                if ident.starts_with('+') || ident.starts_with('-') {
                    let additive = ident.starts_with('+');
                    let cname = ident.trim_start_matches(|c| c == '+' || c == '-');
                    let mut tokens: Vec<String> = Vec::new();
                    if let Some(base) = self.components.get(cname) {
                        tokens.extend(base.iter().cloned());
                    }
                    if let Some(base) = local_components.get(cname) {
                        tokens.extend(base.iter().cloned());
                    }
                    if additive {
                        tokens.extend(inner_tokens.into_iter());
                    } else {
                        let filters = inner_tokens;
                        let mut filtered: Vec<String> = Vec::new();
                        'tok: for t in tokens.into_iter() {
                            for f in &filters {
                                if t.starts_with(f) {
                                    continue 'tok;
                                }
                            }
                            filtered.push(t);
                        }
                        tokens = filtered;
                    }
                    if !tokens.is_empty() {
                        let composite_class = composites::get_or_create(&tokens);
                        out.push(composite_class);
                    }
                } else if screens.contains(ident) {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        c.conditional_blocks
                            .push((format!("screen:{}", ident), inner_tokens));
                    }
                } else if states.contains(ident)
                    || cqs.contains(ident)
                    || ident == "dark"
                    || ident == "light"
                {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        c.state_rules.push((ident.to_string(), inner_tokens));
                    }
                } else if ident == "div"
                    || ident == "span"
                    || ident == "p"
                    || ident == "h1"
                    || ident == "h2"
                    || ident == "h3"
                    || ident == "h4"
                    || ident == "h5"
                    || ident == "h6"
                    || ident == "ul"
                    || ident == "li"
                    || ident == "section"
                    || ident == "header"
                    || ident == "footer"
                    || ident == "main"
                    || ident == "nav"
                {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        c.child_rules.push((ident.to_string(), inner_tokens));
                    }
                    if let Some(c) = &mut pending {
                        for (tag, toks) in nested_children {
                            c.child_rules.push((tag, toks));
                        }
                    }
                } else if ident.starts_with('*') {
                    ensure(&mut pending);
                    let attr_name = ident.trim_start_matches('*').to_string();
                    if let Some(c) = &mut pending {
                        c.data_attr_rules.push((attr_name, inner_tokens));
                    }
                } else if ident.starts_with('?') {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        let cond = &ident[1..];
                        if let Some(rest) = cond.strip_prefix("@self:") {
                            c.conditional_blocks
                                .push((format!("self:{}", rest), inner_tokens));
                        } else {
                            c.conditional_blocks.push((cond.to_string(), inner_tokens));
                        }
                    }
                } else if ident.starts_with('~') {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        let raw_prop = ident.trim_start_matches('~');
                        let prop = if raw_prop == "text" {
                            "font-size"
                        } else {
                            raw_prop
                        };
                        let pieces: Vec<&str> = inner
                            .split(',')
                            .map(|s| s.trim())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if pieces.len() >= 2 {
                            let parse_part = |s: &str| -> Option<(String, String)> {
                                let mut parts = s.split('@');
                                let v = parts.next()?.trim().to_string();
                                let bp = parts.next().unwrap_or("base").trim().to_string();
                                Some((v, bp))
                            };
                            if let (Some((min_v, min_bp)), Some((max_v, max_bp))) =
                                (parse_part(pieces[0]), parse_part(pieces[1]))
                            {
                                c.base.push(format!(
                                    "fluid:{}:{}:{}:{}:{}",
                                    prop, min_v, min_bp, max_v, max_bp
                                ));
                            }
                        }
                    }
                } else if ident == "mesh" {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        let mut colors: Vec<String> = Vec::new();
                        let mut buf = String::new();
                        for ch in inner.chars() {
                            match ch {
                                '[' | ']' | ',' => {
                                    if !buf.trim().is_empty() {
                                        colors.push(
                                            buf.trim()
                                                .trim_matches(']')
                                                .trim_matches('[')
                                                .to_string(),
                                        );
                                    }
                                    buf.clear();
                                }
                                _ => buf.push(ch),
                            }
                        }
                        if !buf.trim().is_empty() {
                            colors.push(buf.trim().to_string());
                        }
                        if !colors.is_empty() {
                            c.base.push(format!("gradient:mesh:{}", colors.join("+")));
                        }
                    }
                } else if ident == "transition" {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        let duration = inner_tokens
                            .get(0)
                            .cloned()
                            .unwrap_or_else(|| "150ms".to_string());
                        c.base.push(format!("transition({})", duration));
                    }
                } else if ident.starts_with('$') {
                    if !inner_tokens.is_empty() {
                        let cname = &ident[1..];
                        let composite_class = composites::get_or_create(&inner_tokens);
                        self.components
                            .entry(cname.to_string())
                            .or_insert(inner_tokens.clone());
                        out.push(composite_class);
                    }
                } else if ident.starts_with('_') {
                    let cname = ident.trim_start_matches('_');
                    local_components
                        .entry(cname.to_string())
                        .or_insert(inner_tokens.clone());
                    ensure(&mut pending);
                } else if ident == "from" || ident == "to" || ident == "via" {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        let stage = ident.to_string();
                        let line = format!("{}|{}", stage, inner_tokens.join("+"));
                        c.animations.push(line);
                        if !animate_mode { /* stage without animate: prefix; treat as independent grouping */
                        }
                    }
                } else if ident == "motion" {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        c.base.push(format!("motion:{}", inner_tokens.join("_")));
                    }
                } else {
                    if !self.components.contains_key(ident) {
                        self.components
                            .insert(ident.to_string(), inner_tokens.clone());
                    }
                    if let Some(list) = self.components.get(ident) {
                        ensure(&mut pending);
                        if let Some(c) = &mut pending {
                            c.base.extend(list.iter().cloned());
                        }
                    }
                }

                let should_finalize = if animate_mode { false } else { true };
                if should_finalize {
                    if let Some(mut c_emit) = pending.take() {
                        let expand_component_tokens = |tokens: &mut Vec<String>| {
                            let mut expanded: Vec<String> = Vec::new();
                            for t in tokens.iter() {
                                if let Some(name) = t.strip_prefix('$') {
                                    if let Some(base) = self.components.get(name) {
                                        expanded.extend(base.clone());
                                        continue;
                                    }
                                    if let Some(base) = local_components.get(name) {
                                        expanded.extend(base.clone());
                                        continue;
                                    }
                                } else if let Some(name) = t.strip_prefix('_') {
                                    if let Some(base) = local_components.get(name) {
                                        expanded.extend(base.clone());
                                        continue;
                                    }
                                    if let Some(base) = self.components.get(name) {
                                        expanded.extend(base.clone());
                                        continue;
                                    }
                                }
                                expanded.push(t.clone());
                            }
                            *tokens = expanded;
                        };
                        for (_, toks) in c_emit.state_rules.iter_mut() {
                            expand_component_tokens(toks);
                        }
                        for (_, toks) in c_emit.child_rules.iter_mut() {
                            expand_component_tokens(toks);
                        }
                        for (_, toks) in c_emit.data_attr_rules.iter_mut() {
                            expand_component_tokens(toks);
                        }
                        for (_, toks) in c_emit.conditional_blocks.iter_mut() {
                            expand_component_tokens(toks);
                        }
                        expand_component_tokens(&mut c_emit.base);
                        let slice_start = animate_group_start.unwrap_or(start);
                        let class_name =
                            composites::register_grouping_raw(raw[slice_start..i].trim(), c_emit);
                        out.push(class_name);
                        animate_group_start = None;
                    }
                }
            } else {
                if ident.starts_with('_') {
                    ensure(&mut pending);
                    let cname = ident.trim_start_matches('_');
                    if let Some(local) = local_components.get(cname) {
                        if let Some(c) = &mut pending {
                            c.base.extend(local.clone());
                        }
                    } else if let Some(global) = self.components.get(cname) {
                        if let Some(c) = &mut pending {
                            c.base.extend(global.clone());
                        }
                    }
                } else if ident == "forwards" {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        c.base.push("animfill:forwards".to_string());
                    }
                    if animate_mode { /* still inside animate chain */ }
                } else if let Some(list) = self.components.get(ident) {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        c.base.extend(list.iter().cloned());
                    }
                } else {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        c.base.push(ident.to_string());
                        if ident.starts_with("animate:") {
                            animate_mode = true;
                            animate_group_start = Some(start);
                        } else if animate_mode {
                            animate_mode = false;
                        }
                    }
                }
                if !animate_mode {
                    if let Some(c) = &pending {
                        if !c.animations.is_empty() {
                            if let Some(mut emit) = pending.take() {
                                let expand_component_tokens = |tokens: &mut Vec<String>| {
                                    let mut expanded: Vec<String> = Vec::new();
                                    for t in tokens.iter() {
                                        if let Some(name) = t.strip_prefix('$') {
                                            if let Some(base) = self.components.get(name) {
                                                expanded.extend(base.clone());
                                                continue;
                                            }
                                            if let Some(base) = local_components.get(name) {
                                                expanded.extend(base.clone());
                                                continue;
                                            }
                                        } else if let Some(name) = t.strip_prefix('_') {
                                            if let Some(base) = local_components.get(name) {
                                                expanded.extend(base.clone());
                                                continue;
                                            }
                                            if let Some(base) = self.components.get(name) {
                                                expanded.extend(base.clone());
                                                continue;
                                            }
                                        }
                                        expanded.push(t.clone());
                                    }
                                    *tokens = expanded;
                                };
                                for (_, toks) in emit.state_rules.iter_mut() {
                                    expand_component_tokens(toks);
                                }
                                for (_, toks) in emit.child_rules.iter_mut() {
                                    expand_component_tokens(toks);
                                }
                                for (_, toks) in emit.data_attr_rules.iter_mut() {
                                    expand_component_tokens(toks);
                                }
                                for (_, toks) in emit.conditional_blocks.iter_mut() {
                                    expand_component_tokens(toks);
                                }
                                expand_component_tokens(&mut emit.base);
                                let slice_start = animate_group_start.unwrap_or(start);
                                let class_name = composites::register_grouping_raw(
                                    raw[slice_start..i].trim(),
                                    emit,
                                );
                                out.push(class_name);
                                animate_group_start = None;
                            }
                        }
                    }
                }
            }
        }
        if let Some(c) = pending {
            if !c.animations.is_empty() {
                let slice_start = animate_group_start.unwrap_or(0);
                let class_name = composites::register_grouping_raw(raw[slice_start..].trim(), c);
                out.push(class_name);
            } else {
                out.extend(c.base);
            }
        }
        out
    }

    fn visit_program(&mut self, program: &Program) {
        for stmt in &program.body {
            self.visit_statement(stmt);
        }
    }

    fn visit_statement(&mut self, stmt: &ast::Statement) {
        match stmt {
            ast::Statement::ExpressionStatement(stmt) => self.visit_expression(&stmt.expression),
            ast::Statement::BlockStatement(stmt) => {
                for s in &stmt.body {
                    self.visit_statement(s);
                }
            }
            ast::Statement::ReturnStatement(stmt) => {
                if let Some(arg) = &stmt.argument {
                    self.visit_expression(arg);
                }
            }
            ast::Statement::IfStatement(stmt) => {
                self.visit_statement(&stmt.consequent);
                if let Some(alt) = &stmt.alternate {
                    self.visit_statement(alt);
                }
            }
            ast::Statement::VariableDeclaration(decl) => {
                for var in &decl.declarations {
                    if let Some(init) = &var.init {
                        self.visit_expression(init);
                    }
                }
            }
            ast::Statement::FunctionDeclaration(decl) => self.visit_function(decl),
            ast::Statement::ExportNamedDeclaration(decl) => {
                if let Some(decl) = &decl.declaration {
                    self.visit_declaration(decl);
                }
            }
            ast::Statement::ExportDefaultDeclaration(decl) => {
                self.visit_export_default_declaration(decl)
            }
            _ => {}
        }
    }

    fn visit_declaration(&mut self, decl: &ast::Declaration) {
        match decl {
            ast::Declaration::FunctionDeclaration(func) => self.visit_function(func),
            ast::Declaration::VariableDeclaration(var_decl) => {
                for var in &var_decl.declarations {
                    if let Some(init) = &var.init {
                        self.visit_expression(init);
                    }
                }
            }
            _ => {}
        }
    }

    fn visit_export_default_declaration(&mut self, decl: &ast::ExportDefaultDeclaration) {
        match &decl.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(func) => self.visit_function(func),
            ExportDefaultDeclarationKind::ArrowFunctionExpression(expr) => {
                for stmt in &expr.body.statements {
                    self.visit_statement(stmt);
                }
            }
            kind => {
                if let Some(expr) = kind.as_expression() {
                    self.visit_expression(expr);
                }
            }
        }
    }

    fn visit_function(&mut self, func: &ast::Function) {
        if let Some(body) = &func.body {
            for stmt in &body.statements {
                self.visit_statement(stmt);
            }
        }
    }

    fn visit_expression(&mut self, expr: &ast::Expression) {
        match expr {
            ast::Expression::JSXElement(elem) => self.visit_jsx_element(elem),
            ast::Expression::JSXFragment(frag) => self.visit_jsx_fragment(frag),
            ast::Expression::ConditionalExpression(expr) => {
                self.visit_expression(&expr.consequent);
                self.visit_expression(&expr.alternate);
            }
            ast::Expression::ArrowFunctionExpression(expr) => {
                for stmt in &expr.body.statements {
                    self.visit_statement(stmt);
                }
            }
            ast::Expression::ParenthesizedExpression(expr) => {
                self.visit_expression(&expr.expression)
            }
            _ => {}
        }
    }

    fn visit_jsx_element(&mut self, elem: &ast::JSXElement) {
        self.visit_jsx_opening_element(&elem.opening_element);
        for child in &elem.children {
            self.visit_jsx_child(child);
        }
    }

    fn visit_jsx_fragment(&mut self, frag: &ast::JSXFragment) {
        for child in &frag.children {
            self.visit_jsx_child(child);
        }
    }

    fn visit_jsx_child(&mut self, child: &ast::JSXChild) {
        match child {
            ast::JSXChild::Element(elem) => self.visit_jsx_element(elem),
            ast::JSXChild::Fragment(frag) => self.visit_jsx_fragment(frag),
            ast::JSXChild::ExpressionContainer(container) => {
                if let Some(expr) = container.expression.as_expression() {
                    self.visit_expression(expr);
                }
            }
            _ => {}
        }
    }

    fn visit_jsx_opening_element(&mut self, elem: &JSXOpeningElement) {
        for attr in &elem.attributes {
            if let JSXAttributeItem::Attribute(attr) = attr {
                if let ast::JSXAttributeName::Identifier(ident) = &attr.name {
                    if ident.name == "className" {
                        if let Some(ast::JSXAttributeValue::StringLiteral(lit)) = &attr.value {
                            let expanded = self.expand_grouping(&lit.value);
                            for cn in expanded {
                                self.class_names.insert(cn);
                            }
                        }
                    }
                }
            }
        }
    }
}
