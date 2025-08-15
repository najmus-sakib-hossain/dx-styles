use oxc_allocator::Allocator;
use oxc_ast::ast::{
    self, ExportDefaultDeclarationKind, JSXAttributeItem, JSXOpeningElement, Program,
};
use oxc_parser::Parser;
use oxc_span::SourceType;
use std::collections::{HashSet, HashMap};
use crate::composites::{self, Composite};
use crate::interner::ClassInterner;
use std::fs;
use std::path::Path;

pub fn parse_classnames(path: &Path) -> HashSet<String> {
    let source_text = fs::read_to_string(path).unwrap_or_default();
    if source_text.is_empty() {
        return HashSet::new();
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
    components: HashMap<String, Vec<String>>, // component name -> utilities
}

impl ClassNameVisitor {
    // Expand grouping syntax inside a single class attribute string.
    // Supported forms:
    // 1. prefix(a b c) where prefix is a screen, state, or container query -> prefix:a prefix:b ...
    // 2. componentName(a b c) defines a component (first definition wins) and expands to its utilities.
    // 3. +componentName(a b c) additive override: expands base component utilities + provided ones.
    // 4. -componentName(p m) subtractive override: removes any base utilities starting with listed prefixes.
    // 5. Plain componentName token (no parentheses) expands to its utilities if previously defined.
    fn expand_grouping(&mut self, raw: &str) -> Vec<String> {
        // Static sets (could be generated from config, hardcoded for now)
        // Note: keep in sync with styles.toml if updated.
        const SCREENS: &[&str] = &["xs","sm","md","lg","xl","2xl"];
    const STATES: &[&str] = &[
            "hover","focus","focus-within","focus-visible","active","visited","disabled","checked","first","last","odd","even","required","optional","valid","invalid","read-only","before","after","placeholder","file","marker","selection","group-hover","group-focus","group-active","group-visited","peer-checked","peer-focus","peer-active","peer-hover","empty","target"
        ];
        const CQS: &[&str] = &["@xs","@sm","@md","@lg","@xl","@2xl","@3xl","@4xl","@5xl","@6xl","@7xl","@8xl","@9xl"];
        let screens: HashSet<&str> = SCREENS.iter().copied().collect();
        let states: HashSet<&str> = STATES.iter().copied().collect();
        let cqs: HashSet<&str> = CQS.iter().copied().collect();

    let mut out = Vec::new();
    // Working composite under construction per raw attribute string.
    let mut pending: Option<Composite> = None;
    let mut ensure = |pending: &mut Option<Composite>| { if pending.is_none() { *pending = Some(Composite::default()); } };
        let mut i = 0usize;
        let bytes = raw.as_bytes();
        while i < bytes.len() {
            // skip whitespace
            while i < bytes.len() && bytes[i].is_ascii_whitespace() { i += 1; }
            if i >= bytes.len() { break; }
            // read ident (allow + - @ letters digits _ -)
            let start = i;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if c == '(' || c.is_ascii_whitespace() { break; }
                i += 1;
            }
            let ident = &raw[start..i];
            // group or plain?
            if i < bytes.len() && bytes[i] as char == '(' {
                // find matching ')'
                i += 1; // skip '('
                let inner_start = i;
                let mut depth = 1;
                while i < bytes.len() && depth > 0 {
                    let c = bytes[i] as char;
                    if c == '(' { depth += 1; }
                    else if c == ')' { depth -= 1; }
                    i += 1;
                }
                let inner_end = i.saturating_sub(1);
                let inner = &raw[inner_start..inner_end];
                // split inner by whitespace into utilities/prefix filters
                let inner_tokens: Vec<String> = inner.split_whitespace().filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
                if ident.starts_with('+') || ident.starts_with('-') {
                    // Variant path: build final token list then collapse to composite class.
                    let additive = ident.starts_with('+');
                    let cname = ident.trim_start_matches(|c| c == '+' || c == '-');
                    let mut tokens: Vec<String> = Vec::new();
                    if let Some(base) = self.components.get(cname) { tokens.extend(base.iter().cloned()); }
                    if additive {
                        tokens.extend(inner_tokens.into_iter());
                    } else { // subtractive: treat provided as prefixes to remove
                        let filters = inner_tokens;
                        let mut filtered: Vec<String> = Vec::new();
                        'tok: for t in tokens.into_iter() {
                            for f in &filters { if t.starts_with(f) { continue 'tok; } }
                            filtered.push(t);
                        }
                        tokens = filtered;
                    }
                    // Hash and register composite
                    if !tokens.is_empty() {
                        let composite_class = composites::get_or_create(&tokens);
                        out.push(composite_class);
                    }
                } else if screens.contains(ident) {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending { c.conditional_blocks.push((format!("screen:{}", ident), inner_tokens)); }
                } else if states.contains(ident) || cqs.contains(ident) || ident == "dark" || ident == "light" {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending { c.state_rules.push((ident.to_string(), inner_tokens)); }
                } else if ident == "div" || ident == "span" || ident == "p" || ident == "h1" || ident == "h2" || ident == "h3" || ident == "h4" || ident == "h5" || ident == "h6" || ident == "ul" || ident == "li" || ident == "section" || ident == "header" || ident == "footer" || ident == "main" || ident == "nav" {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending { c.child_rules.push((ident.to_string(), inner_tokens)); }
                } else if ident.starts_with('*') {
                    ensure(&mut pending);
                    let attr_name = ident.trim_start_matches('*').to_string();
                    if let Some(c) = &mut pending { c.data_attr_rules.push((attr_name, inner_tokens)); }
                } else if ident.starts_with('?') {
                    // Conditional query DSL e.g. ?@container>640px(...)
                    ensure(&mut pending);
                    if let Some(c) = &mut pending { c.conditional_blocks.push((ident[1..].to_string(), inner_tokens)); }
                } else if ident.starts_with('~') {
                    // Fluid scaling ~prop(min@sm, max@lg)
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        let prop = ident.trim_start_matches('~');
                        if inner_tokens.len() >= 2 {
                            let parse_part = |s: &str| -> Option<(String,String)> { let mut parts = s.split('@'); let v = parts.next()?.to_string(); let bp = parts.next().unwrap_or("base").to_string(); Some((v,bp)) };
                            if let (Some((min_v, min_bp)), Some((max_v, max_bp))) = (parse_part(&inner_tokens[0]), parse_part(&inner_tokens[1])) {
                                let token = format!("fluid:{}:{}:{}:{}:{}", prop, min_v, min_bp, max_v, max_bp);
                                c.base.push(token);
                            }
                        }
                    }
                } else if ident == "mesh" {
                    // mesh gradient: normalize inner to colors list
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        let mut colors: Vec<String> = Vec::new();
                        let mut buf = String::new();
                        for ch in inner.chars() {
                            match ch {
                                '[' | ']' | ',' => { if !buf.trim().is_empty() { colors.push(buf.trim().trim_matches(']').trim_matches('[').to_string()); } buf.clear(); },
                                _ => buf.push(ch),
                            }
                        }
                        if !buf.trim().is_empty() { colors.push(buf.trim().to_string()); }
                        if !colors.is_empty() { c.base.push(format!("gradient:mesh:{}", colors.join("+"))); }
                    }
                } else if ident.starts_with('$') {
                    // Generated single-purpose utility -> collapse to composite hashed class immediately
                    if !inner_tokens.is_empty() {
                        let cname = &ident[1..];
                        let composite_class = composites::get_or_create(&inner_tokens);
                        // also register the alias name itself mapping to composite class usage
                        self.components.entry(cname.to_string()).or_insert(inner_tokens.clone());
                        out.push(composite_class);
                    }
                } else if ident == "from" || ident == "to" || ident == "via" {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        // encode animation stage
                        let stage = ident.to_string();
                        let line = format!("animstage|{}|{}", stage, inner_tokens.join("+"));
                        c.animations.push(line);
                    }
                } else if ident == "motion" {
                    ensure(&mut pending);
                    if let Some(c) = &mut pending {
                        c.base.push(format!("motion:{}", inner_tokens.join("_")));
                    }
                } else {
                    // component definition
                    if !self.components.contains_key(ident) {
                        self.components.insert(ident.to_string(), inner_tokens.clone());
                    }
                    // expand for this element
                    if let Some(list) = self.components.get(ident) { ensure(&mut pending); if let Some(c)= &mut pending { c.base.extend(list.iter().cloned()); } }
                }
            } else {
                // plain token
                if ident.starts_with('_') {
                    // scoped component definition like _highlight(a b)
                    if !self.components.contains_key(ident) { /* do not persist globally */ }
                    ensure(&mut pending);
                    if let Some(c) = &mut pending { c.base.push(ident.to_string()); }
                } else if ident == "forwards" {
                    ensure(&mut pending); if let Some(c)= &mut pending { c.base.push("animfill:forwards".to_string()); }
                } else if let Some(list) = self.components.get(ident) { ensure(&mut pending); if let Some(c)= &mut pending { c.base.extend(list.iter().cloned()); } }
                else { ensure(&mut pending); if let Some(c)= &mut pending { c.base.push(ident.to_string()); } }
            }
        }
        if let Some(c) = pending {
            // If composite has only simple base tokens and no advanced features we can still return raw tokens for backward compatibility.
            if c.child_rules.is_empty() && c.state_rules.is_empty() && c.data_attr_rules.is_empty() && c.conditional_blocks.is_empty() && c.extra_raw.is_empty() && c.animations.is_empty() {
                out.extend(c.base);
            } else {
                let class_name = composites::get_or_create_full(c);
                out.push(class_name);
            }
        }
        out
    }
}

impl ClassNameVisitor {
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
                            for cn in expanded { self.class_names.insert(cn); }
                        }
                    }
                }
            }
        }
    }
}
