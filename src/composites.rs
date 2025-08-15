use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;

// Rich composite structure supporting:
// - base declarations (utility tokens)
// - child rules: (selector suffix, utility tokens)
// - conditional blocks: (at-rule, utility tokens) where selector injected
// - extra raw blocks: fully formed CSS blocks (e.g. @keyframes)
//
// Tokens are stored (not resolved) so the engine can reuse existing resolution logic.
#[derive(Clone, Debug, Default)]
pub struct Composite {
    pub base: Vec<String>,
    pub child_rules: Vec<(String, Vec<String>)>,
    pub conditional_blocks: Vec<(String, Vec<String>)>,
    pub extra_raw: Vec<String>,
}

#[derive(Default)]
struct CompositeRegistry {
    // hash -> assigned class name
    map: HashMap<String, String>,
    // class name -> composite
    data: HashMap<String, Composite>,
}

static REGISTRY: Lazy<RwLock<CompositeRegistry>> = Lazy::new(|| RwLock::new(CompositeRegistry::default()));

fn hash_composite(c: &Composite) -> String {
    use seahash::SeaHasher;
    use std::hash::{Hash, Hasher};
    let mut h = SeaHasher::new();
    // canonicalize by sorting copies (order-insensitive dedupe for now)
    let mut base = c.base.clone(); base.sort(); base.hash(&mut h);
    let mut childs: Vec<String> = c.child_rules.iter().map(|(s, toks)| {
        let mut t = toks.clone(); t.sort(); format!("{}=>{}", s, t.join(","))
    }).collect();
    childs.sort(); childs.hash(&mut h);
    let mut conds: Vec<String> = c.conditional_blocks.iter().map(|(a, toks)| {
        let mut t = toks.clone(); t.sort(); format!("{}=>{}", a, t.join(","))
    }).collect();
    conds.sort(); conds.hash(&mut h);
    let mut extra = c.extra_raw.clone(); extra.sort(); extra.hash(&mut h);
    format!("{:x}", h.finish())
}

pub fn get_or_create(tokens: &[String]) -> String {
    // Backwards compatibility helper: only base tokens.
    let composite = Composite { base: tokens.to_vec(), ..Default::default() };
    get_or_create_full(composite)
}

pub fn get_or_create_full(c: Composite) -> String {
    let hash = hash_composite(&c);
    let mut reg = REGISTRY.write().unwrap();
    if let Some(existing) = reg.map.get(&hash) { return existing.clone(); }
    let class_name = format!("dx-c-{}", &hash[..8.min(hash.len())]);
    reg.map.insert(hash, class_name.clone());
    reg.data.insert(class_name.clone(), c);
    class_name
}

pub fn get(class_name: &str) -> Option<Composite> {
    let reg = REGISTRY.read().unwrap();
    reg.data.get(class_name).cloned()
}

pub fn iter_all() -> Vec<(String, Composite)> {
    let reg = REGISTRY.read().unwrap();
    reg.data.iter().map(|(k,v)| (k.clone(), v.clone())).collect()
}
