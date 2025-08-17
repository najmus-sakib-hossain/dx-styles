use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Clone, Debug, Default)]
pub struct Composite {
    pub base: Vec<String>,
    pub child_rules: Vec<(String, Vec<String>)>,
    pub state_rules: Vec<(String, Vec<String>)>,
    pub data_attr_rules: Vec<(String, Vec<String>)>,
    pub conditional_blocks: Vec<(String, Vec<String>)>,
    pub extra_raw: Vec<String>,
    pub animations: Vec<String>,
}

#[derive(Default)]
struct CompositeRegistry {
    map: HashMap<String, String>,
    data: HashMap<String, Composite>,
}

static REGISTRY: Lazy<RwLock<CompositeRegistry>> =
    Lazy::new(|| RwLock::new(CompositeRegistry::default()));

fn hash_composite(c: &Composite) -> String {
    use seahash::SeaHasher;
    use std::hash::{Hash, Hasher};
    let mut h = SeaHasher::new();
    let mut base = c.base.clone();
    base.sort();
    base.hash(&mut h);
    let mut childs: Vec<String> = c
        .child_rules
        .iter()
        .map(|(s, toks)| {
            let mut t = toks.clone();
            t.sort();
            format!("{}=>{}", s, t.join(","))
        })
        .collect();
    childs.sort();
    childs.hash(&mut h);
    let mut conds: Vec<String> = c
        .conditional_blocks
        .iter()
        .map(|(a, toks)| {
            let mut t = toks.clone();
            t.sort();
            format!("{}=>{}", a, t.join(","))
        })
        .collect();
    conds.sort();
    conds.hash(&mut h);
    let mut states: Vec<String> = c
        .state_rules
        .iter()
        .map(|(s, toks)| {
            let mut t = toks.clone();
            t.sort();
            format!("{}=>{}", s, t.join(","))
        })
        .collect();
    states.sort();
    states.hash(&mut h);
    let mut datas: Vec<String> = c
        .data_attr_rules
        .iter()
        .map(|(s, toks)| {
            let mut t = toks.clone();
            t.sort();
            format!("{}=>{}", s, t.join(","))
        })
        .collect();
    datas.sort();
    datas.hash(&mut h);
    let mut anims = c.animations.clone();
    anims.sort();
    anims.hash(&mut h);
    let mut extra = c.extra_raw.clone();
    extra.sort();
    extra.hash(&mut h);
    format!("{:x}", h.finish())
}

pub fn get_or_create(tokens: &[String]) -> String {
    let composite = Composite {
        base: tokens.to_vec(),
        ..Default::default()
    };
    get_or_create_full(composite)
}

pub fn get_or_create_full(c: Composite) -> String {
    let hash = hash_composite(&c);
    let mut reg = REGISTRY.write().unwrap();
    if let Some(existing) = reg.map.get(&hash) {
        return existing.clone();
    }
    let class_name = format!("dx-class-{}", &hash[..8.min(hash.len())]);
    reg.map.insert(hash, class_name.clone());
    reg.data.insert(class_name.clone(), c);
    class_name
}

pub fn register_grouping_raw(raw: &str, c: Composite) -> String {
    let mut reg = REGISTRY.write().unwrap();
    reg.data.entry(raw.to_string()).or_insert(c);
    raw.to_string()
}

pub fn get(class_name: &str) -> Option<Composite> {
    let reg = REGISTRY.read().unwrap();
    reg.data.get(class_name).cloned()
}

#[allow(dead_code)]
pub fn iter_all() -> Vec<(String, Composite)> {
    let reg = REGISTRY.read().unwrap();
    reg.data
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}
