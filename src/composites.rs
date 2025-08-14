use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;

// A composite represents a finalized set of concrete utility class tokens
// produced from a component usage (+/- variants etc). We map the *ordered*
// canonical list (joined with a null separator) to a stable generated class.
static REGISTRY: Lazy<RwLock<CompositeRegistry>> = Lazy::new(|| RwLock::new(CompositeRegistry::default()));

#[derive(Default)]
struct CompositeRegistry {
    // canonical_key -> assigned class name
    map: HashMap<String, String>,
    // reverse mapping (not strictly needed yet) class -> canonical_key
    rev: HashMap<String, String>,
    counter: u64,
}

fn hash_rules(tokens: &[String]) -> String {
    use seahash::SeaHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = SeaHasher::new();
    for t in tokens { t.hash(&mut hasher); }
    format!("{:x}", hasher.finish())
}

// Public API -----------------------------------------------------------------

pub fn get_or_create(tokens: &[String]) -> String {
    // Canonical ordering: sort (stable) for deterministic key unaffected by
    // original author order once semantics are resolved.
    // NOTE: If later we need order-sensitive utilities (e.g. multiple shadows)
    // we can change to preserve order for those specific prefixes.
    let mut canonical: Vec<String> = tokens.iter().cloned().collect();
    canonical.sort();
    let hash = hash_rules(&canonical);
    let mut reg = REGISTRY.write().unwrap();
    if let Some(existing) = reg.map.get(&hash) { return existing.clone(); }
    // Assign new class name.
    let class_name = format!("dx-c-{}", &hash[..8.min(hash.len())]);
    reg.map.insert(hash.clone(), class_name.clone());
    reg.rev.insert(class_name.clone(), canonical.join("\0"));
    class_name
}

pub fn iter_pairs() -> Vec<(String, Vec<String>)> {
    let reg = REGISTRY.read().unwrap();
    reg.map.iter().map(|(k, v)| {
        let toks = reg.rev.get(v).map(|s| s.split('\0').map(|x| x.to_string()).collect()).unwrap_or_default();
        (v.clone(), toks)
    }).collect()
}
