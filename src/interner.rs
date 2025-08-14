use std::collections::HashMap;

// Simple non-thread-safe interner. Wrap in RwLock/Arc externally for concurrency.
pub struct ClassInterner {
    map: HashMap<String, u32>,
    strings: Vec<String>,
    escaped: Vec<String>,
}

#[allow(dead_code)]
impl ClassInterner {
    pub fn new() -> Self {
        Self { map: HashMap::new(), strings: Vec::new(), escaped: Vec::new() }
    }

    #[inline]
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.map.get(s) { return id; }
        let id = self.strings.len() as u32;
        self.strings.push(s.to_string());
        // Precompute escaped selector form (escape ':' and '@') once.
        let mut esc = String::with_capacity(s.len() + 4);
        for ch in s.chars() {
            match ch { ':' => esc.push_str("\\:"), '@' => esc.push_str("\\@"), _ => esc.push(ch) }
        }
        self.escaped.push(esc);
        self.map.insert(self.strings[id as usize].clone(), id);
        id
    }

    #[inline]
    pub fn get(&self, id: u32) -> &str { &self.strings[id as usize] }

    #[inline]
    pub fn escaped(&self, id: u32) -> &str { &self.escaped[id as usize] }

    pub fn len(&self) -> usize { self.strings.len() }
}
