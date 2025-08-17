use cssparser::serialize_identifier;
use std::collections::HashMap;
use std::fmt;

pub struct ClassInterner {
    map: HashMap<String, u32>,
    strings: Vec<String>,
    escaped: Vec<String>,
}

#[allow(dead_code)]
impl ClassInterner {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            strings: Vec::new(),
            escaped: Vec::new(),
        }
    }

    #[inline]
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.map.get(s) {
            return id;
        }
        let id = self.strings.len() as u32;
        self.strings.push(s.to_string());
        let mut escaped = String::with_capacity(s.len() + 8);
        struct Acc<'a> {
            buf: &'a mut String,
        }
        impl<'a> fmt::Write for Acc<'a> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.buf.push_str(s);
                Ok(())
            }
        }
        let serialize_result = {
            let mut acc = Acc { buf: &mut escaped };
            serialize_identifier(s, &mut acc)
        };
        if serialize_result.is_err() {
            escaped.clear();
            for ch in s.chars() {
                match ch {
                    ':' => escaped.push_str("\\:"),
                    '@' => escaped.push_str("\\@"),
                    '(' => escaped.push_str("\\("),
                    ')' => escaped.push_str("\\)"),
                    ' ' => escaped.push_str("\\ "),
                    '/' => escaped.push_str("\\/"),
                    '\\' => escaped.push_str("\\\\"),
                    _ => escaped.push(ch),
                }
            }
        }
        self.escaped.push(escaped);
        self.map.insert(self.strings[id as usize].clone(), id);
        id
    }

    #[inline]
    pub fn get(&self, id: u32) -> &str {
        &self.strings[id as usize]
    }

    #[inline]
    pub fn escaped(&self, id: u32) -> &str {
        &self.escaped[id as usize]
    }

    pub fn len(&self) -> usize {
        self.strings.len()
    }
}
