use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Default)]
pub struct SecurityContext {
    /// key -> set of values
    pub attrs: HashMap<String, HashSet<String>>,
}

impl SecurityContext {
    pub fn set_attr(&mut self, key: &str, value: &str) {
        self.attrs
            .entry(key.to_string())
            .or_default()
            .insert(value.to_string());
    }

    pub fn clear_attr(&mut self, key: &str) {
        self.attrs.remove(key);
    }

    pub fn has(&self, key: &str, value: &str) -> bool {
        self.attrs
            .get(key)
            .map(|vals| vals.contains(value))
            .unwrap_or(false)
    }

    /// Merge another context into this one
    pub fn merge(&mut self, other: &SecurityContext) {
        for (k, v) in &other.attrs {
            self.attrs.entry(k.clone()).or_default().extend(v.iter().cloned());
        }
    }
}