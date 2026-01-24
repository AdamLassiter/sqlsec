use std::collections::{HashMap, HashSet};

use crate::get_context_stack;

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

#[derive(Debug, Clone)]
pub struct ContextStack {
    stack: Vec<(Option<String>, SecurityContext)>, // (optional name, context)
}

impl Default for ContextStack {
    fn default() -> Self {
        Self { stack: vec![(None, SecurityContext::default())] } // start with base context
    }
}

impl ContextStack {
    pub fn current(&self) -> &SecurityContext {
        &self.stack.last().unwrap().1
    }

    pub fn current_mut(&mut self) -> &mut SecurityContext {
        &mut self.stack.last_mut().unwrap().1
    }

    pub fn push(&mut self, name: Option<String>) {
        let new_ctx = self.current().clone();
        self.stack.push((name, new_ctx));
    }

    pub fn pop(&mut self) -> Option<(Option<String>, SecurityContext)> {
        if self.stack.len() > 1 {
            self.stack.pop()
        } else {
            None // never pop the base context
        }
    }

    pub fn push_named(&mut self, name: &str) {
        self.push(Some(name.to_string()));
    }

    pub fn pop_named(&mut self, name: &str) -> Option<SecurityContext> {
        if let Some(pos) = self.stack.iter().rposition(|(n, _)| n.as_deref() == Some(name)) {
            Some(self.stack.remove(pos).1)
        } else {
            None
        }
    }

     /// Context used for access checks
    pub fn effective(&self) -> &SecurityContext {
        &self.stack.last().unwrap().1
    }
}

pub(crate) fn effective_context(db_ptr: usize) -> SecurityContext {
    get_context_stack(db_ptr).effective().clone()
}