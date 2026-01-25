use crate::context::sec_ctx::SecurityContext;

#[derive(Debug, Clone)]
pub struct ContextStack {
    stack: Vec<(Option<String>, SecurityContext)>, // (optional name, context)
}

impl Default for ContextStack {
    fn default() -> Self {
        Self {
            stack: vec![(None, SecurityContext::default())],
        } // start with base context
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
        if let Some(pos) = self
            .stack
            .iter()
            .rposition(|(n, _)| n.as_deref() == Some(name))
        {
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
