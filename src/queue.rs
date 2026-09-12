use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    Normal,
    Security,
}
#[derive(Debug)]
pub struct BoundedPriorityQueue<T> {
    capacity: usize,
    items: VecDeque<(Priority, T)>,
    pub dropped: u64,
}
impl<T> BoundedPriorityQueue<T> {
    pub fn new(capacity: usize) -> Result<Self, &'static str> {
        if capacity == 0 {
            return Err("queue capacity must be positive");
        }
        Ok(Self {
            capacity,
            items: VecDeque::new(),
            dropped: 0,
        })
    }
    pub fn push(&mut self, priority: Priority, item: T) -> bool {
        if self.items.len() == self.capacity {
            if let Some(pos) = self.items.iter().position(|(p, _)| *p < priority) {
                self.items.remove(pos);
                self.dropped += 1;
            } else {
                self.dropped += 1;
                return false;
            }
        }
        self.items.push_back((priority, item));
        true
    }
    pub fn pop(&mut self) -> Option<T> {
        let pos = self
            .items
            .iter()
            .enumerate()
            .max_by_key(|(_, (p, _))| *p)
            .map(|(i, _)| i)?;
        self.items.remove(pos).map(|(_, v)| v)
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
