use std::sync::RwLock;

pub struct SingletonCache<T> (RwLock<T>) where T: Sized + Clone + Default;

#[allow(dead_code)]
impl<T> SingletonCache<T> where T: Sized + Clone + Default {
    pub fn new() -> Self {
        Self(RwLock::new(Default::default()))
    }

    pub fn from_initial_value(initial_value: T) -> Self {
        Self(RwLock::new(initial_value))
    }

    pub fn put(&self, value: T) {
        *self.0.write().unwrap() = value;
    }

    pub fn get(&self) -> T {
        self.0.read().unwrap().clone()
    }
}

impl<T> Default for SingletonCache<T> where T: Sized + Clone + Default {
    fn default() -> Self {
        Self::new()
    }
}
