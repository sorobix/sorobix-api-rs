#[derive(Debug, Clone)]
pub struct Args {
    pub fee: u32,
}

impl Default for Args {
    fn default() -> Self {
        Self { fee: 100 }
    }
}
