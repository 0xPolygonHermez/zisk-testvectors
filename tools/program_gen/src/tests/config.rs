#[derive(Clone)]
pub struct ProgramConfig {
    pub module_name: String,
    pub header: Vec<String>,
    pub minimal: bool,
}

impl ProgramConfig {
    pub fn new(module_name: &str) -> Self {
        Self { module_name: module_name.to_string(), header: vec![], minimal: false }
    }

    pub fn with_header(mut self, header: &[&str]) -> Self {
        self.header = header.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_minimal(mut self, minimal: bool) -> Self {
        self.minimal = minimal;
        self
    }
}
