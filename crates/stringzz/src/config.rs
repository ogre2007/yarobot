// Alternative config.rs with fluent interface
use pyo3::prelude::*;

#[pyclass]
#[derive(Debug, Clone)]
pub struct Config {
    #[pyo3(get, set)]
    pub min_string_len: usize,
    #[pyo3(get, set)]
    pub max_string_len: usize,
    #[pyo3(get, set)]
    pub max_file_size_mb: usize,
    #[pyo3(get, set)]
    pub recursive: bool,
    #[pyo3(get, set)]
    pub extensions: Option<Vec<String>>,
    #[pyo3(get, set)]
    pub extract_opcodes: bool,
    #[pyo3(get, set)]
    pub debug: bool,
}

// Internal builder struct (not exposed to Python)
#[derive(Default)]
struct InternalConfigBuilder {
    min_string_len: Option<usize>,
    max_string_len: Option<usize>,
    max_file_size_mb: Option<usize>,
    recursive: Option<bool>,
    extensions: Option<Vec<String>>,
    extract_opcodes: Option<bool>,
    debug: Option<bool>,
}

impl InternalConfigBuilder {
    fn new() -> Self {
        Self::default()
    }

    fn min_string_len(mut self, value: usize) -> Self {
        self.min_string_len = Some(value);
        self
    }

    fn max_string_len(mut self, value: usize) -> Self {
        self.max_string_len = Some(value);
        self
    }

    fn max_file_size_mb(mut self, value: usize) -> Self {
        self.max_file_size_mb = Some(value);
        self
    }

    fn recursive(mut self, value: bool) -> Self {
        self.recursive = Some(value);
        self
    }

    fn extensions(mut self, value: Vec<String>) -> Self {
        self.extensions = Some(value);
        self
    }

    fn extract_opcodes(mut self, value: bool) -> Self {
        self.extract_opcodes = Some(value);
        self
    }

    fn debug(mut self, value: bool) -> Self {
        self.debug = Some(value);
        self
    }

    fn build(self) -> PyResult<Config> {
        let config = Config {
            min_string_len: self.min_string_len.unwrap_or(5),
            max_string_len: self.max_string_len.unwrap_or(128),
            max_file_size_mb: self.max_file_size_mb.unwrap_or(10),
            recursive: self.recursive.unwrap_or(false),
            extensions: self.extensions,
            extract_opcodes: self.extract_opcodes.unwrap_or(false),
            debug: self.debug.unwrap_or(false),
        };

        config.validate()?;
        Ok(config)
    }
}

#[pymethods]
impl Config {
    #[new]
    #[pyo3(signature = (
        min_string_len = None,
        max_string_len = None,
        max_file_size_mb = None,
        recursive = None,
        extensions = None,
        extract_opcodes = None,
        debug = None
    ))]
    pub fn new(
        min_string_len: Option<usize>,
        max_string_len: Option<usize>,
        max_file_size_mb: Option<usize>,
        recursive: Option<bool>,
        extensions: Option<Vec<String>>,
        extract_opcodes: Option<bool>,
        debug: Option<bool>,
    ) -> PyResult<Self> {
        let mut builder = InternalConfigBuilder::new();

        if let Some(v) = min_string_len {
            builder = builder.min_string_len(v);
        }
        if let Some(v) = max_string_len {
            builder = builder.max_string_len(v);
        }
        if let Some(v) = max_file_size_mb {
            builder = builder.max_file_size_mb(v);
        }
        if let Some(v) = recursive {
            builder = builder.recursive(v);
        }
        if let Some(v) = extensions {
            builder = builder.extensions(v);
        }
        if let Some(v) = extract_opcodes {
            builder = builder.extract_opcodes(v);
        }
        if let Some(v) = debug {
            builder = builder.debug(v);
        }

        builder.build()
    }

    #[staticmethod]
    pub fn create(
        min_string_len: Option<usize>,
        max_string_len: Option<usize>,
        max_file_size_mb: Option<usize>,
        recursive: Option<bool>,
        extensions: Option<Vec<String>>,
        extract_opcodes: Option<bool>,
        debug: Option<bool>,
    ) -> PyResult<Self> {
        Self::new(
            min_string_len,
            max_string_len,
            max_file_size_mb,
            recursive,
            extensions,
            extract_opcodes,
            debug,
        )
    }

    pub fn validate(&self) -> PyResult<()> {
        if self.min_string_len > self.max_string_len {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "min_string_len ({}) cannot be greater than max_string_len ({})",
                self.min_string_len, self.max_string_len
            )));
        }
        if self.min_string_len == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "min_string_len must be at least 1",
            ));
        }
        if self.max_file_size_mb == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_file_size_mb must be at least 1",
            ));
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        InternalConfigBuilder::new().build().unwrap()
    }
}
