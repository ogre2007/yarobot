// config.rs
use derive_builder::Builder;
use pyo3::prelude::*;

#[pyclass]
#[derive(Debug, Clone, Builder)]
#[builder(setter(into, strip_option), default)]
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
    #[pyo3(get, set)]
    pub parallel_processing: bool,
}

// Remove your custom build() method from ConfigBuilder
// derive_builder automatically generates one

// Add a validation method instead
impl ConfigBuilder {
    // Rename to avoid conflict with auto-generated build()
    pub fn build_validated(self) -> Result<Config, String> {
        let config = self.build().map_err(|e| e.to_string())?;

        // Validate
        if config.min_string_len > config.max_string_len {
            return Err("min_string_len cannot be greater than max_string_len".into());
        }
        if config.min_string_len == 0 {
            return Err("min_string_len must be at least 1".into());
        }

        Ok(config)
    }
}

// The builder() method is generated as ConfigBuilder::default(),
// not Config::builder(). We need to add that manually.

impl Config {
    // Add static method to create a builder
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

#[pymethods]
impl Config {
    #[new]
    pub fn py_new(
        min_string_len: Option<usize>,
        max_string_len: Option<usize>,
        max_file_size_mb: Option<usize>,
        recursive: Option<bool>,
        extensions: Option<Vec<String>>,
        extract_opcodes: Option<bool>,
        debug: Option<bool>,
        parallel_processing: Option<bool>,
    ) -> PyResult<Self> {
        Config::builder()
            .min_string_len(min_string_len.unwrap_or(5))
            .max_string_len(max_string_len.unwrap_or(128))
            .max_file_size_mb(max_file_size_mb.unwrap_or(10))
            .recursive(recursive.unwrap_or(false))
            .extensions(extensions.unwrap_or_default())
            .extract_opcodes(extract_opcodes.unwrap_or(false))
            .debug(debug.unwrap_or(false))
            .parallel_processing(parallel_processing.unwrap_or(false))
            .build()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /* Expose builder to Python
    #[staticmethod]
    pub fn create_builder() -> PyResult<PyConfigBuilder> {
        Ok(PyConfigBuilder::new())
    }*/
}

impl Default for Config {
    fn default() -> Self {
        ConfigBuilder::default().build().unwrap()
    }
}
