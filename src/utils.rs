use pyo3::prelude::*;
use regex::Regex;
use std::fs;
use std::io::Read;
use walkdir::WalkDir; 



/// Remove non-ASCII characters from bytes, keeping printable ASCII 0x20..0x7E
#[pyfunction]
pub fn remove_non_ascii_drop(data: &[u8]) -> PyResult<Vec<u8>> {
    Ok(data
        .iter()
        .filter(|&&b| b > 31 && b < 127)
        .cloned()
        .collect())
}

/// Gets the contents of a file (limited to 1024 characters)
#[pyfunction]
pub fn get_file_content(file: String) -> PyResult<String> {
    match fs::File::open(file) {
        Ok(mut f) => {
            let mut buffer = String::new();
            if let Ok(_) = f.read_to_string(&mut buffer) {
                // Limit to 1024 characters
                if buffer.len() > 1024 {
                    buffer.truncate(1024);
                }
                Ok(buffer)
            } else {
                Ok("not found".to_string())
            }
        }
        Err(_) => Ok("not found".to_string()),
    }
}

/// Check if data contains only ASCII characters
#[pyfunction]
pub fn is_ascii_string(data: &[u8], padding_allowed: bool) -> PyResult<bool> {
    for &b in data {
        if padding_allowed {
            if !((b > 31 && b < 127) || b == 0) {
                return Ok(false);
            }
        } else {
            if !(b > 31 && b < 127) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Check if string is valid base64
#[pyfunction]
pub fn is_base_64(s: String) -> PyResult<bool> {
    if s.len() % 4 != 0 {
        return Ok(false);
    }

    let re = Regex::new(r"^[A-Za-z0-9+/]+={0,2}$").unwrap();
    Ok(re.is_match(&s))
}

/// Get files from folder, optionally recursively
#[pyfunction]
pub fn get_files(folder: String, not_recursive: bool) -> PyResult<Vec<String>> {
    let mut files = Vec::new();

    if not_recursive {
        if let Ok(entries) = fs::read_dir(&folder) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(path_str) = path.to_str() {
                        files.push(path_str.to_string());
                    }
                }
            }
        }
    } else {
        for entry in WalkDir::new(&folder).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                if let Some(path_str) = entry.path().to_str() {
                    files.push(path_str.to_string());
                }
            }
        }
    }

    Ok(files)
}

/// Check if string is hex encoded
#[pyfunction]
pub fn is_hex_encoded(s: String, check_length: bool) -> PyResult<bool> {
    if s.len() == 0 {
        Ok(false)
    } else {
        let re = Regex::new(r"^[A-Fa-f0-9]+$").unwrap();

        if !re.is_match(&s) {
            return Ok(false);
        }

        if check_length {
            Ok(s.len() % 2 == 0)
        } else {
            Ok(true)
        }
    }
}
