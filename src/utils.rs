use goblin::pe::PE;
use log::debug;
use md5;
use pyo3::prelude::*;
use regex::Regex;
use std::fs;
use std::io::Read;
use walkdir::WalkDir;

/// Get different PE attributes and hashes using goblin
#[pyfunction]
pub fn get_pe_info(file_data: &[u8]) -> PyResult<(String, Vec<String>)> {
    let mut imphash = String::new();
    let mut exports = Vec::new();

    // Quick reject: not PE
    if file_data.len() < 2 || &file_data[0..2] != b"MZ" {
        return Ok((imphash, exports));
    }

    // Cheap PE signature validation
    if file_data.len() < 0x40 {
        return Ok((imphash, exports));
    }

    let e_lfanew = u32::from_le_bytes(file_data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;

    if e_lfanew + 4 > file_data.len() {
        return Ok((imphash, exports));
    }

    if &file_data[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return Ok((imphash, exports));
    }

    // Parse with goblin
    match PE::parse(file_data) {
        Ok(pe) => {
            imphash = calculate_imphash(&pe).unwrap_or_default();

            for export in pe.exports {
                if let Some(name) = export.name {
                    exports.push(name.to_string());
                }
            }
        }
        Err(e) => {
            debug!("goblin parse failed: {}", e);
        }
    }

    Ok((imphash, exports))
}

/// Calculate imphash from PE (simplified implementation)
fn calculate_imphash(pe: &PE) -> Option<String> {
    let mut imports_data = Vec::new();

    for import in &pe.imports {
        imports_data.push(import.dll.to_lowercase());
        imports_data.push(import.name.to_lowercase());
        imports_data.push(format!("ordinal_{}", import.ordinal));
    }

    if imports_data.is_empty() {
        return None;
    }

    imports_data.sort();
    let combined = imports_data.join(",");

    Some(format!("{:x}", md5::compute(combined)))
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_get_pe_info() {
        // Test with non-PE data
        let non_pe_data = b"Not a PE file";
        let (imphash, exports) = get_pe_info(non_pe_data).unwrap();
        assert!(imphash.is_empty());
        assert!(exports.is_empty());

        // Test with small data (less than 0x40 bytes)
        let small_data = vec![0x4D, 0x5A]; // MZ header only
        let (imphash, exports) = get_pe_info(&small_data).unwrap();
        assert!(imphash.is_empty());
        assert!(exports.is_empty());

        // Note: Testing with actual PE files would require real PE binaries
        // For unit tests, we mainly verify the error handling paths
    }

    #[test]
    fn test_remove_non_ascii_drop() {
        // Test with only ASCII characters
        let ascii_data = b"Hello World!";
        let result = remove_non_ascii_drop(ascii_data).unwrap();
        assert_eq!(result, ascii_data);

        // Test with non-ASCII characters
        let mixed_data = b"Hello\x00World\xFF\x7F\xFE";
        let result = remove_non_ascii_drop(mixed_data).unwrap();
        assert_eq!(result, b"HelloWorld");

        // Test with empty data
        let empty_data = b"";
        let result = remove_non_ascii_drop(empty_data).unwrap();
        assert_eq!(result, b"");

        // Test with only non-ASCII characters
        let non_ascii_data = &[0x00, 0xFF, 0xFE, 0x01];
        let result = remove_non_ascii_drop(non_ascii_data).unwrap();
        assert_eq!(result, b"");
    }

    #[test]
    fn test_get_file_content() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        // Test with existing file
        let content = "Hello World! This is a test file content.";
        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        drop(file);

        let result = get_file_content(file_path.to_str().unwrap().to_string()).unwrap();
        assert_eq!(result, content);

        // Test with file that doesn't exist
        let result = get_file_content("non_existent_file.txt".to_string()).unwrap();
        assert_eq!(result, "not found");

        // Test with file content longer than 1024 characters
        let long_content = "A".repeat(1500);
        let file_path2 = temp_dir.path().join("long.txt");
        let mut file = File::create(&file_path2).unwrap();
        file.write_all(long_content.as_bytes()).unwrap();
        drop(file);

        let result = get_file_content(file_path2.to_str().unwrap().to_string()).unwrap();
        assert_eq!(result.len(), 1024);
        assert!(result.starts_with('A'));
    }

    #[test]
    fn test_is_ascii_string() {
        // Test with valid ASCII (no padding)
        let ascii_data = b"Hello World!";
        let result = is_ascii_string(ascii_data, false).unwrap();
        assert!(result);

        // Test with valid ASCII (with padding allowed)
        let ascii_with_null = b"Hello\x00World";
        let result = is_ascii_string(ascii_with_null, true).unwrap();
        assert!(result);

        // Test with non-ASCII (no padding)
        let non_ascii_data = b"Hello\xFFWorld";
        let result = is_ascii_string(non_ascii_data, false).unwrap();
        assert!(!result);

        // Test with non-ASCII (with padding)
        let non_ascii_with_null = b"Hello\xFF\x00World";
        let result = is_ascii_string(non_ascii_with_null, true).unwrap();
        assert!(!result);

        // Test with empty data
        let empty_data = b"";
        let result = is_ascii_string(empty_data, false).unwrap();
        assert!(result);

        // Test with only null bytes (padding allowed)
        let null_data = &[0x00, 0x00, 0x00];
        let result = is_ascii_string(null_data, true).unwrap();
        assert!(result);

        // Test with only null bytes (padding not allowed)
        let result = is_ascii_string(null_data, false).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_is_base_64() {
        // Valid base64 strings
        assert!(is_base_64("SGVsbG8=".to_string()).unwrap());
        assert!(!is_base_64("SGVsbG8".to_string()).unwrap());
        assert!(is_base_64("SGVsbG8h".to_string()).unwrap());
        assert!(is_base_64("U29tZSB0ZXh0".to_string()).unwrap());
        assert!(!is_base_64("".to_string()).unwrap()); // empty string is valid

        // Invalid base64 strings
        assert!(!is_base_64("SGVsbG8!".to_string()).unwrap()); // invalid character
        assert!(!is_base_64("SGVsbG8===".to_string()).unwrap()); // too many padding
        assert!(!is_base_64("SGVsbG".to_string()).unwrap()); // wrong length
        assert!(!is_base_64("SGVsbG===".to_string()).unwrap()); // wrong padding
        assert!(!is_base_64("ABC=DEF".to_string()).unwrap()); // padding in middle
    }

    #[test]
    fn test_get_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create test directory structure
        let dir1 = temp_dir.path().join("dir1");
        let dir2 = temp_dir.path().join("dir2");
        fs::create_dir_all(&dir1).unwrap();
        fs::create_dir_all(&dir2).unwrap();

        // Create test files
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = dir1.join("file2.txt");
        let file3 = dir2.join("file3.txt");

        File::create(&file1).unwrap();
        File::create(&file2).unwrap();
        File::create(&file3).unwrap();

        // Test non-recursive
        let files = get_files(temp_dir.path().to_str().unwrap().to_string(), true).unwrap();
        assert_eq!(files.len(), 1); // Only file1.txt in root
        assert!(files[0].contains("file1.txt"));

        // Test recursive
        let files = get_files(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        assert_eq!(files.len(), 3); // All three files
        assert!(files.iter().any(|f| f.contains("file1.txt")));
        assert!(files.iter().any(|f| f.contains("file2.txt")));
        assert!(files.iter().any(|f| f.contains("file3.txt")));

        // Test with non-existent directory
        let files = get_files("/non/existent/directory".to_string(), true).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_is_hex_encoded() {
        // Valid hex strings with length check
        assert!(is_hex_encoded("48656C6C6F".to_string(), true).unwrap());
        assert!(is_hex_encoded("0123456789ABCDEF".to_string(), true).unwrap());
        assert!(is_hex_encoded("abcdef".to_string(), true).unwrap());
        assert!(!is_hex_encoded("".to_string(), true).unwrap()); // empty string

        // Invalid hex strings
        assert!(!is_hex_encoded("48656C6C6G".to_string(), true).unwrap()); // invalid character
        assert!(!is_hex_encoded("Hello".to_string(), true).unwrap()); // non-hex characters
        assert!(!is_hex_encoded("48 65 6C 6C 6F".to_string(), true).unwrap()); // spaces

        // Test with length check disabled
        assert!(is_hex_encoded("48656C6C6".to_string(), false).unwrap()); // odd length allowed
        assert!(is_hex_encoded("ABC".to_string(), false).unwrap()); // odd length allowed

        // Test with length check enabled for odd length
        assert!(!is_hex_encoded("48656C6C6".to_string(), true).unwrap()); // odd length not allowed
        assert!(!is_hex_encoded("ABC".to_string(), true).unwrap()); // odd length not allowed
    }

    #[test]
    fn test_calculate_imphash() {
        //todo!();
        // This is an internal function, but we can test it if we make it public
        // or use it indirectly through get_pe_info
        // For now, we'll test that get_pe_info doesn't panic on various inputs

        // Test with empty data
        let (imphash, exports) = get_pe_info(&[]).unwrap();
        assert!(imphash.is_empty());
        assert!(exports.is_empty());

        // Test with MZ header but invalid PE
        let mut mz_header = vec![0x4D, 0x5A]; // MZ
        mz_header.extend(vec![0u8; 60]); // padding to reach 0x3C
        mz_header.extend(vec![0x00, 0x00, 0x00, 0x00]); // e_lfanew = 0
        let (imphash, exports) = get_pe_info(&mz_header).unwrap();
        assert!(imphash.is_empty());
        assert!(exports.is_empty());
    }
}
