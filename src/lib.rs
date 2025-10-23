use log::info;
use pyo3::prelude::*;
use std::{collections::HashMap, fs, path::Path};

pub mod types;
pub use types::*;

pub mod parsing;
pub use parsing::*;

pub mod processing;
pub use processing::*;

pub mod scoring;
pub use scoring::*;

#[pyfunction]
pub fn process_malware(
    malware_path: String,
    recursive: bool,
    extensions: Option<Vec<String>>,
    minssize: usize,
    maxssize: usize,
    fsize: usize,
    get_opcodes: bool,
    debug: bool,
    excludegood: bool,
    min_score: i64,
    superrule_overlap: usize,
    good_strings_db: HashMap<String, usize>,
    good_opcodes_db: HashMap<String, usize>,
    good_imphashes_db: HashMap<String, usize>,
    good_exports_db: HashMap<String, usize>,
    pestudio_strings: HashMap<String, (i64, String)>,
) -> PyResult<(
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, FileInfo>,
    ScoringEngine,
)> {
    //env_logger::init();
    // Check if we should disable super rules for single files
    env_logger::init_from_env("RUST_LOG");
    let mut fp = FileProcessor::new(
        recursive,
        extensions,
        minssize,
        maxssize,
        fsize,
        get_opcodes,
        debug,
    );

    info!("Processing malware files...");
    let (string_scores, opcodes, utf16strings, file_infos) =
        fp.parse_sample_dir(malware_path).unwrap();
    let mut scoring_engine = ScoringEngine {
        good_strings_db,
        good_opcodes_db,
        good_imphashes_db,
        good_exports_db,
        utf16strings,
        pestudio_strings,
        pestudio_marker: Default::default(),
        base64strings: Default::default(),
        hex_enc_strings: Default::default(),
        reversed_strings: Default::default(),
        string_scores,
        excludegood,
        min_score,
        superrule_overlap,
        opcodes,
    };

    let (string_combis, string_superrules, file_strings) = scoring_engine
        .sample_string_evaluation(scoring_engine.string_scores.clone())
        .unwrap();
    let (utf16_combis, utf16_superrules, file_utf16strings) = scoring_engine
        .sample_string_evaluation(scoring_engine.utf16strings.clone())
        .unwrap();
    let mut file_opcodes = Default::default();
    let opcode_combis = Default::default();
    let opcode_superrules = Default::default();
    extract_stats_by_file(&scoring_engine.opcodes, &mut file_opcodes, None, None);
    /*let (opcode_combis, opcode_superrules, file_opcodes) = scoring_engine
    .sample_string_evaluation(scoring_engine.opcodes.clone())
    .unwrap();*/
    Ok((
        string_combis,
        string_superrules,
        utf16_combis,
        utf16_superrules,
        opcode_combis,
        opcode_superrules,
        file_strings,
        file_opcodes,
        file_utf16strings,
        file_infos,
        scoring_engine,
    ))
}

#[cfg(test)]
mod tests {
    use crate::{get_pe_info, FileInfo};

    use super::*;
    use std::fs::{self, File};
    use tempfile::TempDir;

    #[test]
    fn test_get_pe_info() {
        // Test with non-PE data
        let non_pe_data = b"Not a PE file";
        let mut fi: FileInfo = Default::default();

        get_pe_info(non_pe_data, &mut fi);
        assert!(fi.imphash.is_empty());
        assert!(fi.exports.is_empty());

        // Test with small data (less than 0x40 bytes)
        let small_data = vec![0x4D, 0x5A]; // MZ header only
        let mut fi: FileInfo = Default::default();

        get_pe_info(&small_data, &mut fi);

        assert!(fi.imphash.is_empty());
        assert!(fi.exports.is_empty());

        // Note: Testing with actual PE files would require real PE binaries
        // For unit tests, we mainly verify the error handling paths
    }

    #[test]
    fn test_remove_non_ascii_drop() {
        // Test with non-ASCII characters
        let mixed_data = b"Hello\x00World\xFF\x7F\xFE";
        let result = remove_non_ascii_drop(mixed_data).unwrap();
        assert_eq!(result, "HelloWorld");

        // Test with empty data
        let empty_data = b"";
        let result = remove_non_ascii_drop(empty_data).unwrap();
        assert_eq!(result, "");

        // Test with only non-ASCII characters
        let non_ascii_data = &[0x00, 0xFF, 0xFE, 0x01];
        let result = remove_non_ascii_drop(non_ascii_data).unwrap();
        assert_eq!(result, "");
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
        let files = get_files(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        assert_eq!(files.len(), 1); // Only file1.txt in root
        assert!(files[0].contains("file1.txt"));

        // Test recursive
        let files = get_files(temp_dir.path().to_str().unwrap().to_string(), true).unwrap();
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
        let mut fi = &mut Default::default();
        get_pe_info(&[], &mut fi);
        assert!(fi.imphash.is_empty());
        assert!(fi.exports.is_empty());

        // Test with MZ header but invalid PE
        let mut mz_header = vec![0x4D, 0x5A]; // MZ
        mz_header.extend(vec![0u8; 60]); // padding to reach 0x3C
        mz_header.extend(vec![0x00, 0x00, 0x00, 0x00]); // e_lfanew = 0
        let mut fi = &mut Default::default();
        get_pe_info(&mz_header, &mut fi);
        assert!(fi.imphash.is_empty());
        assert!(fi.exports.is_empty());
    }
}

#[pymodule]
fn yarobot_rs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_strings, m)?)?;
    m.add_function(wrap_pyfunction!(get_file_info, m)?)?;
    m.add_function(wrap_pyfunction!(process_malware, m)?)?;

    m.add_function(wrap_pyfunction!(get_pe_info, m)?)?;
    m.add_function(wrap_pyfunction!(remove_non_ascii_drop, m)?)?;
    m.add_function(wrap_pyfunction!(is_ascii_string, m)?)?;
    m.add_function(wrap_pyfunction!(is_base_64, m)?)?;
    m.add_function(wrap_pyfunction!(is_hex_encoded, m)?)?;

    m.add_class::<types::TokenInfo>()?;
    m.add_class::<types::TokenType>()?;
    m.add_class::<processing::FileProcessor>()?;
    m.add_class::<ScoringEngine>()?;

    m.add_class::<Combination>()?;

    Ok(())
}
