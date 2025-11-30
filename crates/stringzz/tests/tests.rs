

#[cfg(test)]
mod tests { 
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;

    use stringzz::{FileInfo, FileProcessor, get_files, get_pe_info, is_ascii_string, is_base_64, is_hex_encoded};
 

    use super::*; 
    use tempfile::TempDir;

 
    #[test]
    fn test() {
        let test_dir = "tests/fixtures";
        let _ = fs::create_dir_all(test_dir);
        
        let mut file = File::create(Path::new(test_dir).join("strings_test.bin")).unwrap();
        let mut data = Vec::new();
        
        // 1. Simple ASCII strings of various lengths
        data.extend(b"short\0");
        data.extend(b"longer_string\0");
        data.extend(b"very_long_string_that_exceeds_typical_minimum_length\0");
        
        // 2. Strings with special characters
        data.extend(b"path/to/file.txt\0");
        data.extend(b"user@example.com\0");
        data.extend(b"$SPECIAL_CHARS%^&*\0");
        
        // 3. Strings at strategic positions
        data.push(0); // null byte separator
        data.extend(b"string_after_null\0");
        
        // 4. UTF-8 encoded strings
        data.extend("unicode_βββ".as_bytes());
        data.extend("emoji_😀😀😀".as_bytes());
        
        // 5. Invalid UTF-8 sequences
        data.extend(&[0xCE, 0xFA, 0xCE]); // incomplete sequence
        data.extend(&[0xFF, 0xFE]); // BOM fragments
        
        // 6. Mixed encodings challenge
        data.extend(&[0x00, 0x00, 0x00]); // padding
        data.extend(b"mixed_");
        data.extend(&[0x41, 0x00, 0x42, 0x00]); // UTF-16-like (A\0B\0)
        data.extend(b"_content");
        
        // 7. Edge case: string exactly at minimum length
        data.extend(b"four");
        
        // 8. Binary data that looks like strings
        data.extend(&[0x41, 0x41, 0x41, 0x41]); // AAAA
        for _ in 0..500 { data.push(0x41); } // long run of 'A's
        
        let _ = file.write_all(&data);
        
        
        println!("Test files generated in {}", test_dir); 
    }

    #[test]
    fn test_extraction() {
        let test_dir = "tests/fixtures"; 
        let mut fp = FileProcessor::default();
        fp.parse_sample_dir(test_dir.to_owned()).unwrap();
        for v in fp.strings.keys() {
            //println!("{:?}, {:?}, equals {}", v, "longer_string", v == "longer_string");
        }
        assert_eq!(fp.strings.keys().any(|x| x.eq("longer_string")), true);
        assert_eq!(fp.strings.keys().any(|x| x == "string_after_null"), true);
        assert_eq!(fp.strings.keys().any(|x| x == "$SPECIAL_CHARS%^&*"), true);
        assert_eq!(fp.strings.keys().any(|x| x == "user@example.com"), true);
        assert_eq!(fp.strings.keys().any(|x| x == "path/to/file.txt"), true);
        assert_eq!(fp.strings.keys().any(|x| x == "very_long_string_that_exceeds_typical_minimum_length"), true);
        assert_eq!(fp.strings.keys().any(|x| x == "short"), true);
        assert_eq!(fp.strings.keys().any(|x| x == "four"), false);


    }

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
    fn test_is_ascii_string() {
        // Test with valid ASCII (no padding)
        let ascii_data = b"Hello World!";
        let result = is_ascii_string(ascii_data, false);
        assert!(result);

        // Test with valid ASCII (with padding allowed)
        let ascii_with_null = b"Hello\x00World";
        let result = is_ascii_string(ascii_with_null, true);
        assert!(result);

        // Test with non-ASCII (no padding)
        let non_ascii_data = b"Hello\xFFWorld";
        let result = is_ascii_string(non_ascii_data, false);
        assert!(!result);

        // Test with non-ASCII (with padding)
        let non_ascii_with_null = b"Hello\xFF\x00World";
        let result = is_ascii_string(non_ascii_with_null, true);
        assert!(!result);

        // Test with empty data
        let empty_data = b"";
        let result = is_ascii_string(empty_data, false);
        assert!(result);

        // Test with only null bytes (padding allowed)
        let null_data = &[0x00, 0x00, 0x00];
        let result = is_ascii_string(null_data, true);
        assert!(result);

        // Test with only null bytes (padding not allowed)
        let result = is_ascii_string(null_data, false);
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
        let fi = &mut Default::default();
        get_pe_info(&[], fi);
        assert!(fi.imphash.is_empty());
        assert!(fi.exports.is_empty());

        // Test with MZ header but invalid PE
        let mut mz_header = vec![0x4D, 0x5A]; // MZ
        mz_header.extend(vec![0u8; 60]); // padding to reach 0x3C
        mz_header.extend(vec![0x00, 0x00, 0x00, 0x00]); // e_lfanew = 0
        let fi = &mut Default::default();
        get_pe_info(&mz_header, fi);
        assert!(fi.imphash.is_empty());
        assert!(fi.exports.is_empty());
    }

}