

use pyo3::{prelude::*, types::PyDict};
use regex::bytes::Regex;
use regex::Regex as StrRegex;
use std::{collections::HashMap, io::Read};
use std::io::Cursor;
use std::sync::Mutex; 
use memchr::memmem;
use ahash::AHashMap;  
lazy_static::lazy_static! {
    static ref STRING_REGEX: Regex = Regex::new(r"[\x1f-\x7e]{6,}").unwrap();
    static ref WIDE_STRING_REGEX: Regex = Regex::new(r"(?:[\x1f-\x7e][\x00]){6,}").unwrap();
    static ref HEX_STRING_REGEX: Regex = Regex::new(r"([a-fA-F0-9]{10,})").unwrap();
}
 

use serde::de::DeserializeOwned;
use std::fs::File;
use std::io::BufReader;
use flate2::read::GzDecoder;
use serde_json::{self, Value};
    use pythonize::pythonize;
 


#[pyfunction]
fn extract_strings_rs(max_len: usize, file_data: &[u8]) -> Vec<String> {
    println!("Extracting strings in rust {:?}", max_len);
    let mut strings = Vec::new(); 
    // Extract ASCII strings
    for mat in STRING_REGEX.find_iter(file_data) {
        let s = String::from_utf8(mat.as_bytes().to_vec()).unwrap() ;
        //println!("found {:?} sting", s);
        if s.len() <= max_len {
            strings.push(s.to_string());
        } else {
            strings.push(s[..max_len].to_string());
        }
    }
     
    for mat in WIDE_STRING_REGEX.find_iter(file_data) {
        let wide_bytes = mat.as_bytes();
        let mut decoded = String::new();
        for chunk in wide_bytes.chunks(2) {
            if chunk.len() == 2 && chunk[1] == 0 && chunk[0] >= 0x1f && chunk[0] <= 0x7e {
                decoded.push(chunk[0] as char);
            }
        }
        if decoded.len() >= 6 {
            strings.push(format!("UTF16LE:{}", decoded));
        }
    }
     
    for mat in HEX_STRING_REGEX.find_iter(file_data) {
        let hex_str = String::from_utf8(mat.as_bytes().to_vec()).unwrap();
        strings.push(hex_str.clone());
        
        // Also add split versions
        for part in hex_str.split("0000") {
            if part.len() >= 10 {
                strings.push(part.to_string());
            }
        } 
    }
    
    strings
}

#[pyfunction]
fn score_strings_rs(strings: Vec<String>) -> PyResult<HashMap<String, (i32, String)>> {
    let results: AHashMap<String, (i32, String)> = strings
        .into_iter()
        .map(|s| {
            let (score, categories) = score_single_string_rs(&s);
            (s, (score, categories))
        })
        .collect();
    
    Ok(results.into_iter().collect())
}

fn score_single_string_rs(string: &str) -> (i32, String) {
    let mut score = 0;
    let mut categories = String::new();
    
    // Length-based scoring
    let len = string.len();
    if len > 8 && len < 128 {
        score += (len / 8) as i32;
    } else if len >= 128 {
        score += 1;
    }
    
    // Penalties
    if string.contains("..") {
        score -= 5;
    }
    if string.contains("   ") {
        score -= 5;
    }
    
    // Regex-based scoring
    score += apply_regex_rules_rs(string, &mut categories);
    
    (score, categories)
}

fn apply_regex_rules_rs(string: &str, categories: &mut String) -> i32 {
    let mut total_score = 0;
    
    // Case insensitive patterns
    let insensitive_patterns = [
        (r"[A-Za-z]:\\", -4, "drives"),
        (r"\.(exe|pdb|scr|log|cfg|txt|dat|msi|com|bat|dll|vbs|tmp|sys|ps1|vbp|hta|lnk)", 4, "exe_extensions"),
        (r"(cmd\.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log)", 5, "system_keywords"),
        (r"(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)", 5, "protocol_keywords"),
        (r"(error|http|closed|fail|version|proxy)", 3, "connection_keywords"),
        (r"(TEMP|Temporary|Appdata|Recycler)", 4, "temp_and_recycler"),
        (r"(scan|sniff|poison|intercept|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|credentials|creds|coded|p0c|Content|host)", 5, "malicious_keywords"),
    ];
    
    for (pattern, points, category) in &insensitive_patterns {
        if let Ok(re) = StrRegex::new(&format!("(?i){}", pattern)) {
            if re.is_match(string) {
                total_score += points;
                categories.push_str(category);
                categories.push_str(", ");
            }
        }
    }
    
    // Case sensitive patterns
    let sensitive_patterns = [
        (r"^[A-Z]{6,}$", 3, "all_caps"),
        (r"^[a-z]{6,}$", 3, "all_lower"),
        (r"^[a-z\s]{6,}$", 2, "all_lower_with_space"),
    ];
    
    for (pattern, points, category) in &sensitive_patterns {
        if let Ok(re) = StrRegex::new(pattern) {
            if re.is_match(string) {
                total_score += points;
                categories.push_str(category);
                categories.push_str(", ");
            }
        }
    }
    
    // IP address detection
    if let Ok(ip_re) = StrRegex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b") {
        if ip_re.is_match(string) {
            total_score += 5;
            categories.push_str("IP, ");
        }
    }
    
    total_score
}

#[pyfunction]
fn filter_string_set_rs(
    string_set: Vec<String>,
    good_strings_db: HashMap<String, u32>,
    excludegood: bool,
) -> Vec<(String, i32)> {
    string_set
        .into_iter()
        .filter_map(|s| {
            let mut score = 0;
            
            // Check goodware database
            if let Some(&count) = good_strings_db.get(&s) {
                if excludegood {
                    return None;
                }
                score = (count as i32) * -1 + 5;
            } else {
                let (string_score, _) = score_single_string_rs(&s);
                score += string_score;
                
                // Check for base64 encoding
                if is_base64_rs(&s) {
                    score += 10;
                }
                
                // Check for hex encoding
                if is_hex_encoded_rs(&s) {
                    score += 8;
                }
                
                // Check for reversed goodware strings
                let reversed: String = s.chars().rev().collect();
                if good_strings_db.contains_key(&reversed) {
                    score += 10;
                }
            }
            
            Some((s, score))
        })
        .collect()
}

fn is_base64_rs(s: &str) -> bool {
    s.len() % 4 == 0 && StrRegex::new(r"^[A-Za-z0-9+/]+={0,2}$").unwrap().is_match(s)
}

fn is_hex_encoded_rs(s: &str) -> bool {
    StrRegex::new(r"^[A-Fa-f0-9]+$").unwrap().is_match(s) && s.len() % 2 == 0
}

#[pyfunction]
fn extract_opcodes_rs(file_data: &[u8]) -> Vec<String> {
    // This would integrate with LIEF or similar Rust PE parsing library
    // For now, return empty vector - implement with goblin or similar
    Vec::new()
}

#[pyfunction]
fn bulk_string_extraction_rs(file_paths: Vec<String>, max_len: usize) -> PyResult<HashMap<String, Vec<String>>> {
    let results: HashMap<String, Vec<String>> = file_paths
        .into_iter()
        .filter_map(|path| {
            match std::fs::read(&path) {
                Ok(data) => {
                    let strings = extract_strings_rs(max_len, &data);
                    Some((path, strings))
                }
                Err(_) => None,
            }
        })
        .collect();
    
    Ok(results)
}

#[pymodule]
fn yargen_rs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_strings_rs, m)?)?;
    m.add_function(wrap_pyfunction!(score_strings_rs, m)?)?;
    m.add_function(wrap_pyfunction!(filter_string_set_rs, m)?)?;
    m.add_function(wrap_pyfunction!(extract_opcodes_rs, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_string_extraction_rs, m)?)?; 
    Ok(())
}