

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
 
 
use pythonize::pythonize;


use pyo3::exceptions::PyException;
use goblin::{Object, elf, pe}; 


#[pyfunction]
fn extract_strings(file_data: Vec<u8>, min_len: usize, max_len: Option<usize>, utf16: bool) -> PyResult<Vec<(String, u64)>> {
    let mut string_counts: HashMap<String, u64> = HashMap::new();
    let max_len = max_len.unwrap_or(usize::MAX);

    if utf16 {
        extract_and_count_utf16_strings(&file_data, min_len, max_len, &mut string_counts);
    } else {
        extract_and_count_ascii_strings(&file_data, min_len, max_len, &mut string_counts);
    }

    Ok(string_counts.into_iter().collect())
}

fn extract_and_count_ascii_strings(data: &[u8], min_len: usize, max_len: usize, counts: &mut HashMap<String, u64>) {
    let mut current_string = String::new();

    for &byte in data {
        if (0x20..=0x7E).contains(&byte) && current_string.len() <= max_len {
            current_string.push(byte as char);
        } else {
            if current_string.len() >= min_len  {
                *counts.entry(current_string.clone()).or_insert(0) += 1;
            }
            current_string.clear();
        }
    }
    
    // Don't forget the last string
    if current_string.len() >= min_len && current_string.len() <= max_len {
        *counts.entry(current_string).or_insert(0) += 1;
    }
}
 
// Alternative implementation that handles UTF-16 more robustly
fn extract_and_count_utf16_strings(data: &[u8], min_len: usize, max_len: usize, counts: &mut HashMap<String, u64>) {
    let mut current_string = String::new();
    let mut i = 0;

    while i + 1 < data.len() {
        let code_unit = u16::from_le_bytes([data[i], data[i+1]]);
        
        // Handle different cases for UTF-16
        match code_unit {
            // Printable ASCII range
            0x0020..=0x007E => {
                if let Some(ch) = char::from_u32(code_unit as u32) {
                    current_string.push(ch);
                }
                if current_string.len() == max_len {
                    *counts.entry(current_string.clone()).or_insert(0) += 1;
                }
                current_string.clear();
            }
            // Null character or other control characters - end of string
            _ => {
                if current_string.len() >= min_len {
                    *counts.entry(current_string.clone()).or_insert(0) += 1;
                }
                current_string.clear();
            }
        }
        
        i += 2;
    }
    
    // Final string
    if current_string.len() >= min_len {
        *counts.entry(current_string[0..max_len].to_owned()).or_insert(0) += 1;
        if current_string.len() - max_len >= min_len {
            *counts.entry(current_string[max_len..].to_owned()).or_insert(0) += 1;
        }
    }
}

fn extract_elf_opcodes(elf: elf::Elf, file_data: &[u8], opcodes: &mut Vec<String>) {
    let entry_point = elf.header.e_entry;
    
    // Find the section containing the entry point
    for section in elf.section_headers {
        let va_start = section.sh_addr;
        let va_end = va_start + section.sh_size;
        
        if va_start <= entry_point && entry_point < va_end {
            println!("EP is located at {} section", elf.shdr_strtab.get_at(section.sh_name).unwrap_or("unknown"));
            
            // Extract section content
            let start = section.sh_offset as usize;
            let end = start + section.sh_size as usize;
            
            if end <= file_data.len() {
                let section_data = &file_data[start..end];
                process_section_data(section_data, opcodes);
            }
            break;
        }
    }
}

fn extract_pe_opcodes(pe: pe::PE, file_data: &[u8], opcodes: &mut Vec<String>) {
    let entry_point = pe.entry as u64;
    let image_base = pe.header.optional_header.unwrap().windows_fields.image_base;
    let entry_va = entry_point + image_base;
    
    // Find the section containing the entry point
    for section in pe.sections {
        let va_start = section.virtual_address as u64 + image_base;
        let va_end = va_start + section.virtual_size as u64;
        
        if va_start <= entry_va && entry_va < va_end {
            println!("EP is located at {} section", String::from_utf8_lossy(&section.name).trim_end_matches('\0'));
            
            // Extract section content
            let start = section.pointer_to_raw_data as usize;
            let end = start + section.size_of_raw_data as usize;
            
            if end <= file_data.len() {
                let section_data = &file_data[start..end];
                process_section_data(section_data, opcodes);
            }
            break;
        }
    }
}



#[pyfunction]
fn extract_opcodes(file_data: Vec<u8>) -> PyResult<Vec<String>> {
    let mut opcodes = Vec::new();
    
    match Object::parse(&file_data).map_err(|e| PyException::new_err(format!("Failed to parse binary: {}", e)))? {
        Object::Elf(elf) => {
            extract_elf_opcodes(elf, &file_data, &mut opcodes);
        }
        Object::PE(pe) => {
            extract_pe_opcodes(pe, &file_data, &mut opcodes);
        }
        Object::Mach(mach) => {
            // Mach-O support can be added here
            println!("Mach-O parsing not yet implemented");
        }
        Object::Archive(archive) => {
            // Archive support can be added here  
            println!("Archive parsing not yet implemented");
        }
        _ => {
            println!("Unknown binary format");
        }
    }
    
    Ok(opcodes)
}

fn process_section_data(section_data: &[u8], opcodes: &mut Vec<String>) {
    // Split on sequences of 3 or more null bytes
    let null_pattern = Regex::new(r"\x00{3,}").unwrap();
    let text_parts: Vec<&[u8]> = null_pattern.split(section_data).collect();
    
    for text_part in text_parts {
        if text_part.is_empty() || text_part.len() < 8 {
            continue;
        }
        
        // Take first 16 bytes and convert to hex string
        let chunk = if text_part.len() >= 16 {
            &text_part[..16]
        } else {
            text_part
        };
        
        let hex_string = hex::encode(chunk);
        opcodes.push(hex_string);
    }
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
 

#[pymodule]
fn yarobot_rs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(score_strings_rs, m)?)?;
    m.add_function(wrap_pyfunction!(filter_string_set_rs, m)?)?;
    m.add_function(wrap_pyfunction!(extract_opcodes, m)?)?;
    m.add_function(wrap_pyfunction!(extract_strings, m)?)?;

    
    Ok(())
}