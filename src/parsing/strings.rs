use std::{
    cmp::min,
    collections::{HashMap, HashSet},
};

use pyo3::prelude::*;
use regex::Regex;

use crate::{TokenInfo, TokenType};

#[pyfunction]
pub fn extract_strings(
    file_data: Vec<u8>,
    min_len: usize,
    max_len: Option<usize>,
) -> PyResult<(HashMap<String, TokenInfo>, HashMap<String, TokenInfo>)> {
    let max_len = max_len.unwrap_or(usize::MAX);
    Ok((
        extract_and_count_ascii_strings(&file_data, min_len, max_len),
        extract_and_count_utf16_strings(&file_data, min_len, max_len),
    ))
}

pub fn extract_and_count_ascii_strings(
    data: &[u8],
    min_len: usize,
    max_len: usize,
) -> HashMap<String, TokenInfo> {
    let mut current_string = String::new();
    let mut stats: HashMap<String, TokenInfo> = HashMap::new();
    //println!("{:?}", data);
    for &byte in data {
        if (0x20..=0x7E).contains(&byte) && current_string.len() <= max_len {
            current_string.push(byte as char);
        } else {
            if current_string.len() >= min_len {
                stats
                    .entry(current_string.clone())
                    .or_insert(TokenInfo::new(
                        current_string.clone(),
                        0,
                        TokenType::ASCII,
                        HashSet::new(),
                        None,
                    ))
                    .count += 1;
            }
            current_string.clear();
        }
    }
    //println!("{:?}", stats);
    if current_string.len() >= min_len && current_string.len() <= max_len {
        stats
            .entry(current_string.clone())
            .or_insert(TokenInfo::new(
                current_string.clone(),
                0,
                TokenType::ASCII,
                HashSet::new(),
                None,
            ))
            .count += 1;
        assert!(stats.get(&current_string.clone()).unwrap().reprz.len() > 0);
    }
    stats.clone()
}

// Alternative implementation that handles UTF-16 more robustly
pub fn extract_and_count_utf16_strings(
    data: &[u8],
    min_len: usize,
    max_len: usize,
) -> HashMap<String, TokenInfo> {
    let mut current_string = String::new();
    let mut stats: HashMap<String, TokenInfo> = HashMap::new();
    let mut i = 0;

    while i + 1 < data.len() {
        let code_unit = u16::from_le_bytes([data[i], data[i + 1]]);

        // Handle different cases for UTF-16
        match code_unit {
            // Printable ASCII range
            0x0020..=0x007E => {
                if let Some(ch) = char::from_u32(code_unit as u32) {
                    current_string.push(ch);
                } else {
                    if current_string.len() >= min_len {
                        println!("UTF16LE: {}", current_string);

                        stats
                            .entry(current_string.clone())
                            .or_insert(TokenInfo::new(
                                current_string.clone(),
                                0,
                                TokenType::UTF16LE,
                                HashSet::new(),
                                None,
                            ))
                            .count += 1;
                    }
                    current_string.clear();
                }
            }
            // Null character or other control characters - end of string
            _ => {
                if current_string.len() >= min_len {
                    stats
                        .entry(current_string.clone())
                        .or_insert(TokenInfo::new(
                            current_string.clone(),
                            0,
                            TokenType::UTF16LE,
                            HashSet::new(),
                            None,
                        ))
                        .count += 1;
                }
                current_string.clear();
            }
        }

        i += 2;
    }

    // Final string
    if current_string.len() >= min_len {
        stats
            .entry(current_string[..min(max_len, current_string.len())].to_owned())
            .or_insert(TokenInfo::new(
                current_string.clone(),
                0,
                TokenType::UTF16LE,
                HashSet::new(),
                None,
            ))
            .count += 1;

        if current_string.len() as i64 - max_len as i64 >= min_len as i64 {
            stats
                .entry(current_string[max_len..].to_owned())
                .or_insert(TokenInfo::new(
                    current_string.clone(),
                    0,
                    TokenType::UTF16LE,
                    HashSet::new(),
                    None,
                ))
                .count += 1;
        }
    }
    stats
}

/// Remove non-ASCII characters from bytes, keeping printable ASCII 0x20..0x7E
#[pyfunction]
pub fn remove_non_ascii_drop(data: &[u8]) -> PyResult<String> {
    Ok(data
        .iter()
        .filter(|&&b| b > 31 && b < 127)
        .cloned()
        .map(|x| x.to_string())
        .collect())
}

/// Gets the contents of a file (limited to 1024 characters)

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
