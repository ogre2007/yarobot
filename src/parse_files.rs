use std::collections::{HashMap, HashSet};
use std::fs;

use goblin::pe::PE;
use goblin::Object;
use log::error;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

use goblin::{elf, pe};
use sha2::{Digest, Sha256}; 
 

use regex::bytes::Regex;
lazy_static::lazy_static! {
    static ref STRING_REGEX: Regex = Regex::new(r"[\x1f-\x7e]{6,}").unwrap();
    static ref WIDE_STRING_REGEX: Regex = Regex::new(r"(?:[\x1f-\x7e][\x00]){6,}").unwrap();
    static ref HEX_STRING_REGEX: Regex = Regex::new(r"([a-fA-F0-9]{10,})").unwrap();
}

#[pyclass]
#[derive(Debug, Clone, Default)]
pub struct FileInfo {
    #[pyo3(get, set)]
    pub imphash: String,
    #[pyo3(get, set)]
    pub exports: Vec<String>,
    #[pyo3(get, set)]
    pub sha256: String,
    #[pyo3(get, set)]
    pub size: usize,
    #[pyo3(get, set)]
    pub magic: [u8; 4],
}

#[pymethods]
impl FileInfo {
    pub fn __str__(&self) -> String {
        format!(
            "FileInfo: imphash={}, exports={:?}, sha256={:?}",
            self.imphash, self.exports, self.sha256
        )
    }
}


#[pyfunction]
pub fn get_file_info(file_data: &[u8]) -> PyResult<FileInfo> {
    let mut hasher = Sha256::new();
    hasher.update(file_data);
    let mut fi = FileInfo {
        sha256: hex::encode(hasher.finalize()),
        imphash: Default::default(),
        exports: Default::default(),
        size: Default::default(),
        magic: file_data[0..4].try_into().unwrap(),
    };
    if fi.magic[0..2] == *b"MZ" {
        get_pe_info(file_data, &mut fi);
    }
    Ok(fi)
}


/// Get different PE attributes and hashes using goblin
#[pyfunction]
pub fn get_pe_info(file_data: &[u8], fi: &mut FileInfo) {
    // Quick reject: not PE
    if file_data.len() < 2 || &file_data[0..2] != b"MZ" {
    } else if file_data.len() < 0x40 {
    } else {
        let e_lfanew =
            u32::from_le_bytes(file_data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;

        if e_lfanew + 4 > file_data.len() {
        } else if &file_data[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        } else {
            // Parse with goblin
            match PE::parse(file_data) {
                Ok(pe) => {
                    fi.imphash = calculate_imphash(&pe).unwrap_or_default();

                    for export in pe.exports {
                        if let Some(name) = export.name {
                            fi.exports.push(name.to_string());
                        }
                    }
                }
                Err(e) => {
                    error!("goblin parse failed: {}", e);
                }
            }
        }
    }
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


#[pyclass]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    ASCII,
    UTF16LE,
    BINARY,
}

#[pymethods]
impl TokenType {
    fn __eq__(&self, val: &TokenType) -> bool {
        self == val
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct TokenInfo {
    #[pyo3(get, set)]
    pub count: u32,
    #[pyo3(get, set)]
    pub typ: TokenType,
    #[pyo3(get, set)]
    pub files: HashSet<String>,
}

#[pymethods]
impl TokenInfo {
    #[new]
    pub fn new(count: u32, typ: TokenType, files: HashSet<String>) -> Self {
        TokenInfo { count, typ, files }
    }

    pub fn __str__(&self) -> String {
        format!(
            "TokenInfo: count={}, typ={:?}, files={:?}",
            self.count, self.typ, self.files
        )
    }

    pub fn add_file(&mut self, value: String) {
        self.files.insert(value);
    }
}

#[pyfunction]
pub fn process_single_file(
    file_path: String,
    minssize: usize,
    maxssize: usize,
    get_opcodes: bool,
) -> PyResult<(
    FileInfo,
    HashMap<String, TokenInfo>,
    HashMap<String, TokenInfo>,
    HashMap<String, TokenInfo>,
)> {
    let file_data = fs::read(file_path.clone()).expect("Cant read file");
    let fi = get_file_info(&file_data).unwrap();
    let (mut strings, mut utf16strings) = (
        extract_and_count_ascii_strings(&file_data, minssize, maxssize),
        extract_and_count_utf16_strings(&file_data, minssize, maxssize),
    );
    for (_, ti) in strings.iter_mut() {
        ti.files.insert(file_path.clone());
    }
    for (_, ti) in utf16strings.iter_mut() {
        ti.files.insert(file_path.clone());
    }
    let mut opcodes = Default::default();
    if get_opcodes {
        opcodes = extract_opcodes(file_data).unwrap();
        for (_, ti) in opcodes.iter_mut() {
            ti.files.insert(file_path.clone());
        }
    }

    Ok((fi, strings, utf16strings, opcodes))
}

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
                    .or_insert(TokenInfo::new(0, TokenType::ASCII, HashSet::new()))
                    .count += 1;
            }
            current_string.clear();
        }
    }
    //println!("{:?}", stats);
    if current_string.len() >= min_len && current_string.len() <= max_len {
        stats
            .entry(current_string.clone())
            .or_insert(TokenInfo::new(0, TokenType::ASCII, HashSet::new()))
            .count += 1;
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
                }
                if current_string.len() == max_len {
                    stats
                        .entry(current_string.clone())
                        .or_insert(TokenInfo::new(0, TokenType::UTF16LE, HashSet::new()))
                        .count += 1;
                }
                current_string.clear();
            }
            // Null character or other control characters - end of string
            _ => {
                if current_string.len() >= min_len {
                    stats
                        .entry(current_string.clone())
                        .or_insert(TokenInfo::new(0, TokenType::UTF16LE, HashSet::new()))
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
            .entry(current_string[0..max_len].to_owned())
            .or_insert(TokenInfo::new(0, TokenType::UTF16LE, HashSet::new()))
            .count += 1;

        if current_string.len() - max_len >= min_len {
            stats
                .entry(current_string[max_len..].to_owned())
                .or_insert(TokenInfo::new(0, TokenType::UTF16LE, HashSet::new()))
                .count += 1;
        }
    }
    stats
}

fn extract_elf_opcodes(elf: elf::Elf, file_data: &[u8]) -> HashMap<String, TokenInfo> {
    let entry_point = elf.header.e_entry;
    let mut opcodes = HashMap::new();
    // Find the section containing the entry point
    for section in elf.section_headers {
        let va_start = section.sh_addr;
        let va_end = va_start + section.sh_size;

        if va_start <= entry_point && entry_point < va_end {
            println!(
                "EP is located at {} section",
                elf.shdr_strtab.get_at(section.sh_name).unwrap_or("unknown")
            );

            // Extract section content
            let start = section.sh_offset as usize;
            let end = start + section.sh_size as usize;

            if end <= file_data.len() {
                let section_data = &file_data[start..end];
                process_section_data(section_data, &mut opcodes);
            }
            break;
        }
    }
    opcodes
}

fn extract_pe_opcodes(pe: pe::PE, file_data: &[u8]) -> HashMap<String, TokenInfo> {
    let entry_point = pe.entry as u64;
    let image_base = pe.header.optional_header.unwrap().windows_fields.image_base;
    let entry_va = entry_point + image_base;
    let mut opcodes = HashMap::new();
    // Find the section containing the entry point
    for section in pe.sections {
        let va_start = section.virtual_address as u64 + image_base;
        let va_end = va_start + section.virtual_size as u64;

        if va_start <= entry_va && entry_va < va_end {
            println!(
                "EP is located at {} section",
                String::from_utf8_lossy(&section.name).trim_end_matches('\0')
            );

            // Extract section content
            let start = section.pointer_to_raw_data as usize;
            let end = start + section.size_of_raw_data as usize;

            if end <= file_data.len() {
                let section_data = &file_data[start..end];
                process_section_data(section_data, &mut opcodes);
            }
            break;
        }
    }
    opcodes
}

#[pyfunction]
pub fn extract_opcodes(file_data: Vec<u8>) -> PyResult<HashMap<String, TokenInfo>> {
    let mut opcodes = HashMap::new();

    match Object::parse(&file_data)
        .map_err(|e| PyException::new_err(format!("Failed to parse binary: {}", e)))?
    {
        Object::Elf(elf) => {
            opcodes = extract_elf_opcodes(elf, &file_data);
        }
        Object::PE(pe) => {
            opcodes = extract_pe_opcodes(pe, &file_data);
        }
        Object::Mach(_) => {
            // Mach-O support can be added here
            println!("Mach-O parsing not yet implemented");
        }
        Object::Archive(_) => {
            // Archive support can be added here
            println!("Archive parsing not yet implemented");
        }
        _ => {
            println!("Unknown binary format");
        }
    }

    Ok(opcodes)
}

fn process_section_data(section_data: &[u8], opcodes: &mut HashMap<String, TokenInfo>) {
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
        opcodes
            .entry(hex_string)
            .or_insert(TokenInfo::new(0, TokenType::BINARY, HashSet::new()))
            .count += 1;
    }
}
