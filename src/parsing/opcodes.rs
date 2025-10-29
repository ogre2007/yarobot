use std::collections::{HashMap, HashSet};

use crate::{TokenInfo, TokenType};
use anyhow::Result;
use goblin::{elf, pe, Object};
use log::{debug, error};
use pyo3::{exceptions::PyException, prelude::*};
use regex::bytes::Regex;

fn extract_elf_opcodes(elf: elf::Elf, file_data: &[u8]) -> HashMap<String, TokenInfo> {
    let entry_point = elf.header.e_entry;
    let mut opcodes = HashMap::new();
    // Find the section containing the entry point
    for section in elf.section_headers {
        let va_start = section.sh_addr;
        let va_end = va_start + section.sh_size;

        if va_start <= entry_point && entry_point < va_end {
            debug!(
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
            debug!(
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

pub fn extract_dex_opcodes(file_data: Vec<u8>) -> Result<HashMap<String, TokenInfo>> {
    let mut opcodes:HashMap<String, TokenInfo> = Default::default();
    if let Ok(dex) = dex::DexReader::from_vec(&file_data) {
        println!("{:?}", dex.header());
        for result in dex.classes() {
            match result {
                Ok(clazz) => {
                    for method in clazz.methods() {
                        if let Some(code) = method.code() {
                            for ins in code.insns(){
                                let hex_string = hex::encode(ins.to_le_bytes());
                                        opcodes
                                        .entry(hex_string.clone())
                                        .or_insert(TokenInfo::new(
                                            hex_string.clone(),
                                            0,
                                            TokenType::BINARY,
                                            HashSet::new(),
                                            None,
                                        ))
                                        .count += 1;
                            }
                            
                        }
                    }
                },
                _ => {},
            }
        }
    }
    Ok(opcodes)
}

pub fn extract_opcodes(file_data: Vec<u8>) -> Result<HashMap<String, TokenInfo>> {
    let mut opcodes = HashMap::new();

    match Object::parse(&file_data)
        //.map_err(|e| error!("{}", format!("Failed to parse binary: {}", e)))
    {
        Ok(Object::Elf(elf)) => {
            opcodes = extract_elf_opcodes(elf, &file_data);
        }
        Ok(Object::PE(pe)) => {
            opcodes = extract_pe_opcodes(pe, &file_data);
        }
        Ok(Object::Mach(_)) => {
            // Mach-O support can be added here
            debug!("Mach-O parsing not yet implemented"); // TODO:
        }
        Ok(Object::Archive(_)) => {
            // Archive support can be added here
            debug!("Archive parsing not yet implemented"); // TODO:
        }
        _ => {
            debug!("Unknown binary format. lets try dex");
            opcodes = extract_dex_opcodes(file_data)?;
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
            .entry(hex_string.clone())
            .or_insert(TokenInfo::new(
                hex_string.clone(),
                0,
                TokenType::BINARY,
                HashSet::new(),
                None,
            ))
            .count += 1;
    }
}
