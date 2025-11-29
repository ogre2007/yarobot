use goblin::pe::PE;
use log::error;

use pyo3::prelude::*;

use crate::FileInfo;

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
