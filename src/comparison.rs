use crate::signature::{ComparisonResult, SignatureDatabase, SignatureDifference, SignatureError};

/// Compare a signature from the database with a system-loaded function
pub fn compare_signatures(
    db: &SignatureDatabase,
    dll_name: &str,
    function_name: &str,
    windows_version: &str,
    system_bytes: &[u8],
) -> Result<ComparisonResult, SignatureError> {
    // Get signature from database
    let db_signature = db.get_signature(dll_name, function_name, windows_version);
    
    match db_signature {
        Some(sig) => {
            let mut differences = Vec::new();
            let mut matches = true;

            // Compare lengths
            if sig.signature_bytes.len() != system_bytes.len() {
                differences.push(SignatureDifference::LengthMismatch {
                    db_length: sig.signature_bytes.len(),
                    system_length: system_bytes.len(),
                });
                matches = false;
            }

            // Compare bytes
            let min_len = std::cmp::min(sig.signature_bytes.len(), system_bytes.len());
            for i in 0..min_len {
                if sig.signature_bytes[i] != system_bytes[i] {
                    differences.push(SignatureDifference::ByteMismatch {
                        offset: i,
                        db_byte: sig.signature_bytes[i],
                        system_byte: system_bytes[i],
                    });
                    matches = false;
                }
            }

            Ok(ComparisonResult::new(
                matches,
                differences,
                Some(sig.clone()),
                system_bytes.to_vec(),
            ))
        }
        None => {
            // Function not found in database
            Ok(ComparisonResult::new(
                false,
                vec![SignatureDifference::MissingInDatabase],
                None,
                system_bytes.to_vec(),
            ))
        }
    }
}



/// Print comparison results in a formatted way
pub fn print_comparison_result(
    dll_name: &str,
    function_name: &str,
    result: &ComparisonResult,
) {
    println!("\n=== Comparing signatures for {} in {} ===", function_name, dll_name);

    match &result.db_signature {
        Some(db_sig) => {
            println!("Database signature ({} bytes):", db_sig.signature_bytes.len());
            println!("  RVA: 0x{:x}", db_sig.function_rva);
            println!("  Bytes: {}", db_sig.signature_hex_formatted());

            println!("System signature ({} bytes):", result.system_bytes.len());
            println!("  Bytes: {}", bytes_to_hex_formatted(&result.system_bytes));

            if result.matches {
                println!("✅ SIGNATURES MATCH!");
            } else {
                println!("❌ SIGNATURES DO NOT MATCH!");

                // Show differences
                for difference in &result.differences {
                    match difference {
                        SignatureDifference::ByteMismatch { offset, db_byte, system_byte } => {
                            println!("  Mismatch at byte {}: DB=0x{:02x}, System=0x{:02x}", offset, db_byte, system_byte);
                        }
                        SignatureDifference::LengthMismatch { db_length, system_length } => {
                            println!("  Length mismatch: DB={}, System={}", db_length, system_length);
                        }
                        SignatureDifference::MissingInDatabase => {
                            println!("  Function not found in database");
                        }
                    }
                }
            }
        }
        None => {
            println!("❌ Function {} not found in database", function_name);
        }
    }
}

/// Print summary of comparison results
pub fn print_comparison_summary(results: &[(String, ComparisonResult)]) {
    let total = results.len();
    let matches = results.iter().filter(|(_, r)| r.matches).count();
    let mismatches = total - matches;

    println!("\n=== Comparison Summary ===");
    println!("Total functions compared: {}", total);
    println!("Matching signatures: {} ({:.1}%)", matches, (matches as f64 / total as f64) * 100.0);
    println!("Mismatching signatures: {} ({:.1}%)", mismatches, (mismatches as f64 / total as f64) * 100.0);

    if mismatches > 0 {
        println!("\nMismatching functions:");
        for (func_name, result) in results {
            if !result.matches {
                println!("  - {}", func_name);
            }
        }
    }
}

/// Convert bytes to formatted hex string
fn bytes_to_hex_formatted(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(" ")
} 