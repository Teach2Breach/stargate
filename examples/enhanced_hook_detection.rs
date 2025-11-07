use stargate::*;
use std::fs::File;
use std::io::Write;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Enhanced Hook Detection Scanner");
    println!("This example demonstrates improved hook detection with syscall pattern analysis");

    // Step 1: Extract signatures from ntdll (most likely to have hooks)
    println!("\n=== Step 1: Extracting Signatures ===");
    
    let db = extract_all_signatures("ntdll", 32)?;
    println!("Extracted {} signatures from ntdll", db.len());

    // Step 2: Scan for hooks using enhanced detection
    println!("\n=== Step 2: Enhanced Hook Detection ===");
    
    let results = scan_loaded_dll("ntdll", &db)?;
    println!("Scanned {} functions", results.len());
    
    // Step 3: Analyze results with enhanced detection
    println!("\n=== Step 3: Analyzing Results ===");
    
    let hooked_functions: Vec<&ScanResult> = results
        .iter()
        .filter(|r| r.hook_detected)
        .collect();
    
    println!("Found {} hooked functions out of {} total functions", 
             hooked_functions.len(), results.len());
    
    // Step 4: Write detailed analysis to enhanced_hooks.txt
    println!("\n=== Step 4: Writing Enhanced Analysis ===");
    
    let mut file = File::create("enhanced_hooks.txt")?;
    
    // Write header
    writeln!(file, "ENHANCED HOOK DETECTION REPORT")?;
    writeln!(file, "Generated: {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs())?;
    writeln!(file, "Total functions scanned: {}", results.len())?;
    writeln!(file, "Hooked functions found: {}", hooked_functions.len())?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file)?;
    
    // Group hooks by type with enhanced analysis
    let mut hooks_by_type: HashMap<&HookType, Vec<&ScanResult>> = HashMap::new();
    for result in &hooked_functions {
        if let Some(hook_details) = &result.hook_details {
            hooks_by_type.entry(&hook_details.hook_type)
                .or_insert_with(Vec::new)
                .push(result);
        }
    }
    
    // Write summary by hook type
    writeln!(file, "HOOK TYPE SUMMARY:")?;
    writeln!(file, "{}", "-".repeat(40))?;
    for (hook_type, functions) in &hooks_by_type {
        writeln!(file, "{:?}: {} functions", hook_type, functions.len())?;
    }
    writeln!(file)?;
    
    // Write detailed analysis for each hooked function
    writeln!(file, "DETAILED ENHANCED ANALYSIS:")?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file)?;
    
    for (i, result) in hooked_functions.iter().enumerate() {
        writeln!(file, "HOOK #{:03}", i + 1)?;
        writeln!(file, "{}", "-".repeat(40))?;
        writeln!(file, "Function: {}", result.function_name)?;
        writeln!(file, "DLL: {}", result.dll_name)?;
        writeln!(file, "Found Address: 0x{:x}", result.found_address)?;
        writeln!(file, "Expected RVA: 0x{:x}", result.expected_rva)?;
        writeln!(file, "Actual RVA: 0x{:x}", result.actual_rva)?;
        writeln!(file, "Scan Method: {:?}", result.scan_method)?;
        writeln!(file, "Confidence Score: {:.1}%", result.confidence_score * 100.0)?;
        
        if let Some(hook_details) = &result.hook_details {
            writeln!(file, "Hook Type: {:?}", hook_details.hook_type)?;
            writeln!(file, "Hook Offset: 0x{:x}", hook_details.hook_offset)?;
            
            // Write original vs hook bytes
            writeln!(file, "Original Bytes: {}", bytes_to_hex(&hook_details.original_bytes))?;
            writeln!(file, "Hook Bytes:     {}", bytes_to_hex(&hook_details.hook_bytes))?;
            
            if let Some(target) = hook_details.jump_target {
                writeln!(file, "Jump/Call Target: 0x{:x}", target)?;
                
                // Enhanced target analysis
                if let Some(target_info) = enhanced_target_analysis(target) {
                    writeln!(file, "Target Analysis: {}", target_info)?;
                }
            }
            
            // Enhanced analysis based on hook type
            match hook_details.hook_type {
                HookType::JumpHook => {
                    writeln!(file, "Analysis: Function start has been replaced with a JMP instruction")?;
                    writeln!(file, "          This is a common API hooking technique")?;
                    writeln!(file, "          Detection: Enhanced with syscall pattern recognition")?;
                }
                HookType::CallHook => {
                    writeln!(file, "Analysis: Function start has been replaced with a CALL instruction")?;
                    writeln!(file, "          This may indicate function wrapping or logging")?;
                    writeln!(file, "          Detection: Enhanced with pattern matching")?;
                }
                HookType::InlineHook => {
                    writeln!(file, "Analysis: Function body has been modified at offset 0x{:x}", hook_details.hook_offset)?;
                    writeln!(file, "          This is an inline hook, more difficult to detect")?;
                    writeln!(file, "          Detection: Enhanced with byte-by-byte comparison")?;
                }
                HookType::Unknown => {
                    writeln!(file, "Analysis: Unknown hook type detected")?;
                    writeln!(file, "          Manual investigation required")?;
                    writeln!(file, "          Detection: Enhanced with pattern recognition")?;
                }
                HookType::IATHook => {
                    writeln!(file, "Analysis: IAT hook detection is not supported in this build.")?;
                }
            }
        }
        
        writeln!(file)?;
        writeln!(file, "Enhanced Detection Features:")?;
        writeln!(file, "  - Syscall pattern recognition (4C 8B D1)")?;
        writeln!(file, "  - PUSH+RET pattern detection")?;
        writeln!(file, "  - MOV+JMP pattern detection")?;
        writeln!(file, "  - Inline hook detection")?;
        writeln!(file, "  - Target address analysis")?;
        writeln!(file)?;
        
        // Add separator between hooks
        if i < hooked_functions.len() - 1 {
            writeln!(file, "{}", "=".repeat(80))?;
            writeln!(file)?;
        }
    }
    
    // Write footer with enhanced recommendations
    writeln!(file, "ENHANCED RECOMMENDATIONS:")?;
    writeln!(file, "{}", "=".repeat(80))?;
    writeln!(file)?;
    writeln!(file, "1. Investigate syscall pattern modifications (4C 8B D1)")?;
    writeln!(file, "2. Check for PUSH+RET and MOV+JMP hook patterns")?;
    writeln!(file, "3. Analyze target addresses for known hook libraries")?;
    writeln!(file, "4. Monitor for new hook patterns in system functions")?;
    writeln!(file)?;
    writeln!(file, "Enhanced Detection Capabilities:")?;
    writeln!(file, "  - Ntdll syscall pattern recognition")?;
    writeln!(file, "  - Multiple hook pattern detection")?;
    writeln!(file, "  - Inline hook identification")?;
    writeln!(file, "  - Target address analysis")?;
    writeln!(file)?;
    writeln!(file, "Note: This report was generated by Stargate enhanced hook detection")?;
    writeln!(file, "      Some legitimate software may use hooks for monitoring or security")?;
    
    println!("Enhanced hook report written to enhanced_hooks.txt");
    println!("Found {} hooked functions", hooked_functions.len());
    
    // Step 6: Show enhanced summary on console
    println!("\n=== Step 6: Enhanced Console Summary ===");
    
    if !hooked_functions.is_empty() {
        println!("⚠️  ENHANCED HOOK DETECTION RESULTS:");
        for result in &hooked_functions {
            println!("  {}!{} at 0x{:x}", 
                     result.dll_name, 
                     result.function_name, 
                     result.found_address);
            
            if let Some(hook_details) = &result.hook_details {
                println!("    Hook type: {:?}", hook_details.hook_type);
                if let Some(target) = hook_details.jump_target {
                    println!("    Target: 0x{:x}", target);
                }
                
                // Show enhanced detection info
                match hook_details.hook_type {
                    HookType::JumpHook => {
                        if hook_details.hook_bytes.len() >= 4 && 
                           hook_details.hook_bytes[0] == 0x4C && 
                           hook_details.hook_bytes[1] == 0x8B && 
                           hook_details.hook_bytes[2] == 0xD1 {
                            println!("    Syscall pattern detected!");
                        }
                    }
                    _ => {}
                }
            }
        }
    } else {
        println!("✅ No hooks detected with enhanced scanning");
    }
    
    println!("\n✅ Enhanced hook detection example completed successfully!");
    println!("Check enhanced_hooks.txt for detailed analysis");
    
    Ok(())
}

/// Convert bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Enhanced target address analysis
fn enhanced_target_analysis(address: usize) -> Option<String> {
    // This is an enhanced implementation that provides more detailed analysis
    if address == 0 {
        return Some("Null address - invalid hook".to_string());
    }
    
    // Check address ranges
    if address > 0x10000000 && address < 0x7FFFFFFF {
        // User space address
        if address > 0x40000000 && address < 0x7FFFFFFF {
            Some("Address in high user space - possible hook library".to_string())
        } else if address > 0x10000000 && address < 0x40000000 {
            Some("Address in low user space - possible legitimate hook".to_string())
        } else {
            Some("Address in user space - requires investigation".to_string())
        }
    } else if address > 0x80000000 {
        Some("Address in kernel space - suspicious hook".to_string())
    } else if address < 0x10000000 {
        Some("Address in low memory - possible system hook".to_string())
    } else {
        Some("Address range unknown - manual investigation required".to_string())
    }
} 