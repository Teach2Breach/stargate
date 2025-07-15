use stargate::*;
use std::env;

fn main() {
    println!("Stargate - Hook-Resistant Function Location Tool");

    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <dll_name> [function_name] [signature_length]", args[0]);
        println!("Example: {} ntdll NtQuerySystemTime 32", args[0]);
        println!("Example: {} kernel32 Sleep", args[0]);
        println!("Example: {} ntdll", args[0]);
        return;
    }

    let dll_name = &args[1];
    let test_function_name = args.get(2).cloned();
    let signature_length = args.get(3)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_SIGNATURE_LENGTH);

    println!("Target DLL: {}", dll_name);
    println!("Signature Length: {} bytes", signature_length);
    println!("Note: DLL version will be automatically detected from loaded DLL");

    // Extract all signatures from the DLL
    println!("\nExtracting signatures from {}...", dll_name);
    let database = match extract_all_signatures(dll_name, signature_length) {
        Ok(db) => {
            println!("✅ Successfully extracted {} signatures", db.len());
            db
        }
        Err(e) => {
            println!("❌ Failed to extract signatures: {}", e);
            return;
        }
    };

    // Display database statistics
    let stats = database.get_stats();
    println!("\n=== Database Statistics ===");
    println!("Total signatures: {}", stats.total_signatures);
    println!("Unique DLLs: {}", stats.unique_dlls);
    println!("Unique Windows versions: {}", stats.unique_versions);

    // Display first 10 signatures as a sample
    println!("\n=== Sample Signatures (first 10) ===");
    let signatures = database.get_signatures_by_dll(dll_name);
    for (i, sig) in signatures.iter().take(10).enumerate() {
        println!("{}. {} (RVA: 0x{:x})", i + 1, sig.function_name, sig.function_rva);
        println!("   Signature: {}", sig.signature_hex_formatted());
    }

    if signatures.len() > 10 {
        println!("... and {} more signatures", signatures.len() - 10);
    }

    // Note: System comparison functionality has been removed to avoid PEB walking and EAT parsing
    if let Some(ref func_name) = test_function_name {
        println!("\n=== Function Information ===");
        println!("Function: {} (comparison with system not available)", func_name);
        println!("Note: System comparison was removed to avoid PEB walking and EAT parsing techniques");
    }

    println!("\n✅ DLL Inspector completed successfully!");
    println!("Database contains {} signatures in memory", database.len());

    // Now demonstrate signature scanning functionality
    println!("\n=== Signature Scanning Demo ===");
    
    // Scan the loaded DLL for functions matching our signatures
    match scan_loaded_dll(dll_name, &database) {
        Ok(scan_results) => {
            println!("Scan completed! Found {} functions in loaded {}", scan_results.len(), dll_name);
            
            // Show detailed results
            print_scan_results(&scan_results);
            
            // Show summary statistics
            let exact_matches = scan_results.iter().filter(|r| r.signature_matches).count();
            let hooked_functions = scan_results.iter().filter(|r| r.hook_detected).count();
            
            println!("\n=== Scan Statistics ===");
            println!("Total functions found: {}", scan_results.len());
            println!("Exact signature matches: {}", exact_matches);
            println!("Hooked functions detected: {}", hooked_functions);
            println!("Functions relocated: {}", scan_results.iter().filter(|r| r.expected_rva != r.actual_rva).count());
            
            // If a specific function was requested, show detailed analysis
            if let Some(ref func_name) = test_function_name {
                if let Some(specific_result) = scan_results.iter().find(|r| r.function_name == *func_name) {
                    println!("\n=== Detailed Analysis for {} ===", func_name);
                    println!("Found at: 0x{:x}", specific_result.found_address);
                    println!("Expected RVA: 0x{:x}", specific_result.expected_rva);
                    println!("Actual RVA: 0x{:x}", specific_result.actual_rva);
                    println!("Scan method: {:?}", specific_result.scan_method);
                    println!("Confidence: {:.1}%", specific_result.confidence_score * 100.0);
                    
                    if specific_result.hook_detected {
                        println!("⚠️  This function appears to be hooked!");
                        if let Some(hook_details) = &specific_result.hook_details {
                            println!("Hook type: {:?}", hook_details.hook_type);
                            if let Some(target) = hook_details.jump_target {
                                println!("Hook redirects to: 0x{:x}", target);
                            }
                        }
                    } else if specific_result.signature_matches {
                        println!("✅ Function signature matches exactly!");
                    }
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to scan loaded {}: {}", dll_name, e);
        }
    }
}
