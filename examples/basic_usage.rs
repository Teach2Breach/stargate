use stargate::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("DLL Inspector Library - Basic Usage Example");

    // Example 1: Extract all signatures from ntdll.dll
    println!("\n=== Example 1: Extract all signatures ===");
    let db = extract_all_signatures("ntdll", 32)?;
    println!("Extracted {} signatures from ntdll.dll", db.len());

    // Example 2: Get a specific signature
    println!("\n=== Example 2: Get specific signature ===");
    if let Some(sig) = db.get_signature("ntdll", "NtQuerySystemTime", "dynamic") {
        println!("Found NtQuerySystemTime signature:");
        println!("  RVA: 0x{:x}", sig.function_rva);
        println!("  Bytes: {}", sig.signature_hex_formatted());
    } else {
        println!("NtQuerySystemTime not found in database");
    }

    // Example 3: Get database statistics
    println!("\n=== Example 3: Database statistics ===");
    let stats = db.get_stats();
    println!("Total signatures: {}", stats.total_signatures);
    println!("Unique DLLs: {}", stats.unique_dlls);
    println!("Unique Windows versions: {}", stats.unique_versions);

    // Example 4: Search for functions containing "Query"
    println!("\n=== Example 4: Search for Query functions ===");
    let query_functions: Vec<_> = db.get_signatures_by_dll("ntdll")
        .into_iter()
        .filter(|sig| sig.function_name.contains("Query"))
        .take(5)
        .collect();
    
    println!("Found {} Query functions (showing first 5):", query_functions.len());
    for sig in query_functions {
        println!("  - {} (RVA: 0x{:x})", sig.function_name, sig.function_rva);
    }

    // Example 5: Extract single signature
    println!("\n=== Example 5: Extract single signature ===");
    let single_sig = extract_single_signature("kernel32", "Sleep", 32)?;
    if let Some(sig) = single_sig {
        println!("Extracted Sleep signature:");
        println!("  RVA: 0x{:x}", sig.function_rva);
        println!("  Bytes: {}", sig.signature_hex_formatted());
    }

    println!("\n✅ All examples completed successfully!");
    Ok(())
} 