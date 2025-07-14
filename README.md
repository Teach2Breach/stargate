# Stargate

A novel Rust library for locating function addresses in loaded Windows DLLs without relying on Export Address Table (EAT) parsing. This tool uses signature-based scanning to find functions at runtime, making it resistant to EDR hooking and DLL modifications.

## 🎯 Key Features

- **Signature-Based Function Location**: Find functions by their byte signatures instead of EAT parsing
- **Hook-Resistant Scanning**: Detect and work around EDR hooks and function modifications
- **Runtime Function Discovery**: Locate functions in currently loaded DLLs at runtime
- **Version-Specific Signatures**: Extract and use signatures specific to the exact DLL version
- **Memory-Based Database**: Fast in-memory signature storage without external dependencies
- **Multi-DLL Support**: Works with any Windows DLL (ntdll, kernel32, user32, etc.)

## 🚀 How It Works

### Novel Approach
Traditional function location relies on parsing the Export Address Table (EAT), which can be easily hooked or modified by EDR solutions. This tool takes a different approach:

1. **Extract Clean Signatures**: Download clean DLL files from Microsoft Symbol Server
2. **Build Signature Database**: Extract function byte signatures from clean DLLs
3. **Scan Loaded Memory**: Search loaded DLLs in memory for matching signatures
4. **Hook Detection**: Identify and work around common hooking techniques
5. **Function Location**: Return the actual runtime addresses of functions

### Hook Resistance
The scanner implements multiple detection and bypass methods:
- **Exact Match**: Try to find exact signature matches
- **Partial Match**: Match signatures while ignoring common hook bytes
- **Relocation Detection**: Find functions that have been moved in memory
- **Hook Pattern Recognition**: Detect JMP, CALL, and inline hooks
- **Alternative Location Search**: Check common relocation patterns

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
stargate = { git = "https://github.com/Teach2Breach/stargate.git" }
```

## 🔧 Quick Start

### Standard Usage
```rust
use stargate::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Extract signatures from clean ntdll (version detected automatically)
    let db = extract_all_signatures("ntdll", 32)?;
    
    // Scan loaded ntdll for functions
    let results = scan_loaded_dll("ntdll", &db)?;
    
    // Find specific function
    if let Some(result) = results.iter().find(|r| r.function_name == "NtQuerySystemTime") {
        println!("Found NtQuerySystemTime at 0x{:x}", result.found_address);
        
        // Call the function if signature matches exactly
        if result.signature_matches {
            unsafe {
                let func: extern "system" fn() = std::mem::transmute(result.found_address);
                func();
            }
        }
    }
    
    Ok(())
}
```

### Silent Usage (Recommended for Implants)
```rust
use stargate::*;
use std::ffi::c_void;

type GetTickCountFunc = extern "system" fn() -> u32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Extract signatures silently (no debug output)
    let db = extract_all_signatures("kernel32", 32)?;
    
    // Find and call function with minimal output
    if let Some(result) = find_specific_function("kernel32", "GetTickCount", &db) {
        let get_tick_count: GetTickCountFunc = unsafe { 
            std::mem::transmute(result.found_address as *const c_void) 
        };
        let uptime = get_tick_count();
        // Only print essential result
        println!("GetTickCount: {}", uptime);
    }
    Ok(())
}
```

## 🛠️ Usage Examples

### Extract Signatures from Clean DLLs

```rust
// Extract all signatures from a clean DLL (version detected automatically)
let db = extract_all_signatures("ntdll", 32)?;
println!("Extracted {} signatures", db.len());

// Extract single function signature
let sig = extract_single_signature("kernel32", "Sleep", 32)?;
```

### Scan Loaded DLLs for Functions

```rust
// Scan entire DLL
let results = scan_loaded_dll("ntdll", &db)?;

// Find specific function
let result = find_specific_function("kernel32", "Sleep", &db)?;

// Scan all loaded DLLs
let all_results = scan_all_loaded_dlls(&db);
```

### Analyze Results

```rust
for result in results {
    println!("Function: {}", result.function_name);
    println!("  Found at: 0x{:x}", result.found_address);
    println!("  Expected RVA: 0x{:x}", result.expected_rva);
    println!("  Actual RVA: 0x{:x}", result.actual_rva);
    println!("  Hooked: {}", result.hook_detected);
    println!("  Confidence: {:.1}%", result.confidence_score * 100.0);
}
```

## 🎮 Command Line Interface

```bash
# Extract signatures from ntdll
cargo run -- ntdll

# Extract and scan for specific function
cargo run -- ntdll NtQuerySystemTime

# Extract with custom signature length
cargo run -- kernel32 Sleep 64
```

## 📚 Examples

### Basic Usage
```bash
cargo run --example basic_usage
```

### Signature Scanning Demo
```bash
cargo run --example signature_scanning
```

### Silent Function Calling (Recommended for Implants)
For opsec-sensitive operations and implants, use the silent example that minimizes output:
```bash
cargo run --example silent_call
```

This example demonstrates clean function calling with minimal logging - only prints the function name and result.

## 🔍 API Reference

### Core Functions

- `extract_all_signatures(dll_name, length)` - Extract all signatures from clean DLL (version detected automatically)
- `extract_single_signature(dll_name, function_name, length)` - Extract single function signature
- `scan_loaded_dll(dll_name, db)` - Scan loaded DLL for matching functions
- `find_specific_function(dll_name, function_name, db)` - Find specific function
- `scan_all_loaded_dlls(db)` - Scan all loaded DLLs

### Data Structures

- `SignatureDatabase` - In-memory signature storage
- `FunctionSignature` - Individual function signature data
- `ScanResult` - Result of signature scanning operation
- `HookDetails` - Information about detected hooks

### Hook Detection

- `JumpHook` - JMP instruction at function start
- `CallHook` - CALL instruction at function start  
- `InlineHook` - Modified bytes within function
- `IATHook` - Import Address Table hook

## 🎯 Use Cases

### Red Team Operations
- **Bypass EDR**: Find functions without triggering EAT parsing hooks
- **Dynamic Function Resolution**: Locate functions at runtime without hardcoded addresses
- **Hook Detection**: Identify when functions have been modified
- **Version Independence**: Work with different Windows/DLL versions
- **Implant Integration**: Silent operation with minimal logging for opsec-sensitive deployments

### Security Research
- **Malware Analysis**: Understand how malware locates functions
- **EDR Testing**: Test EDR hook detection capabilities
- **Memory Forensics**: Analyze loaded DLLs without file system access

### Development
- **Dynamic Linking**: Find functions without import tables
- **Plugin Systems**: Load and call functions dynamically
- **Hot Patching**: Locate functions for runtime modification

## 🛡️ Security Considerations

- **Memory Access**: Requires read access to process memory
- **Signature Reliability**: Signatures may change between Windows versions
- **Hook Detection**: Not all hooking techniques may be detected
- **Performance**: Scanning large DLLs can be resource-intensive

## 🔧 Dependencies

- `byont` - Clean DLL extraction and processing
- `noldr` - System DLL loading and function resolution  
- `moonwalk` - Memory scanning and DLL base address location
- `thiserror` - Error handling

## 📄 License

[Add your license information here]

## 🤝 Contributing

[Add contribution guidelines here]

## ⚠️ Disclaimer

This tool is for educational and research purposes. Use responsibly and in accordance with applicable laws and regulations.

## 🔗 Related Projects

- [moonwalk](https://github.com/Teach2Breach/moonwalk) - Memory scanning library
- [byont](https://github.com/Teach2Breach/byont) - Clean DLL extraction
- [noldr](https://github.com/Teach2Breach/noldr) - System DLL loading
