# Stargate

**Signature-based function discovery**

Stargate is a novel Rust library that takes a fundamentally different approach to locating Windows API functions. Instead of relying on easily-hooked structures like the PEB or Export Address Table, Stargate uses signature-based scanning to find functions in memory. Used in combination with [moonwalk](https://github.com/Teach2Breach/moonwalk) to avoid PEB walking to locate target dll base addresses. Together moonwalk and stargate represent a novel approach to locating windows API function addresses in memory.

**Why this matters:** Traditional function location techniques follow well-trodden paths that defenders have learned to monitor. Stargate treats function discovery as a pattern matching problem rather than a structure parsing problem.

For detailed technical information, see [blog.md](blog.md).

## 🎯 Key Features

- **Signature-Based Function Location**: Find functions by their byte signatures instead of EAT parsing
- **Hook-Resistant Scanning**: Detect EDR hooks and function modifications
- **Runtime Function Discovery**: Locate functions in currently loaded DLLs at runtime
- **Version-Specific Signatures**: Extract and use signatures specific to the exact DLL version
- **Memory-Based Database**: Fast in-memory signature storage without external dependencies
- **Multi-DLL Support**: Works with any loaded Windows DLL (ntdll, kernel32, etc.)

## 🚀 How It Works

Instead of asking "where is the export table pointing?", Stargate asks "what does this function look like in memory?"

### The Process
1. **Get Clean DLLs**: Download unmodified DLL files from Microsoft's Symbol Server
2. **Extract Signatures**: Pull unique byte patterns from function beginnings
3. **Find Loaded DLLs**: Use Moonwalk to locate DLLs in memory (no PEB walking)
4. **Pattern Match**: Scan memory for matching signatures
5. **Detect Hooks**: Identify when functions have been modified
6. **Return Addresses**: Get the actual runtime function locations

### Hook Resistance
Stargate doesn't just detect hooks—it works around them:
- **Exact Match**: Find functions exactly where expected
- **Hook Detection**: Identify JMP, CALL, and inline hooks
- **Relocation Search**: Find functions that have been moved
- **Alternative Locations**: Check common relocation patterns

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
stargate = { git = "https://github.com/Teach2Breach/stargate.git" }
```

## 🔧 Quick Start

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

### Signature Scanning Demo
```bash
cargo run --example signature_scanning
```

**Example Output:**
```
DLL Inspector - Signature Scanning Example
This example demonstrates hook-resistant signature scanning

=== Step 1: Extracting Signatures ===
Extracting ntdll signatures...
Extracted 2514 ntdll signatures
Extracting kernel32 signatures...
Extracted 1691 kernel32 signatures
Combined database contains 4205 signatures

=== Step 2: Scanning Loaded DLLs ===
Scanning loaded ntdll.dll...
Found 2514 functions in loaded ntdll
Scanning loaded kernel32.dll...
Found 1691 functions in loaded kernel32

=== Step 3: Analysis Results ===
Total functions found: 4205
Exact signature matches: 4196
Hooked functions detected: 9
Relocated functions: 0

=== Step 4: Detailed Function Analysis ===
Function: NtQuerySystemTime
  DLL: ntdll
  Found at: 0x7fff15f02900
  Expected RVA: 0x162900
  Actual RVA: 0x162900
  Scan method: ExactMatch
  Confidence: 100.0%
  ✅ Signature matches exactly!

Function: Sleep
  DLL: kernel32
  Found at: 0x7fff14e71980
  Expected RVA: 0x31980
  Actual RVA: 0x31980
  Scan method: ExactMatch
  Confidence: 100.0%
  ✅ Signature matches exactly!
```

### Silent Function Calling (Recommended for Implants)
For opsec-sensitive operations and implants, use the silent example that minimizes output:
```bash
cargo run --example silent_call
```

**Example Output:**
```
GetTickCount: 229817843
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

## 🎯 Use Cases

### Red Team Operations
- **Bypass EDR**: Find functions without triggering EAT parsing or PEB walking hooks
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

## ⚠️ Security Considerations

- **Memory Access**: Requires read access to process memory
- **Signature Reliability**: Signatures may change between Windows versions
- **Hook Detection**: Not all hooking techniques may be detected
- **Performance**: Scanning large DLLs can be resource-intensive

## 🔧 Dependencies

- `byont` - Clean DLL extraction and processing
- `noldr` - System DLL loading and function resolution  
- `moonwalk` - Memory scanning and DLL base address location
- `thiserror` - Error handling

## Future Development

- `unhooking` - add optional unhooking feature for functions detected with hooks

## 🔗 Related Projects

- [moonwalk](https://github.com/Teach2Breach/moonwalk) - Memory scanning library (enables PEB-free DLL discovery)
- [byont](https://github.com/Teach2Breach/byont) - Clean DLL extraction
- [noldr](https://github.com/Teach2Breach/noldr) - System DLL loading
