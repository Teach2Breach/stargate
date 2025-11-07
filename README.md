# Stargate

**Signature-based function discovery**

Stargate is a novel Rust library that takes a fundamentally different approach to locating Windows API functions. Instead of relying on easily-hooked structures like the PEB or Export Address Table, Stargate uses signature-based scanning to find functions in memory. Used in combination with [moonwalk](https://github.com/Teach2Breach/moonwalk) to avoid PEB walking to locate target dll base addresses. Together moonwalk and stargate represent a novel approach to locating windows API function addresses in memory.

**Why this matters:** Traditional function location techniques follow well-trodden paths that defenders have learned to monitor. Stargate treats function discovery as a pattern matching problem rather than a structure parsing problem.

For detailed technical information, see [blog.md](blog.md).

## 🎯 Key Features

- **Signature-Based Function Location**: Find functions by their byte signatures instead of EAT parsing
- **Enhanced Hook Detection**: Advanced inline hook detection with syscall pattern recognition
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

### Enhanced Hook Detection
Stargate provides advanced inline hook detection capabilities:
- **Syscall Pattern Recognition**: Detect ntdll syscall prologue modifications (4C 8B D1)
- **Multiple Hook Patterns**: Identify JMP, CALL, PUSH+RET, and MOV+JMP patterns
- **Inline Hook Detection**: Find modified bytes within function bodies
- **Target Address Analysis**: Analyze hook redirect targets for suspicious patterns
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

type NtQuerySystemTimeFunc = extern "system" fn(lpSystemTime: *mut i64) -> i32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Extract signatures silently (ntdll recommended for strict environments)
    let db = extract_all_signatures("ntdll", 32)?;
    
    // Find and call function with minimal output
    if let Some(result) = find_specific_function("ntdll", "NtQuerySystemTime", &db) {
        let query_time: NtQuerySystemTimeFunc = unsafe { 
            std::mem::transmute(result.found_address as *const c_void) 
        };
        let mut system_time = 0i64;
        let status = query_time(&mut system_time);
        // Only print essential result
        println!("NtQuerySystemTime: {} (status: {})", system_time, status);
    }
    Ok(())
}
```

## 🛠️ Usage Examples

### Extract Signatures from Clean DLLs

```rust
// Extract all signatures from a clean DLL (version detected automatically)
// Recommended: Use ntdll for strict environments
let db = extract_all_signatures("ntdll", 32)?;
println!("Extracted {} signatures", db.len());

// Extract single function signature
let sig = extract_single_signature("ntdll", "NtQuerySystemTime", 32)?;

// Note: kernel32 scanning may trigger security products in strict environments
// let sig = extract_single_signature("kernel32", "Sleep", 32)?; // Use with caution
```

### Scan Loaded DLLs for Functions

```rust
// Scan entire DLL (recommended: ntdll for strict environments)
let results = scan_loaded_dll("ntdll", &db)?;

// Find specific function
let result = find_specific_function("ntdll", "NtQuerySystemTime", &db)?;

// Scan all loaded DLLs (use with caution in strict environments)
let all_results = scan_all_loaded_dlls(&db);

// Note: kernel32 scanning may trigger security products
// let result = find_specific_function("kernel32", "Sleep", &db)?; // Use with caution
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

### Enhanced Hook Detection Demo
```bash
cargo run --example enhanced_hook_detection
```

**Features:**
- Advanced syscall pattern recognition (4C 8B D1)
- Multiple hook pattern detection (JMP, CALL, PUSH+RET, MOV+JMP)
- Inline hook identification
- Target address analysis
- Detailed reporting to `enhanced_hooks.txt`

**Example Output:**
```
Enhanced Hook Detection Scanner
This example demonstrates improved hook detection with syscall pattern analysis

=== Step 1: Extracting Signatures ===
Extracted 2514 signatures from ntdll

=== Step 2: Enhanced Hook Detection ===
Scanned 2514 functions

=== Step 3: Analyzing Results ===
Found 9 hooked functions out of 2514 total functions

=== Step 4: Writing Enhanced Analysis ===
Enhanced hook report written to enhanced_hooks.txt
Found 9 hooked functions

=== Step 5: Enhanced Console Summary ===
⚠️  ENHANCED HOOK DETECTION RESULTS:
  ntdll!NtCreateFile at 0x7fff15f02900
    Hook type: JumpHook
    Target: 0x7fff12345678
    Syscall pattern detected!
```

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
For opsec-sensitive operations and implants, use the silent example that minimizes output and avoids kernel32:
```bash
cargo run --release --target x86_64-pc-windows-msvc --example silent_call
```

**Example Output:**
```
NtQuerySystemTime: 133970745314599291 (status: 0)
```

This example demonstrates clean function calling with minimal logging - only prints the function name and result, and uses ntdll for maximum opsec.

### Unhook Example (Advanced)
⚠️ **WARNING: This example will attempt to unhook ntdll functions! Only run in controlled environments!**

The unhook example demonstrates enhanced hook detection combined with automatic unhooking using nt_unhooker:
```bash
cargo run --example unhook
```

**Features:**
- Enhanced hook detection with syscall pattern recognition
- Automatic unhooking using nt_unhooker library
- Pre and post-unhook verification scanning
- Detailed success rate analysis
- Comprehensive reporting to `unhook_report.txt`

**Example Output:**
```
Stargate Unhook Example
This example demonstrates enhanced hook detection and unhooking using nt_unhooker
⚠️  WARNING: This example will attempt to unhook ntdll functions!
   Only run this in a controlled environment!

=== Step 1: Extracting Signatures ===
Extracted 2488 signatures from ntdll

=== Step 2: Initial Hook Detection ===
Scanned 2481 functions
Found 64 hooked functions before unhooking

=== Step 3: Writing Initial Analysis ===

=== Step 4: Unhooking Functions ===
Attempting to unhook 64 functions using nt_unhooker...
Processing sections...
Processing section: .text
Found .text section at RVA: 0x1000, Raw offset: 0x1000, Size: 0x12e000
Writing clean section at 0x7ffb28711000 with size 0x12e000
Successfully wrote 1236992 bytes
✅ nt_unhooker unhook_ntdll() completed successfully

=== Step 5: Post-Unhook Verification ===
Post-unhook scan completed: 2481 functions
Found 0 hooked functions after unhooking

=== Step 6: Analysis and Comparison ===
Unhooking Results:
  Initial hooks: 64
  Remaining hooks: 0
  Successfully unhooked: 64
  Success rate: 100.0%

=== Step 7: Final Summary ===
🎉 All 64 hooks were successfully removed!

✅ Unhook example completed successfully!
Check unhook_report.txt for detailed analysis
```

**Dependencies:**
- Requires `nt_unhooker` crate for unhooking functionality
- Uses `winapi` for Windows API types

### Building Examples with Static CRT
For production builds with static linking:
```bash
# Set environment variable for static CRT
set RUSTFLAGS=-C target-feature=+crt-static

# Build enhanced hook detection example
cargo build --release --target x86_64-pc-windows-msvc --example enhanced_hook_detection

# Run the built example
target\x86_64-pc-windows-msvc\release\examples\enhanced_hook_detection.exe
```

## 🔍 API Reference

### Core Functions

- `extract_all_signatures(dll_name, length)` - Extract all signatures from clean DLL (version detected automatically)
- `extract_all_signatures_from_loaded)` - Extract all signatures from DLL by base address.
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
- **EDR Triggers**: Scanning all of kernel32.dll may trigger security products in strict environments - more testing is needed

**Why ntdll-only scanning is recommended:**
- `ntdll.dll` contains the core Windows NT functions that are less likely to be monitored
- `kernel32.dll` scanning has been observed to trigger some security products - more testing is needed to patch a solution
- Most critical functions can be accessed through ntdll equivalents
- Reduces the attack surface for detection
- Enhanced hook detection works best with ntdll syscall patterns

**When to scan kernel32:**
- Development and testing environments
- Research and analysis scenarios
- When specific kernel32 functions are required
- In environments where you have confirmed EDR behavior

## 🔧 Dependencies

- `byont` - Clean DLL extraction and processing
- `moonwalk` - Memory scanning and DLL base address location
- `thiserror` - Error handling
- `nt_unhooker` - NTDLL unhooking functionality (optional, for unhook example)
- `winapi` - Windows API bindings (optional, for unhook example)

## Future Development

- Enhanced unhooking capabilities for other DLLs beyond ntdll
- Additional hook detection patterns and techniques
- Performance optimizations for large-scale scanning

## 🔗 Related Projects

- [moonwalk](https://github.com/Teach2Breach/moonwalk) - Memory scanning library (enables PEB-free DLL discovery)
- [byont](https://github.com/Teach2Breach/byont) - Clean DLL extraction
