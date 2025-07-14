# Stargate: Bypassing EDR Hooks Through Signature-Based Function Discovery

## Introduction

This post introduces **Stargate**, a novel Rust library that takes a fundamentally different approach to function location. Instead of relying on easily-hooked structures like the PEB or EAT, Stargate uses signature-based scanning to find functions in memory, making it resistant to common detection mechanisms.

## The Problem: Traditional Function Location is Too Visible

### PEB Walking and EAT Parsing

Traditional function location techniques follow a well-trodden path that defenders have learned to monitor:

1. **PEB Walking**: Navigate through the Process Environment Block to find loaded modules
2. **EAT Parsing**: Parse the Export Address Table to locate function addresses
3. **Direct Function Resolution**: Use `GetProcAddress` or similar APIs

These techniques are problematic because:

- **High Visibility**: EDR solutions specifically monitor PEB access and EAT parsing
- **Predictable Patterns**: The sequence of operations is well-known and easily detected
- **Hookable Points**: Both PEB walking and EAT parsing can be hooked at multiple levels
- **Limited Evasion**: Once detected, the entire function resolution chain is compromised

### The Hells Gate Approach

The "Hells Gate" technique represents an innovative approach that combines EAT parsing with additional obfuscation layers. While effective in many scenarios, it operates within the same fundamental paradigm of structure-based function resolution.

### Real-World Detection Scenarios

Modern EDR solutions employ various detection mechanisms that may include:

- **API Call Monitoring**: Functions like `GetProcAddress` and `LoadLibrary` are commonly monitored
- **Memory Access Patterns**: Access to PEB structures may trigger alerts in some EDR solutions
- **Behavioral Analysis**: Sequences of operations that match known patterns may be flagged
- **Hook Detection**: Some EDR solutions attempt to detect when their hooks are being bypassed

*Note: The effectiveness of these detection mechanisms varies between different EDR solutions and configurations.*

## Stargate's Novel Approach: Signature-Based Discovery

Stargate takes a completely different approach by treating function location as a **pattern matching problem** rather than a **structure parsing problem**. Instead of asking "where is the export table pointing?", we ask "what does this function look like in memory?"

### Why Function Signatures Work

Function signatures can be stable across Windows versions due to several factors:

1. **Compiler Consistency**: Microsoft typically uses consistent compiler settings for system DLLs
2. **ABI Stability**: The Windows Application Binary Interface generally remains stable across versions
3. **Optimization Predictability**: System functions are often compiled with predictable optimization levels
4. **Prologue Patterns**: Function prologues typically follow consistent patterns for stack management

For example, a typical x64 function prologue might look like:
```
48 89 5C 24 08    mov [rsp+8], rbx    ; Save rbx
48 89 74 24 10    mov [rsp+16], rsi   ; Save rsi
48 89 7C 24 18    mov [rsp+24], rdi   ; Save rdi
48 83 EC 20       sub rsp, 32         ; Allocate stack space
```

This pattern can be consistent across Windows versions and may provide a reliable signature, though stability varies by function and Windows version. By extracting these byte patterns from clean DLL files and then scanning loaded memory for matching patterns, we can locate functions without ever touching the EAT.

## Technical Implementation

### 1. Clean DLL Extraction with Byont

Stargate leverages the **Byont** library (from Teach2Breach) to download clean, unmodified DLL files directly from Microsoft's Symbol Server. This is crucial because:

- **Version Matching**: We get the exact DLL version that's loaded in memory
- **Clean Baseline**: No hooks, patches, or modifications
- **Automatic Detection**: Byont automatically detects the correct version from the loaded DLL

```rust
// Get clean DLL from Microsoft Symbol Server
let clean_dll = get_clean_dll(&dll_name_clean)
    .ok_or_else(|| SignatureError::DllNotFound(dll_name_clean.clone()))?;
```

The Byont library handles the complex process of:
- Querying Microsoft's Symbol Server for the exact DLL version
- Downloading the PDB (Program Database) file
- Extracting the clean DLL bytes
- Verifying file integrity and authenticity

### 2. In-Memory DLL Processing with Byont

The **Byont** library handles the complex task of loading the clean DLL into executable memory and applying all necessary relocations:

```rust
// Allocate executable memory and copy the DLL
let (memory, size) = allocate_executable_memory(&clean_dll)
    .ok_or(SignatureError::MemoryAllocationFailed)?;

// Apply relocations to match the loaded DLL's base address
let (clean_base, _ntdll_base, _delta) = apply_relocations_raw(memory, size)
    .ok_or(SignatureError::RelocationFailed)?;
```

This step is critical because it ensures our signatures are extracted from a DLL that's positioned in memory exactly like the target DLL. The relocation process involves:

- Parsing the PE (Portable Executable) headers
- Identifying relocation entries
- Adjusting absolute addresses based on the new base address
- Handling import tables and other relocatable structures

### 3. Signature Extraction

For each exported function, we extract a configurable number of bytes (default: 32) from the function's beginning:

```rust
// Extract signature bytes from function start
let signature_bytes = std::slice::from_raw_parts(func_addr as *const u8, signature_length);
```

The 32-byte default was chosen based on testing and analysis:
- It typically captures enough unique characteristics to identify functions
- It's generally long enough to reduce false positives
- It's typically short enough to remain stable across minor updates
- It provides sufficient data for basic hook detection

*Note: The optimal signature length may vary depending on the specific function and use case.*

#### Signature Extraction Algorithm

```rust
pub fn extract_function_signature(
    dll_base: usize,
    function_rva: usize,
    signature_length: usize
) -> Result<Vec<u8>, SignatureError> {
    let function_address = dll_base + function_rva;
    
    // Validate memory access
    if !is_valid_executable_memory(function_address, signature_length) {
        return Err(SignatureError::InvalidMemoryAccess);
    }
    
    // Extract signature bytes
    let signature_bytes = unsafe {
        std::slice::from_raw_parts(
            function_address as *const u8, 
            signature_length
        ).to_vec()
    };
    
    // Validate signature quality
    if !is_signature_quality_acceptable(&signature_bytes) {
        return Err(SignatureError::PoorSignatureQuality);
    }
    
    Ok(signature_bytes)
}
```

### 4. Memory Scanning with Moonwalk

The **Moonwalk** library provides the foundation for scanning loaded DLLs in memory:

```rust
// Find the loaded DLL in memory
let dll_base = find_dll_base(dll_name)
    .ok_or_else(|| SignatureError::DllNotFound(dll_name.to_string()))?;
```

### 5. System Function Resolution with Noldr (Optional)

The **Noldr** library is used only for comparison and verification purposes, allowing us to compare our signature-based results with traditional function resolution:

```rust
// Get system DLL address for comparison
let dll_base = get_system_dll_address(&format!("{}.dll", dll_name))?;

// Get function address using traditional methods
let function_address = get_system_function_address(dll_base, function_name)?;
```

This is optional and only used when we want to verify the accuracy of our signature-based approach.

### 6. Multi-Method Signature Matching

Stargate implements a sophisticated multi-stage scanning approach that progressively falls back to more aggressive methods:

#### Method 1: Exact Match at Expected RVA
First, we try to find the exact signature at the expected relative virtual address (RVA):

```rust
fn try_exact_match(dll_base: usize, signature: &FunctionSignature) -> Option<ScanResult> {
    let expected_address = dll_base + signature.function_rva;
    let actual_bytes = unsafe {
        std::slice::from_raw_parts(expected_address as *const u8, signature.signature_bytes.len())
    };
    
    if actual_bytes == signature.signature_bytes.as_slice() {
        // Perfect match - function is exactly where expected
        return Some(ScanResult {
            found_address: expected_address,
            confidence: 1.0,
            signature_matches: true,
            hook_details: None,
            scan_method: ScanMethod::ExactMatch,
        });
    }
    None
}
```

#### Method 2: Hook Detection and Partial Matching
If the exact match fails, we analyze the bytes for common hook patterns:

```rust
fn detect_hook_pattern(actual_bytes: &[u8], expected_bytes: &[u8]) -> Option<HookDetails> {
    // Check for JMP instruction (0xE9) at the beginning
    if actual_bytes[0] == 0xE9 {
        let jump_offset = u32::from_le_bytes([
            actual_bytes[1], actual_bytes[2], actual_bytes[3], actual_bytes[4]
        ]) as usize;
        let jump_target = actual_bytes.as_ptr() as usize + 5 + jump_offset;
        
        return Some(HookDetails {
            hook_type: HookType::JumpHook,
            original_bytes: expected_bytes[..5].to_vec(),
            hook_bytes: actual_bytes[..5].to_vec(),
            hook_offset: 0,
            jump_target: Some(jump_target),
        });
    }
    
    // Check for CALL instruction (0xE8) at the beginning
    if actual_bytes[0] == 0xE8 {
        let call_offset = u32::from_le_bytes([
            actual_bytes[1], actual_bytes[2], actual_bytes[3], actual_bytes[4]
        ]) as usize;
        let call_target = actual_bytes.as_ptr() as usize + 5 + call_offset;
        
        return Some(HookDetails {
            hook_type: HookType::CallHook,
            original_bytes: expected_bytes[..5].to_vec(),
            hook_bytes: actual_bytes[..5].to_vec(),
            hook_offset: 0,
            jump_target: Some(call_target),
        });
    }
    
    // Check for inline hooks (modified bytes in the middle)
    for i in 0..actual_bytes.len().saturating_sub(4) {
        if actual_bytes[i..i+4] != expected_bytes[i..i+4] {
            return Some(HookDetails {
                hook_type: HookType::InlineHook,
                original_bytes: expected_bytes[i..i+4].to_vec(),
                hook_bytes: actual_bytes[i..i+4].to_vec(),
                hook_offset: i,
                jump_target: None,
            });
        }
    }
    
    None
}
```

#### Method 3: Nearby Region Scanning
If the function has been relocated, we scan nearby memory regions using an optimized Boyer-Moore algorithm:

```rust
fn scan_nearby_regions(dll_base: usize, signature: &FunctionSignature) -> Option<ScanResult> {
    // Define search range around expected RVA
    let search_start = dll_base.saturating_sub(0x1000);
    let search_end = dll_base + 0x100000; // Search up to 1MB forward
    
    // Use Boyer-Moore algorithm for efficient string matching
    let bm = BoyerMoore::new(&signature.signature_bytes);
    
    // Scan in chunks for the signature
    for addr in (search_start..search_end).step_by(chunk_size) {
        let chunk = unsafe {
            std::slice::from_raw_parts(addr as *const u8, chunk_size)
        };
        
        // Search for signature in this chunk
        if let Some(offset) = bm.find_in(chunk) {
            let found_address = addr + offset;
            return Some(ScanResult {
                found_address,
                confidence: 0.9,
                signature_matches: true,
                hook_details: None,
                scan_method: ScanMethod::NearbyScan,
            });
        }
    }
    None
}
```

#### Method 4: Alternative Location Search
Finally, we check common relocation patterns and known alternative locations:

```rust
fn try_alternative_locations(dll_base: usize, signature: &FunctionSignature) -> Option<ScanResult> {
    // Common alternative locations to check
    let alternative_rvas = vec![
        signature.function_rva + 0x1000,  // Common relocation offset
        signature.function_rva - 0x1000,  // Backward relocation
        signature.function_rva + 0x2000,  // Larger offset
        signature.function_rva + 0x4000,  // ASLR-style relocation
    ];
    
    for alt_rva in alternative_rvas {
        let alt_address = dll_base + alt_rva;
        let actual_bytes = unsafe {
            std::slice::from_raw_parts(alt_address as *const u8, signature.signature_bytes.len())
        };
        
        if actual_bytes == signature.signature_bytes.as_slice() {
            return Some(ScanResult {
                found_address: alt_address,
                confidence: 0.85,
                signature_matches: true,
                hook_details: None,
                scan_method: ScanMethod::AlternativeLocation,
            });
        }
    }
    None
}
```

## Novel Techniques and Innovations

### 1. Signature-Based Function Resolution

This approach differs from traditional function resolution methods. While signature scanning has been used for malware detection and pattern matching, applying it specifically to function resolution represents a different approach. 

### 2. Hook-Resistant Scanning

Stargate attempts to detect hooks and work around them. The multi-method approach aims to locate functions even when they may have been modified.

### 3. Version-Agnostic Operation

By downloading clean DLLs from Microsoft's Symbol Server, Stargate can adapt to different Windows versions without requiring manual signature databases or version-specific code.

### 4. In-Memory Signature Database

Unlike approaches that require external files or databases, Stargate maintains signatures in memory, which may provide performance benefits and reduce disk I/O.

#### Memory-Efficient Storage

Signatures are stored using a hash table implementation designed for:
- **Fast Lookups**: O(1) average case complexity
- **Memory Efficiency**: Minimal overhead per signature
- **Cache Locality**: Optimized for CPU cache performance

### 5. Confidence Scoring

Each scan result includes a confidence score based on the matching method used:
- **1.0**: Exact match at expected location
- **0.9**: Relocated function found
- **0.85**: Function found at alternative location
- **0.8**: Hooked function detected
- **0.7+**: Partial match with hook detection

## Practical Usage

### Basic Function Location

```rust
use stargate::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Extract signatures from clean ntdll
    let db = extract_all_signatures("ntdll", 32)?;
    
    // Find specific function
    if let Some(result) = find_specific_function("ntdll", "NtQuerySystemTime", &db) {
        println!("Found NtQuerySystemTime at 0x{:x}", result.found_address);
        println!("Confidence: {:.2}", result.confidence);
        println!("Scan method: {:?}", result.scan_method);
        
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

### Silent Operation for Implants

For opsec-sensitive operations, Stargate provides a silent mode:

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

### Advanced Usage: Hook Analysis

```rust
use stargate::*;

fn analyze_hooks() -> Result<(), Box<dyn std::error::Error>> {
    let db = extract_all_signatures("ntdll", 32)?;
    
    // Check for hooks in critical functions
    let critical_functions = vec![
        "NtCreateFile",
        "NtWriteFile", 
        "NtReadFile",
        "NtCreateProcess",
        "NtCreateThread",
    ];
    
    for func_name in critical_functions {
        if let Some(result) = find_specific_function("ntdll", func_name, &db) {
            if let Some(hook) = &result.hook_details {
                println!("Hook detected in {}:", func_name);
                println!("  Type: {:?}", hook.hook_type);
                println!("  Offset: 0x{:x}", hook.hook_offset);
                if let Some(target) = hook.jump_target {
                    println!("  Target: 0x{:x}", target);
                }
            }
        }
    }
    
    Ok(())
}
```

## Characteristics and Potential Advantages

### 1. EDR Evasion Characteristics
- **No PEB Access**: Stargate avoids accessing the Process Environment Block
- **No EAT Parsing**: Bypasses Export Address Table parsing
- **No API Calls**: Doesn't use `GetProcAddress` or similar APIs
- **Reduced Visibility**: May reduce memory access patterns that could trigger detection

### 2. Hook Resistance Features
- **Detects Hooks**: Attempts to identify when functions have been modified
- **Works Around Hooks**: May locate functions even when they're hooked
- **Provides Intelligence**: Returns information about detected hook types and targets

### 3. Version Independence
- **Automatic Adaptation**: Can work with different Windows versions without modification
- **No Hardcoded Addresses**: No need to maintain version-specific offset databases
- **Future-Proof**: May adapt to new Windows releases automatically

### 4. Performance Characteristics
- **In-Memory Database**: Signature lookups without disk I/O
- **Efficient Scanning**: Memory scanning algorithms
- **Minimal Overhead**: Only extracts signatures when needed

## Limitations and Considerations

### 1. Signature Stability
Function signatures can change between Windows updates, though this is mitigated by:
- Using clean DLLs from the same version
- Configurable signature lengths
- Partial matching capabilities

### 2. Memory Access Requirements
Stargate requires read access to process memory, which may be restricted in some environments.

### 3. Performance Impact
Scanning large DLLs can be resource-intensive, though this is typically a one-time cost during signature extraction.

### 4. Hook Detection Limitations
While Stargate attempts to detect common hook patterns, sophisticated hooking techniques may evade detection.

### 5. False Positive Management
The signature-based approach may occasionally produce false positives, which can be mitigated by:
- Configurable signature lengths
- Confidence scoring
- Multiple verification methods

## Conclusion

Stargate represents a different approach to function location in Windows environments. By treating function discovery as a pattern matching problem rather than a structure parsing problem, it offers an alternative to traditional techniques.

The combination of clean DLL extraction, sophisticated signature matching, and hook detection makes Stargate suitable for various use cases:
- **Red Team Operations**: Exploring alternative function resolution methods
- **Malware Analysis**: Understanding different approaches to function location
- **Security Research**: Investigating signature-based detection and evasion
- **Implant Development**: Evaluating different stealth techniques

As EDR solutions continue to evolve, having multiple approaches to function location provides flexibility and options for different scenarios. The signature-based approach offers a different perspective on this fundamental problem.

## Future Work

Potential areas for future development include:
- **Advanced Hook Detection**: Detecting more sophisticated hooking techniques
- **Performance Optimization**: Improving scanning speed and efficiency
- **Optional Unhooking Modules**: Unhook specific functions before use

*Stargate is part of the Teach2Breach rust offensive tooling ecosystem, alongside other innovative tools like Moonwalk (memory scanning), Byont (clean DLL extraction), and Noldr (system function resolution). Together, these tools provide a comprehensive toolkit for advanced Windows security research and red team operations.* 