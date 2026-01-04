# Complete Guide to PE Analysis and Decompilation

## ⚠️ IMPORTANT DISCLAIMER - EDUCATIONAL USE ONLY

**This guide is intended for EDUCATIONAL and RESEARCH purposes ONLY.**

- **FOR LEARNING**: Understand how software works through reverse engineering
- **NOT FOR EXPLOITATION**: Do not use this knowledge to bypass security, create exploits, or violate software terms
- **NOT FOR MALICIOUS USE**: Do not create malware, hacks, or unauthorized modifications
- **RESPECT LAWS**: Only analyze software you have explicit permission to analyze
- **ETHICAL USE**: Use knowledge responsibly and ethically

**By using this guide, you agree to use it only for legitimate educational and research purposes in compliance with all applicable laws.**

---

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [PE Section Extraction](#pe-section-extraction)
3. [Static Analysis with Ghidra](#static-analysis-with-ghidra)
4. [Understanding Decompiled Code](#understanding-decompiled-code)
5. [Analyzing BGStart.exe Entry Point](#analyzing-bgstartexe-entry-point)
6. [Advanced Analysis Techniques](#advanced-analysis-techniques)

---

## Prerequisites

### Required Tools
1. **Python 3.7+** with pefile module
   ```bash
   pip install pefile
   ```

2. **Ghidra** (you already have v12.0)
   - Path: `E:\MMORPG\Decompile\ghidra_12.0_PUBLIC`

3. **Optional but useful:**
   - PE-bear (GUI PE viewer)
   - x64dbg or WinDbg (dynamic analysis)
   - IDA Free (alternative decompiler)
   - Detect It Easy (packer detection)

---

## PE Section Extraction

### Step 1: Understanding PE File Structure

A PE (Portable Executable) file contains:
- **Headers**: DOS header, PE header, Optional header
- **Sections**: Code and data segments
  - `.text` - Executable code
  - `.data` - Initialized writable data
  - `.rdata` - Read-only data (strings, constants)
  - `.reloc` - Relocation information
  - `.rsrc` - Resources (icons, dialogs, etc.)

### Step 2: Run the Extraction Script

**Single file extraction:**
```bash
cd "E:\MMORPG\Decompile"
python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder\BGStart.exe"
```

**Extract all executables in directory:**
```bash
python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder"
```

**Include DLL files:**
```bash
python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder" --include-dll
```

### Step 3: Review Extracted Files

After extraction, each executable will have a folder with:
- Individual section files (`.text`, `.data`, `.rdata`, etc.)
- `imports.txt` - All imported DLL functions
- `exports.txt` - Exported functions (if any)
- `strings.txt` - Extracted ASCII and Unicode strings
- `metadata.txt` - PE file metadata
- `.rsrc/` - Extracted resources

**What to look for:**
- **High entropy sections** (> 7.0) may indicate packed/encrypted code
- **Import list** reveals what APIs the program uses
- **Strings** can reveal URLs, registry keys, file paths, error messages

---

## Static Analysis with Ghidra

### Step 1: Create Ghidra Project

1. Launch Ghidra
2. **File → New Project**
3. Choose "Non-Shared Project"
4. Name: `MMORPG_Analysis`
5. Location: `E:\MMORPG\Decompile\ghidra_projects`

### Step 2: Import Executable

1. **File → Import File**
2. Select executable (e.g., `BGStart.exe`)
3. Click **OK** on format detection
4. When prompted "Analyze now?", click **Yes**
5. **Analysis Options**:
   - ✅ Aggressive Instruction Finder
   - ✅ Decompiler Parameter ID
   - ✅ Function Start Search
   - ✅ Non-Returning Functions - Discovered
   - ✅ Reference
   - ✅ Shared Return Calls
   - ✅ Stack
   - ✅ Windows x86 PE Exception Handling
   - ✅ Windows x86 Thread Environment Block (TEB) Analyzer

**Note:** The PDB warning you saw is normal - release builds don't include debug symbols.

### Step 3: Navigate the Interface

**Main Windows:**
- **Listing (Disassembly)**: Shows assembly code
- **Decompiler**: Shows C-like pseudo-code
- **Symbol Tree**: Functions, imports, exports
- **Data Type Manager**: Structures and types
- **Program Trees**: Sections and memory layout

**Key Shortcuts:**
- `G` - Go to address
- `L` - Edit label (rename function/variable)
- `Ctrl+Shift+E` - Search for functions
- `Ctrl+Shift+F` - Search program text
- `;` - Add comment
- `Ctrl+L` - Retype variable

### Step 4: Find Entry Point

1. Click **Symbol Tree** → **Functions** → **entry**
2. Or press `G` and enter the entry point address from metadata.txt
3. The decompiler will show the C-like code

---

## Understanding Decompiled Code

### What You're Seeing in BGStart.exe

Based on your screenshot, the `entry` function shows:

```c
void entry(void) {
    __security_init_cookie();
    FUN_00644de();
    return;
}
```

**Breakdown:**

1. **`__security_init_cookie()`**
   - Security feature: Stack buffer overrun protection
   - Initializes a random "cookie" value
   - Used to detect stack corruption

2. **`FUN_00644de()`**
   - Ghidra's auto-generated name for an unknown function
   - Address: `0x00644de`
   - This is the **real main function**
   - Double-click to navigate to it

### How to Analyze Functions

#### Step 1: Rename Functions
1. Right-click on `FUN_00644de`
2. Select **Edit Function Signature**
3. Rename to something meaningful (e.g., `main` or `startup`)

#### Step 2: Identify Function Parameters
Look at the assembly in the Listing window:
- **32-bit (cdecl/stdcall)**: Parameters pushed on stack
- **64-bit**: First 4 params in RCX, RDX, R8, R9
- Check decompiler's parameter detection

#### Step 3: Analyze Control Flow
- **If statements**: Look for conditional jumps (JZ, JNZ, JE, JNE)
- **Loops**: Look for backward jumps
- **Function calls**: CALL instructions
- **Switch statements**: Jump tables

#### Step 4: Identify API Calls
- Look in **Symbol Tree → Imports**
- Common Windows APIs:
  - `CreateProcess` - Launching programs
  - `WriteFile` / `ReadFile` - File I/O
  - `RegSetValue` - Registry modification
  - `VirtualAlloc` - Memory allocation
  - `LoadLibrary` / `GetProcAddress` - Dynamic loading
  - `socket` / `send` / `recv` - Network communication

---

## Analyzing BGStart.exe Entry Point

### Step-by-Step Analysis

#### Step 1: Navigate to Real Main
1. In the decompiler for `entry`, double-click `FUN_00644de`
2. This function likely contains the program logic

#### Step 2: Look for Initialization Code
Common patterns:
```c
// Initializing COM
CoInitialize(NULL);

// Setting up exception handlers
SetUnhandledExceptionFilter(...);

// Checking for single instance
CreateMutex(...);
```

#### Step 3: Identify Main Functionality

**Look for:**
- **Strings**: Right-click → Find References to see where strings are used
- **Loops**: Main event loops or monitoring loops
- **Network activity**: Socket calls, HTTP requests
- **File operations**: File paths being accessed
- **Registry access**: What keys are being read/written

#### Step 4: Trace Data Flow

1. **Find interesting strings** in `strings.txt`
2. **Search for string in Ghidra**: `Search → For Strings`
3. **Find references**: Right-click string → References → Show References to Address
4. **Analyze the function** that uses the string

### Example: Finding What BGStart Does

```bash
# Check strings for clues
grep -i "config\|registry\|file\|http\|server" BGStart/strings.txt
```

Common patterns in monitoring software:
- Registry persistence: `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
- Config files: AppData paths
- Network endpoints: IP addresses or domain names
- Process injection: OpenProcess, VirtualAllocEx, WriteProcessMemory

---

## Advanced Analysis Techniques

### 1. Cross-References (XREFs)

**Find where a function is called:**
1. Right-click function name
2. **References → Show References to [function]**

**Find what a function calls:**
1. Right-click function name
2. **References → Show References from [function]**

### 2. Scripting with Ghidra

Create Python/Java scripts to automate analysis:

**Example: Find all string references**
```python
# Ghidra Python script
from ghidra.program.model.data import StringDataType

currentProgram = getCurrentProgram()
strings = currentProgram.getListing().getDefinedData(True)

for data in strings:
    if isinstance(data.getDataType(), StringDataType):
        string_value = data.getValue()
        refs = data.getReferenceIteratorTo()
        print("{} used at:".format(string_value))
        for ref in refs:
            print("  {}".format(ref.getFromAddress()))
```

### 3. Dynamic Analysis

Once you understand the static structure:

1. **Set up VM**: Use a Windows VM for safe execution
2. **Process Monitor**: Monitor file/registry/network activity
3. **Debugger**: x64dbg or WinDbg
   - Set breakpoints on interesting functions
   - Trace execution flow
   - Inspect memory and registers

### 4. Comparing Executables

Compare all the extracted executables:

```bash
# Find shared strings
comm -12 <(sort BGStart/strings.txt) <(sort scthost/strings.txt)

# Compare imports
diff BGStart/imports.txt scthost/imports.txt
```

### 5. Identifying Obfuscation

**Signs of obfuscation/packing:**
- High entropy in .text section (> 7.5)
- Few imports (packed code unpacks at runtime)
- Unusual section names
- Code that writes to its own memory
- `VirtualProtect` calls to change memory permissions

**Tools to detect:**
```bash
# Use Detect It Easy or DIE
# Check entropy in metadata.txt from extraction script
```

---

## Quick Reference: Common Analysis Workflow

### Initial Reconnaissance
1. ✅ Extract PE sections with script
2. ✅ Review `metadata.txt` for basic info
3. ✅ Check `strings.txt` for interesting strings
4. ✅ Review `imports.txt` for API usage

### Deep Dive in Ghidra
1. ✅ Import to Ghidra and auto-analyze
2. ✅ Navigate to entry point
3. ✅ Trace execution from entry → main
4. ✅ Identify key functions (based on strings/imports)
5. ✅ Rename functions and variables
6. ✅ Document findings in comments

### Understanding Behavior
1. ✅ Map out control flow
2. ✅ Identify all external API calls
3. ✅ Find persistence mechanisms
4. ✅ Locate network communication
5. ✅ Check for anti-analysis techniques

### Verification
1. ✅ Compare static analysis findings
2. ✅ Run in controlled environment (VM)
3. ✅ Use Process Monitor to verify behavior
4. ✅ Use debugger to confirm hypotheses

---

## Troubleshooting

### "Cannot find appropriate PDB file"
- **Normal**: Release builds don't have debug symbols
- **Solution**: Ignore this warning, Ghidra can still analyze

### Decompiler shows "undefined" everywhere
- **Cause**: Analysis not complete or failed
- **Solution**: Re-run analysis with all options enabled

### Functions show as "External" or "Thunk"
- **Cause**: These are imported from DLLs
- **Solution**: These are legitimate - check imports.txt for details

### Too many FUN_* functions
- **Solution**: Gradually rename as you understand their purpose
- **Tip**: Use prefixes like `net_`, `file_`, `reg_` for organization

---

## Additional Resources

### Learning Resources
- **Ghidra Docs**: https://ghidra-sre.org/
- **Reverse Engineering Book**: "Practical Reverse Engineering" by Dang et al.
- **Malware Analysis**: "Practical Malware Analysis" by Sikorski & Honig

### Tools Comparison
| Tool | Best For | Cost |
|------|----------|------|
| Ghidra | Full-featured, scriptable | Free |
| IDA Free | Industry standard UI | Free (limited) |
| Binary Ninja | Modern UI, good for learning | Paid |
| x64dbg | Dynamic debugging | Free |
| Detect It Easy | Packer detection | Free |

---

## Next Steps for Your Analysis

1. **Run the extraction script on all executables**
   ```bash
   python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder"
   ```

2. **Compare the executables**
   - Which ones share functionality?
   - Are they different components of the same system?

3. **Focus on one executable (BGStart.exe)**
   - Follow the execution from entry
   - Map out the main functionality
   - Document all API calls

4. **Look for game-specific behavior**
   - Memory reading/writing (game hacks)
   - Process injection
   - Network packet manipulation
   - Anti-cheat evasion

Would you like me to help analyze any specific function or aspect of the code?
