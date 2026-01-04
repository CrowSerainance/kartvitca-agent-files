# PE Analysis Toolkit - Complete Setup

## ⚠️ IMPORTANT DISCLAIMER - EDUCATIONAL USE ONLY

**This repository is intended for EDUCATIONAL and RESEARCH purposes ONLY.**

- This project is for learning reverse engineering techniques and understanding software behavior
- **NOT** for exploiting, bypassing security, or unauthorized use of software
- **NOT** for creating malware, hacks, or cheating tools
- Use responsibly and ethically - only analyze software you have permission to analyze
- Respect software licenses, terms of service, and applicable laws
- The authors assume no liability for misuse of this information

**By using this repository, you agree to:**
- Use it only for legitimate educational/research purposes
- Comply with all applicable laws and regulations
- Not use the knowledge gained to harm others or violate software terms
- Accept full responsibility for your actions

---

## 📁 What You Have

### Scripts
- **pe_extractor.py** - Automated PE section extraction tool

### Documentation
- **QUICKSTART.md** - 5-minute quick start guide
- **ANALYSIS_GUIDE.md** - Complete step-by-step analysis methodology
- **BGSTART_ANALYSIS.md** - Detailed analysis of BGStart.exe entry point
- **README.md** - This file

---

## 🚀 Get Started in 3 Steps

### Step 1: Extract PE Sections (2 minutes)
```bash
cd "E:\MMORPG\Decompile"
python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder"
```

This will create folders for each executable containing:
- Extracted sections (.text, .data, .rdata, etc.)
- imports.txt - All imported functions
- strings.txt - Extracted strings
- metadata.txt - PE file information

### Step 2: Review Extracted Data (5 minutes)
```bash
# Check what APIs BGStart uses
type "BGStart\imports.txt"

# Find interesting strings
type "BGStart\strings.txt" | findstr /i "config file http"

# View metadata
type "BGStart\metadata.txt"
```

### Step 3: Analyze in Ghidra (Ongoing)
1. Open Ghidra
2. Import BGStart.exe
3. Auto-analyze (click Yes)
4. Navigate: Symbol Tree → Functions → entry
5. Double-click FUN_00644de to see main logic

---

## 📚 Documentation Guide

### For Beginners
Start with: **QUICKSTART.md**
- 5-minute setup
- Basic commands
- Common patterns to recognize

### For Complete Analysis
Read: **ANALYSIS_GUIDE.md**
- Full PE structure explanation
- Ghidra setup and usage
- Advanced analysis techniques
- Troubleshooting guide

### For BGStart Specific Analysis
See: **BGSTART_ANALYSIS.md**
- Explanation of entry() function
- What __security_init_cookie() does
- How to analyze FUN_00644de
- Expected patterns to find

---

## 🎯 Your Current Analysis

### Files to Analyze
Located in: `E:\MMORPG\Decompile\ACTIVTRAK Agent\SourceDir\SystemFolder\`

```
BGStart.exe    - 4.5 MB  (Currently analyzing in Ghidra)
scthost.exe    - 9.1 MB
scthosti.exe   - 5.1 MB
svctcom.exe    - 9.5 MB
svctcr.exe     - 2.1 MB
syschk.exe     - 5.2 MB
conmhost.dll   - 4.4 MB
scthosth.dll   - 2.0 MB
```

### Current Status
✅ Ghidra project created
✅ BGStart.exe imported and analyzed
✅ Entry point located (entry @ 0x006449ab)
🔄 Next: Analyze FUN_00644de (main function)

---

## 🔍 Quick Analysis Commands

### Extract All Executables
```bash
python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder"
```

### Extract Single File
```bash
python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder\BGStart.exe"
```

### Include DLL Files
```bash
python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder" --include-dll
```

### Compare Two Executables
```bash
# Compare imports
fc BGStart\imports.txt scthost\imports.txt

# Compare strings
fc BGStart\strings.txt scthost\strings.txt
```

### Search for Specific Patterns
```bash
# Find network-related strings
findstr /i "http https socket connect server ip port" BGStart\strings.txt

# Find file paths
findstr /i "C:\ %appdata% program" BGStart\strings.txt

# Find registry keys
findstr /i "HKEY_ registry software" BGStart\strings.txt
```

---

## 🛠️ pe_extractor.py Features

### What It Extracts

1. **PE Sections**
   - .text (code)
   - .data (initialized data)
   - .rdata (read-only data)
   - .reloc (relocations)
   - .rsrc (resources)
   - Custom sections

2. **Import Table**
   - All DLLs used
   - All functions imported
   - Organized by DLL

3. **Export Table**
   - Exported functions (for DLLs)
   - Function addresses
   - Ordinals

4. **Resources**
   - Icons, bitmaps
   - Dialogs, menus
   - Version info
   - Manifests

5. **Strings**
   - ASCII strings (4+ chars)
   - Unicode strings (UTF-16)
   - Extracted from entire binary

6. **Metadata**
   - PE type (32/64 bit)
   - Compilation timestamp
   - Entry point
   - Section information
   - File hashes (MD5)

### Output Format

For each executable, creates a folder:
```
BGStart/
├── .text              # Code section (binary)
├── .data              # Data section (binary)
├── .rdata             # Read-only data (binary)
├── .reloc             # Relocations (binary)
├── .rsrc/             # Resources folder
│   ├── ICON_1
│   ├── DIALOG_100
│   └── VERSION_1
├── imports.txt        # Human-readable import list
├── exports.txt        # Human-readable export list
├── strings.txt        # All extracted strings
└── metadata.txt       # PE file information
```

---

## 📖 Understanding Your Decompiled Code

### The Entry Point

What you saw in Ghidra:
```c
void entry(void)
{
    __security_init_cookie();  // Stack protection init
    FUN_00644de();             // Main program logic
    return;
}
```

### What Each Part Means

**__security_init_cookie()**
- Buffer overflow protection (Microsoft /GS flag)
- Creates random "canary" value
- Placed on stack before return addresses
- Checked before function returns
- If modified → overflow detected → program terminates

**FUN_00644de()**
- This is where the REAL program starts
- Auto-generated name (Ghidra couldn't determine actual name)
- Likely corresponds to main() or WinMain()
- **Your next step: Analyze this function**

### Next Steps in Ghidra

1. **Double-click FUN_00644de** in the decompiler
2. Look at the structure to identify application type:
   - GUI app: Has message loop, window creation
   - Console: Has argc/argv parameters
   - Service: Has service control dispatcher
   - Launcher: Creates processes
3. **Rename the function** once you understand it
4. **Add comments** to document your findings

---

## 🎓 Analysis Methodology

### Phase 1: Static Reconnaissance (30 min)
1. Run pe_extractor.py
2. Review metadata.txt
3. Check imports.txt for interesting APIs
4. Read strings.txt for clues
5. Note high entropy sections (possible packing)

### Phase 2: Ghidra Analysis (1-2 hours)
1. Import executable
2. Auto-analyze
3. Navigate to entry point
4. Follow execution flow
5. Rename functions
6. Document findings

### Phase 3: Deep Dive (2-4 hours)
1. Analyze key functions
2. Map out control flow
3. Identify data structures
4. Document all API usage
5. Create function call graph

### Phase 4: Comparison (30 min)
1. Compare multiple executables
2. Find shared code/libraries
3. Identify relationships
4. Determine execution order

### Phase 5: Dynamic Analysis (Optional)
1. Set up isolated VM
2. Run with Process Monitor
3. Debug with x64dbg
4. Monitor network with Wireshark
5. Verify static analysis findings

---

## 🚨 Important Notes

### ⚠️ LEGAL AND ETHICAL RESPONSIBILITY

**THIS IS FOR EDUCATIONAL USE ONLY - NOT FOR EXPLOITATION**

- **This repository is for learning reverse engineering and security research**
- **Do NOT use this knowledge to:**
  - Bypass security measures without authorization
  - Create exploits or malware
  - Violate software terms of service
  - Perform unauthorized access or hacking
  - Cheat in games or bypass anti-cheat systems

### Safety
- **Always analyze unknown executables in a VM**
- **Disable network** if analyzing potentially malicious code
- **Take snapshots** before running anything
- **Never analyze** on production systems

### Legal
- **Only analyze** software you have permission to analyze
- **Respect licenses** and terms of service
- **Educational purposes** - understand, don't abuse
- **Comply with all applicable laws** (DMCA, CFAA, etc.)
- **Obtain proper authorization** before analyzing any software

### Best Practices
- **Document everything** - you'll forget details
- **Work systematically** - don't jump around randomly
- **Take breaks** - complex code needs fresh eyes
- **Compare with legitimate software** - learn patterns
- **Ask for help** - reverse engineering is hard

---

## 🔧 Troubleshooting

### "Module 'pefile' not found"
```bash
pip install pefile
```

### "Permission denied" when extracting
- Run as administrator
- Check if files are in use
- Disable antivirus temporarily

### Ghidra crashes on import
- File might be packed/protected
- Try unpacking first
- Use different analysis options

### Too much undefined/unknown code
- Normal for optimized code
- Manually set types as you understand
- Focus on high-level flow first

### Can't find specific function
- Use Search → For Strings
- Search in imports.txt
- Check cross-references (XREF)

---

## 📊 What to Look For

### Common Application Patterns

**Monitoring Software:**
- GetForegroundWindow
- GetWindowText
- GetAsyncKeyState
- Timing loops (Sleep calls)

**Network Client:**
- WSAStartup
- socket, connect, send, recv
- InternetOpen, InternetConnect
- IP addresses/domains in strings

**Persistence:**
- Registry Run keys
- Startup folder
- Service installation
- Scheduled tasks

**Process Injection:**
- OpenProcess
- VirtualAllocEx
- WriteProcessMemory
- CreateRemoteThread

**Configuration:**
- GetModuleFileName
- SHGetFolderPath
- GetPrivateProfileString
- ReadFile/WriteFile

---

## 📞 Getting Help

### Included Documentation
- QUICKSTART.md - Quick reference
- ANALYSIS_GUIDE.md - Complete methodology
- BGSTART_ANALYSIS.md - Specific analysis

### When You Need More Help
Provide:
1. Function address or name
2. Screenshot of decompiled code
3. Relevant imports/strings
4. What you're trying to understand

---

## ✅ Checklist

### Initial Setup
- [x] Python with pefile installed
- [x] Ghidra installed and working
- [x] Extraction script created
- [x] Documentation available

### For Each Executable
- [ ] Extract PE sections
- [ ] Review metadata
- [ ] Check imports
- [ ] Read strings
- [ ] Import to Ghidra
- [ ] Analyze entry point
- [ ] Map main functions
- [ ] Document findings

### Advanced Analysis
- [ ] Compare executables
- [ ] Identify relationships
- [ ] Create call graphs
- [ ] Dynamic analysis (VM)
- [ ] Write final report

---

## 🎯 Your Immediate Next Steps

1. **Run the extraction script** (2 minutes)
   ```bash
   python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder"
   ```

2. **Review BGStart data** (5 minutes)
   ```bash
   type BGStart\imports.txt
   type BGStart\strings.txt | findstr /i "config http file"
   ```

3. **Continue Ghidra analysis** (30 minutes)
   - Double-click FUN_00644de
   - Identify application type
   - Rename main function
   - Add comments

4. **Document findings** (ongoing)
   - What does BGStart do?
   - How does it relate to other executables?
   - What's the overall system architecture?

---

## 📈 Success Metrics

You'll know you're making progress when you can answer:
- [ ] What type of application is this? (GUI/Console/Service)
- [ ] What is its main purpose?
- [ ] What APIs does it use?
- [ ] What files does it access?
- [ ] Does it communicate over network?
- [ ] How does it achieve persistence?
- [ ] How does it relate to other executables?

---

## 🌟 Tips for Success

1. **Start broad, then narrow** - Overview first, details later
2. **Rename aggressively** - Clear names make everything easier
3. **Comment liberally** - Future you will thank you
4. **Compare patterns** - Same patterns = same functionality
5. **Trust the tools** - Ghidra's analysis is usually good
6. **Verify with dynamic** - Confirm static findings by running
7. **Take notes externally** - Not just in Ghidra
8. **Draw diagrams** - Visualize relationships

---

Ready to start? Begin with:
```bash
python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder"
```

Then open QUICKSTART.md for the next steps!
