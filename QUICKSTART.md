# Quick Start Guide - PE Analysis

## ⚠️ IMPORTANT DISCLAIMER - EDUCATIONAL USE ONLY

**This guide is for EDUCATIONAL and RESEARCH purposes ONLY.**

- Learn reverse engineering techniques for legitimate educational purposes
- **NOT** for exploiting software or bypassing security measures
- **NOT** for creating malware, hacks, or unauthorized modifications
- Only analyze software you have explicit permission to analyze
- Comply with all applicable laws and regulations

**Use this knowledge responsibly and ethically.**

---

## 5-Minute Setup

### Step 1: Install Python Dependencies
```bash
pip install pefile
```

### Step 2: Extract All PE Sections
```bash
cd "E:\MMORPG\Decompile"
python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder"
```

**Result**: Creates folders for each .exe with extracted sections, strings, imports, etc.

### Step 3: Quick Reconnaissance

**Check what APIs are used:**
```bash
type "BGStart\imports.txt"
```

**Find interesting strings:**
```bash
type "BGStart\strings.txt" | findstr /i "config file registry http"
```

**Check metadata:**
```bash
type "BGStart\metadata.txt"
```

---

## Understanding Your Decompiled Code

### What You Saw in Ghidra

```c
void entry(void) {
    __security_init_cookie();  // Security initialization
    FUN_00644de();             // ← THE REAL PROGRAM STARTS HERE
    return;
}
```

### What to Do Next

1. **In Ghidra's Decompiler window:**
   - Double-click on `FUN_00644de`
   - This takes you to the actual program logic

2. **Rename the function:**
   - Right-click on `FUN_00644de`
   - Select "Edit Function Signature"
   - Change name to `main` or `WinMain`

3. **Look for these patterns:**

   **Configuration loading:**
   ```c
   GetModuleFileName(...);  // Get own path
   ReadFile(...);           // Read config
   ```

   **Process creation:**
   ```c
   CreateProcess(...);      // Launch another program
   ```

   **Network activity:**
   ```c
   WSAStartup(...);         // Network init
   connect(...);            // Connect to server
   ```

   **Persistence:**
   ```c
   RegSetValue(...);        // Add to registry
   CreateFile(...);         // Write startup file
   ```

---

## Step-by-Step Analysis Workflow

### Phase 1: Static Analysis (30 minutes)

1. **Extract PE sections** (Done with script)
   ```bash
   python pe_extractor.py "path\to\exe"
   ```

2. **Review strings for clues**
   - File paths → What files it accesses
   - URLs/IPs → Network destinations
   - Registry keys → Persistence methods
   - Error messages → Program behavior

3. **Check imports**
   - Network APIs → `ws2_32.dll`, `winhttp.dll`
   - File APIs → `CreateFile`, `WriteFile`, `ReadFile`
   - Registry APIs → `RegOpenKey`, `RegSetValue`
   - Process APIs → `CreateProcess`, `OpenProcess`

### Phase 2: Ghidra Analysis (1-2 hours)

1. **Import to Ghidra**
   - File → Import File
   - Let it auto-analyze (click Yes)

2. **Navigate to entry point**
   - Symbol Tree → Functions → entry
   - Follow the execution flow

3. **Identify main logic**
   - From entry, go to the called function (FUN_00644de in your case)
   - This is usually `main()` or `WinMain()`

4. **Map out functionality**
   - Rename functions as you understand them
   - Add comments to important sections
   - Use bookmarks for interesting areas

5. **Trace interesting API calls**
   - Right-click API call → Find References
   - See where and how it's used

### Phase 3: Compare Executables (30 minutes)

**Find common functionality:**
```bash
# Compare imports
fc BGStart\imports.txt scthost\imports.txt

# Compare strings
fc BGStart\strings.txt scthost\strings.txt
```

**Questions to answer:**
- Are these different modules of same system?
- Do they communicate with each other?
- Do they share configuration files?
- What's the execution order?

---

## Common Patterns You'll See

### Pattern 1: Monitoring Software

```c
while (true) {
    // Get active window
    HWND hwnd = GetForegroundWindow();
    GetWindowText(hwnd, buffer, MAX_PATH);

    // Log activity
    LogActivity(buffer);

    // Wait
    Sleep(1000);
}
```

**Look for:**
- `GetForegroundWindow` - Active window monitoring
- `GetWindowText` - Window title capture
- `GetKeyState` / `GetAsyncKeyState` - Keyboard monitoring
- Timing loops with `Sleep()`

### Pattern 2: Process Launcher

```c
void LaunchProcess(char* exePath) {
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    CreateProcess(
        exePath,           // Application
        NULL,              // Command line
        NULL, NULL,        // Security
        FALSE,             // Inherit handles
        CREATE_NO_WINDOW,  // Creation flags
        NULL, NULL,        // Environment, directory
        &si, &pi           // Startup/Process info
    );

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
```

**Look for:**
- `CreateProcess` - Launching executables
- `CREATE_NO_WINDOW` - Hidden execution
- `ShellExecute` - Opening files/URLs

### Pattern 3: Configuration Management

```c
void LoadConfig(void) {
    char configPath[MAX_PATH];

    // Get AppData path
    SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, configPath);
    strcat(configPath, "\\AppName\\config.ini");

    // Read config
    GetPrivateProfileString("Settings", "ServerURL",
                           "http://default.com",
                           serverURL, MAX_PATH,
                           configPath);
}
```

**Look for:**
- `SHGetFolderPath` / `SHGetSpecialFolderPath` - Special folder paths
- `GetPrivateProfileString` - INI file reading
- `ReadFile` - Binary config reading
- File paths in strings

### Pattern 4: Network Communication

```c
void ConnectToServer(void) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;

    // Initialize Winsock
    WSAStartup(MAKEWORD(2,2), &wsaData);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);

    // Setup server address
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    server.sin_addr.s_addr = inet_addr("192.168.1.100");

    // Connect
    connect(sock, (struct sockaddr*)&server, sizeof(server));

    // Send/Receive data
    send(sock, data, dataSize, 0);
    recv(sock, buffer, bufferSize, 0);
}
```

**Look for:**
- `WSAStartup` - Winsock initialization
- `socket`, `connect`, `send`, `recv` - Socket operations
- IP addresses or domains in strings
- `InternetOpen`, `InternetConnect` - WinINet (HTTP)

---

## Keyboard Shortcuts Cheat Sheet

### Ghidra Navigation
| Key | Action |
|-----|--------|
| `G` | Go to address |
| `L` | Rename label/function |
| `;` | Add comment |
| `Ctrl+L` | Retype variable |
| `Ctrl+D` | Bookmark |
| `Ctrl+E` | Edit function signature |
| `Alt+←` | Back |
| `Alt+→` | Forward |
| `Ctrl+Shift+E` | Function search |
| `Ctrl+Shift+F` | Text search |

### Decompiler Window
| Action | Method |
|--------|--------|
| Rename variable | Right-click → Rename Variable |
| Change type | Right-click → Retype Variable |
| Find references | Right-click → References → Show References to |
| Go to definition | Double-click on function name |

---

## Troubleshooting

### Q: Script fails with "No module named 'pefile'"
**A:** Install it: `pip install pefile`

### Q: Ghidra shows "FUN_*" for everything
**A:** Normal - these are auto-generated names. Rename as you analyze.

### Q: Decompiler shows "undefined4" everywhere
**A:** Ghidra couldn't determine types. You can manually set them with `Ctrl+L`.

### Q: "Cannot find appropriate PDB file" warning
**A:** Ignore - this is normal for release builds without debug symbols.

### Q: Too much code to analyze
**A:** Start with high-level flow:
1. Entry point → Main function
2. Check imports for interesting APIs
3. Search strings for clues
4. Focus on those specific areas

---

## Files You Now Have

### Created by pe_extractor.py

For each executable (e.g., BGStart.exe):

```
BGStart/
├── .text           # Executable code section
├── .data           # Initialized data
├── .rdata          # Read-only data
├── .reloc          # Relocation info
├── .rsrc/          # Resources (icons, etc.)
├── imports.txt     # All imported DLL functions
├── exports.txt     # Exported functions (if any)
├── strings.txt     # ASCII and Unicode strings
└── metadata.txt    # PE file metadata
```

### Documentation Files

```
E:\MMORPG\Decompile/
├── pe_extractor.py       # Extraction script
├── ANALYSIS_GUIDE.md     # Complete guide (this file)
├── BGSTART_ANALYSIS.md   # Specific BGStart analysis
└── QUICKSTART.md         # Quick reference
```

---

## Next Steps

### Immediate (5 minutes)
1. ✅ Run extraction script
2. ✅ Review BGStart imports.txt
3. ✅ Review BGStart strings.txt

### Short-term (30 minutes)
1. ✅ Open BGStart.exe in Ghidra
2. ✅ Navigate from entry → FUN_00644de
3. ✅ Identify application type (GUI/Console/Service)
4. ✅ Rename main function

### Medium-term (2 hours)
1. ✅ Map out main execution flow
2. ✅ Identify all key functions
3. ✅ Document API usage
4. ✅ Compare with other executables

### Long-term
1. ✅ Full behavioral analysis
2. ✅ Create call graphs
3. ✅ Dynamic analysis in VM
4. ✅ Write analysis report

---

## Pro Tips

1. **Always work in a VM** when analyzing unknown executables
2. **Take notes** as you analyze - you'll forget details
3. **Use bookmarks** liberally in Ghidra
4. **Rename early and often** - makes later analysis easier
5. **Compare with similar software** - learn common patterns
6. **Don't rush** - understanding takes time
7. **Ask specific questions** - easier to find answers

---

## What Makes BGStart Interesting?

Based on the name "BGStart" (Background Start), this likely:

✓ Runs other components in the background
✓ Possibly runs as a Windows service
✓ May be part of a multi-component system
✓ Probably launches other .exe files you extracted

**Check for:**
- Calls to `CreateProcess` or `ShellExecute`
- File paths to other executables in the same directory
- Service-related APIs: `StartServiceCtrlDispatcher`
- Mutex creation for single-instance check

---

## Need More Help?

### If you want to analyze specific code:
1. Take a screenshot of the Ghidra decompiler window
2. Note the function address
3. Share the function name and surrounding context

### If you want to understand behavior:
1. Share the imports.txt content
2. Share interesting strings from strings.txt
3. Describe what you want to know

### If you're stuck:
1. What specific function are you analyzing?
2. What doesn't make sense?
3. What are you trying to understand?

---

## Summary

You now have:
- ✅ Automated PE extraction script
- ✅ Complete analysis methodology
- ✅ Specific guidance for BGStart.exe
- ✅ Quick reference for common patterns

**Start here:**
```bash
# 1. Extract sections
python pe_extractor.py "ACTIVTRAK Agent\SourceDir\SystemFolder\BGStart.exe"

# 2. Review what it imports
type BGStart\imports.txt

# 3. Look for interesting strings
type BGStart\strings.txt | findstr /i "config registry http file"

# 4. Open in Ghidra and navigate to FUN_00644de
```

Good luck with your analysis! 🔍
