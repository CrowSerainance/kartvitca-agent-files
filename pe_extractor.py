#!/usr/bin/env python3
"""
PE Section Extractor - Automates extraction of PE sections from executables
Extracts .text, .data, .rdata, .reloc, .rsrc and other sections
"""

import os
import sys
import pefile
from pathlib import Path
import hashlib

def calculate_md5(data):
    """Calculate MD5 hash of data"""
    return hashlib.md5(data).hexdigest()

def extract_pe_sections(exe_path, output_dir=None):
    """
    Extract all sections from a PE file

    Args:
        exe_path: Path to the PE executable
        output_dir: Directory to save extracted sections (default: exe_name folder)

    Returns:
        Dictionary with extraction results
    """
    exe_path = Path(exe_path)

    if not exe_path.exists():
        print(f"[ERROR] File not found: {exe_path}")
        return None

    # Create output directory
    if output_dir is None:
        output_dir = exe_path.parent / exe_path.stem
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(exist_ok=True, parents=True)

    print(f"\n[*] Analyzing: {exe_path.name}")
    print(f"[*] Output directory: {output_dir}")

    try:
        pe = pefile.PE(str(exe_path))
    except Exception as e:
        print(f"[ERROR] Failed to parse PE file: {e}")
        return None

    results = {
        'exe': exe_path.name,
        'sections': [],
        'imports': [],
        'exports': [],
        'resources': []
    }

    # Extract basic PE info
    print(f"\n[+] PE Type: {'PE32+' if pe.FILE_HEADER.Machine == 0x8664 else 'PE32'}")
    print(f"[+] Compilation timestamp: {pe.FILE_HEADER.TimeDateStamp}")
    print(f"[+] Number of sections: {pe.FILE_HEADER.NumberOfSections}")

    # Extract sections
    print("\n[*] Extracting sections...")
    for section in pe.sections:
        section_name = section.Name.decode().rstrip('\x00')
        section_data = section.get_data()

        # Save section to file
        section_file = output_dir / section_name
        with open(section_file, 'wb') as f:
            f.write(section_data)

        section_info = {
            'name': section_name,
            'virtual_address': hex(section.VirtualAddress),
            'virtual_size': section.Misc_VirtualSize,
            'raw_size': section.SizeOfRawData,
            'entropy': section.get_entropy(),
            'md5': calculate_md5(section_data)
        }

        results['sections'].append(section_info)

        print(f"  [+] {section_name:10s} | VA: {section_info['virtual_address']:10s} | "
              f"Size: {section_info['raw_size']:8d} | Entropy: {section_info['entropy']:.2f}")

    # Extract imports
    print("\n[*] Extracting imports...")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            imports = []
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode())
                else:
                    imports.append(f"Ordinal_{imp.ordinal}")

            results['imports'].append({
                'dll': dll_name,
                'functions': imports
            })
            print(f"  [+] {dll_name}: {len(imports)} functions")

        # Save imports to text file
        imports_file = output_dir / "imports.txt"
        with open(imports_file, 'w') as f:
            for imp_entry in results['imports']:
                f.write(f"\n{imp_entry['dll']}\n")
                f.write("=" * len(imp_entry['dll']) + "\n")
                for func in imp_entry['functions']:
                    f.write(f"  {func}\n")

    # Extract exports
    print("\n[*] Extracting exports...")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exports_file = output_dir / "exports.txt"
        with open(exports_file, 'w') as f:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_name = exp.name.decode() if exp.name else f"Ordinal_{exp.ordinal}"
                results['exports'].append({
                    'name': export_name,
                    'address': hex(exp.address),
                    'ordinal': exp.ordinal
                })
                f.write(f"{export_name} @ {hex(exp.address)}\n")
                print(f"  [+] {export_name}")

    # Extract resources
    print("\n[*] Extracting resources...")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        resource_dir = output_dir / ".rsrc"
        resource_dir.mkdir(exist_ok=True)

        extract_resources(pe, resource_dir, results)

    # Extract strings (printable ASCII strings > 4 chars)
    print("\n[*] Extracting strings...")
    strings_file = output_dir / "strings.txt"
    extract_strings(exe_path, strings_file)

    # Save metadata
    metadata_file = output_dir / "metadata.txt"
    with open(metadata_file, 'w') as f:
        f.write(f"PE Analysis: {exe_path.name}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"File: {exe_path}\n")
        f.write(f"Size: {exe_path.stat().st_size} bytes\n")
        f.write(f"MD5: {calculate_md5(exe_path.read_bytes())}\n")
        f.write(f"PE Type: {'PE32+' if pe.FILE_HEADER.Machine == 0x8664 else 'PE32'}\n")
        f.write(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}\n")
        f.write(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n\n")

        f.write("Sections:\n")
        f.write("-" * 60 + "\n")
        for sec in results['sections']:
            f.write(f"{sec['name']:10s} | VA: {sec['virtual_address']:10s} | "
                   f"Size: {sec['raw_size']:8d} | Entropy: {sec['entropy']:.2f}\n")

    print(f"\n[✓] Extraction complete! Files saved to: {output_dir}")
    pe.close()

    return results

def extract_resources(pe, output_dir, results):
    """Extract resources from PE file"""
    def _extract_resource_data(entry, level=0, path=""):
        if hasattr(entry, 'data'):
            # This is actual resource data
            resource_name = path.strip('/').replace('/', '_')
            resource_file = output_dir / resource_name

            data = pe.get_data(entry.data.struct.OffsetToData, entry.data.struct.Size)
            with open(resource_file, 'wb') as f:
                f.write(data)

            results['resources'].append({
                'name': resource_name,
                'size': entry.data.struct.Size,
                'md5': calculate_md5(data)
            })
            print(f"  [+] {resource_name} ({entry.data.struct.Size} bytes)")

        if hasattr(entry, 'directory'):
            for res_entry in entry.directory.entries:
                if hasattr(res_entry, 'name'):
                    name = str(res_entry.name)
                elif hasattr(res_entry, 'id'):
                    name = str(res_entry.id)
                else:
                    name = "unknown"

                _extract_resource_data(res_entry, level + 1, f"{path}/{name}")

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if hasattr(entry, 'name'):
            name = str(entry.name)
        elif hasattr(entry, 'id'):
            # Common resource type IDs
            resource_types = {
                1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU',
                5: 'DIALOG', 6: 'STRING', 7: 'FONTDIR', 8: 'FONT',
                9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE',
                12: 'GROUP_CURSOR', 14: 'GROUP_ICON', 16: 'VERSION',
                24: 'MANIFEST'
            }
            name = resource_types.get(entry.id, f"TYPE_{entry.id}")
        else:
            name = "unknown"

        _extract_resource_data(entry, 0, name)

def extract_strings(exe_path, output_file, min_length=4):
    """Extract printable ASCII and Unicode strings from executable"""
    with open(exe_path, 'rb') as f:
        data = f.read()

    ascii_strings = []
    unicode_strings = []

    # Extract ASCII strings
    current_string = b""
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string += bytes([byte])
        else:
            if len(current_string) >= min_length:
                ascii_strings.append(current_string.decode('ascii'))
            current_string = b""

    # Extract Unicode strings (UTF-16 LE)
    i = 0
    current_string = ""
    while i < len(data) - 1:
        if 32 <= data[i] <= 126 and data[i + 1] == 0:
            current_string += chr(data[i])
            i += 2
        else:
            if len(current_string) >= min_length:
                unicode_strings.append(current_string)
            current_string = ""
            i += 1

    # Save to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("ASCII Strings:\n")
        f.write("=" * 60 + "\n")
        for s in ascii_strings:
            f.write(f"{s}\n")

        f.write("\n\nUnicode Strings:\n")
        f.write("=" * 60 + "\n")
        for s in unicode_strings:
            f.write(f"{s}\n")

    print(f"  [+] Found {len(ascii_strings)} ASCII strings and {len(unicode_strings)} Unicode strings")

def main():
    """Main function to process all executables in a directory"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python pe_extractor.py <exe_file>                    # Extract single file")
        print("  python pe_extractor.py <directory>                   # Extract all .exe files in directory")
        print("  python pe_extractor.py <directory> --include-dll     # Extract .exe and .dll files")
        return

    target = Path(sys.argv[1])
    include_dll = '--include-dll' in sys.argv

    if not target.exists():
        print(f"[ERROR] Target not found: {target}")
        return

    # Check if pefile is installed
    try:
        import pefile
    except ImportError:
        print("[ERROR] pefile module not found!")
        print("Install it with: pip install pefile")
        return

    executables = []

    if target.is_file():
        executables = [target]
    elif target.is_dir():
        print(f"[*] Scanning directory: {target}")
        executables.extend(target.glob("*.exe"))
        if include_dll:
            executables.extend(target.glob("*.dll"))

    if not executables:
        print("[ERROR] No executable files found!")
        return

    print(f"\n[*] Found {len(executables)} file(s) to process\n")

    for exe in executables:
        try:
            extract_pe_sections(exe)
        except Exception as e:
            print(f"[ERROR] Failed to process {exe.name}: {e}")
            import traceback
            traceback.print_exc()

    print("\n[✓] All files processed!")

if __name__ == "__main__":
    main()
