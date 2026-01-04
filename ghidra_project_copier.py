#!/usr/bin/env python3
"""
Ghidra Project File Copier
Copies readable/useful files from Ghidra project to a consolidated location
"""

import os
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
import json

def copy_ghidra_project(source_repo, destination_base):
    """
    Copy Ghidra project files to a new organized location

    Args:
        source_repo: Path to .rep directory (e.g., ACTIVTRAK_ATTACK.rep)
        destination_base: Where to copy files to
    """
    source_repo = Path(source_repo)
    destination_base = Path(destination_base)

    if not source_repo.exists():
        print(f"[ERROR] Source repository not found: {source_repo}")
        return

    # Create destination directories
    dest_project = destination_base / source_repo.name
    dest_programs = dest_project / "programs"
    dest_metadata = dest_project / "metadata"

    dest_project.mkdir(parents=True, exist_ok=True)
    dest_programs.mkdir(exist_ok=True)
    dest_metadata.mkdir(exist_ok=True)

    print(f"[*] Copying Ghidra project: {source_repo.name}")
    print(f"[*] Destination: {dest_project}")
    print()

    # Copy project files
    project_files = [
        source_repo / "project.prp",
        source_repo / "projectState"
    ]

    print("[*] Copying project configuration files...")
    for file in project_files:
        if file.exists():
            shutil.copy2(file, dest_project / file.name)
            print(f"  [+] {file.name}")

    # Extract program information and organize
    print("\n[*] Extracting program information...")

    programs = {}
    idata_path = source_repo / "idata"

    # Find all .prp files and extract program names
    for root, dirs, files in os.walk(idata_path):
        for file in files:
            if file.endswith('.prp'):
                filepath = Path(root) / file
                try:
                    tree = ET.parse(filepath)
                    root_elem = tree.getroot()

                    # Extract program name
                    name_elem = root_elem.find('.//STATE[@NAME="NAME"]')
                    if name_elem is not None:
                        prog_name = name_elem.get('VALUE')
                        if prog_name and prog_name != 'chris':  # Filter out owner name

                            # Extract other metadata
                            file_id_elem = root_elem.find('.//STATE[@NAME="FILE_ID"]')
                            content_type_elem = root_elem.find('.//STATE[@NAME="CONTENT_TYPE"]')

                            file_id = file_id_elem.get('VALUE') if file_id_elem is not None else 'unknown'
                            content_type = content_type_elem.get('VALUE') if content_type_elem is not None else 'unknown'

                            if prog_name not in programs:
                                programs[prog_name] = {
                                    'name': prog_name,
                                    'file_id': file_id,
                                    'type': content_type,
                                    'prp_file': filepath,
                                    'db_folder': filepath.parent / f"~{filepath.stem}.db"
                                }
                except Exception as e:
                    pass

    # Remove duplicate versions (keep base names only)
    unique_programs = {}
    for prog_name, info in programs.items():
        # Get base name (remove .0, .1, etc.)
        base_name = prog_name.split('.')[0] + '.' + prog_name.split('.')[1] if '.' in prog_name else prog_name
        if base_name.endswith('.exe') or base_name.endswith('.dll'):
            if base_name not in unique_programs:
                unique_programs[base_name] = info

    print(f"  [+] Found {len(unique_programs)} unique programs")

    # Create program index
    program_list = []
    for prog_name, info in sorted(unique_programs.items()):
        program_list.append({
            'name': prog_name,
            'type': info['type'],
            'file_id': info['file_id']
        })
        print(f"    - {prog_name}")

    # Save program list
    index_file = dest_metadata / "program_index.json"
    with open(index_file, 'w') as f:
        json.dump(program_list, f, indent=2)
    print(f"\n[+] Program index saved to: {index_file}")

    # Copy metadata files
    print("\n[*] Copying metadata files...")
    for prog_name, info in unique_programs.items():
        # Copy .prp file
        dest_prp = dest_metadata / f"{prog_name}.prp"
        shutil.copy2(info['prp_file'], dest_prp)
        print(f"  [+] {prog_name}.prp")

    # Copy important database files (.gbf files contain analysis data)
    print("\n[*] Copying analysis database files...")

    copied_count = 0
    total_size = 0

    for prog_name, info in unique_programs.items():
        db_folder = info['db_folder']
        if db_folder.exists():
            # Create destination for this program's database
            prog_safe_name = prog_name.replace('/', '_').replace('\\', '_')
            dest_db = dest_programs / prog_safe_name
            dest_db.mkdir(exist_ok=True)

            # Copy all .gbf files (Ghidra binary format - contains analysis)
            for gbf_file in db_folder.glob("*.gbf"):
                dest_file = dest_db / gbf_file.name
                shutil.copy2(gbf_file, dest_file)
                copied_count += 1
                total_size += gbf_file.stat().st_size

            # Copy changesets and other important files
            for ext in ['*.grf', '*.prp', '*.crf']:
                for file in db_folder.glob(ext):
                    dest_file = dest_db / file.name
                    shutil.copy2(file, dest_file)
                    copied_count += 1
                    total_size += file.stat().st_size

            print(f"  [+] {prog_name} - {len(list(dest_db.iterdir()))} files")

    print(f"\n[+] Copied {copied_count} database files ({total_size / (1024*1024):.1f} MB)")

    # Create README
    readme_content = f"""# Ghidra Project Export: {source_repo.name}

## Contents

This folder contains exported data from the Ghidra project.

### Structure

- `programs/` - Analysis database files for each program
- `metadata/` - Program metadata and configuration files
- `project.prp` - Main project configuration
- `projectState` - Project state information
- `program_index.json` - List of all analyzed programs

### Programs Analyzed ({len(unique_programs)})

"""
    for prog_name in sorted(unique_programs.keys()):
        readme_content += f"- {prog_name}\n"

    readme_content += f"""

### File Types

- `.prp` - XML property files (human-readable metadata)
- `.gbf` - Ghidra Binary Format (contains decompiled code, analysis, functions)
- `.grf` - Ghidra Resource Files
- `.crf` - Change/Revision Files

### How to Use

1. **To restore in Ghidra:**
   - Copy the entire `{source_repo.name}` folder back to Ghidra's repository location
   - Open Ghidra and import the project

2. **To read with AI/tools:**
   - `.prp` files are XML and can be read directly
   - `.gbf` files require Ghidra or custom parser
   - `program_index.json` lists all programs

3. **To analyze elsewhere:**
   - Export folder is {total_size / (1024*1024*1024):.2f} GB
   - Can be copied to another drive or machine
   - Self-contained with all analysis data

### Original Location

Source: {source_repo.absolute()}
Exported: {dest_project.absolute()}

### Notes

This export contains all Ghidra analysis data including:
- Decompiled functions
- Renamed functions and variables
- Comments and bookmarks
- Cross-references
- Data type information
"""

    readme_file = dest_project / "README.md"
    with open(readme_file, 'w') as f:
        f.write(readme_content)

    print(f"\n[✓] Export complete!")
    print(f"[✓] Location: {dest_project}")
    print(f"[✓] Total size: {total_size / (1024*1024*1024):.2f} GB")
    print(f"[✓] Programs: {len(unique_programs)}")
    print(f"\nYou can now copy this folder to another drive:")
    print(f"  {dest_project}")

def main():
    """Main function"""
    import sys

    print("=" * 70)
    print("Ghidra Project File Copier")
    print("=" * 70)
    print()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python ghidra_project_copier.py <ghidra_repo_path> [destination]")
        print()
        print("Example:")
        print('  python ghidra_project_copier.py "E:\\MMORPG\\Decompile\\ACTIVTRAK DECOMPILED\\ACTIVTRAK_ATTACK.rep"')
        print('  python ghidra_project_copier.py "E:\\MMORPG\\Decompile\\ACTIVTRAK DECOMPILED\\ACTIVTRAK_ATTACK.rep" "D:\\Backup"')
        print()

        # Auto-detect if run from decompile folder
        default_repo = Path(r"E:\MMORPG\Decompile\ACTIVTRAK DECOMPILED\ACTIVTRAK_ATTACK.rep")
        if default_repo.exists():
            print(f"Found Ghidra project at: {default_repo}")
            response = input("Use this project? (y/n): ")
            if response.lower() == 'y':
                dest = input("Enter destination folder (or press Enter for current directory): ").strip()
                if not dest:
                    dest = Path.cwd()
                copy_ghidra_project(default_repo, dest)
                return
        return

    source_repo = sys.argv[1]
    destination = sys.argv[2] if len(sys.argv) > 2 else Path.cwd()

    copy_ghidra_project(source_repo, destination)

if __name__ == "__main__":
    main()
