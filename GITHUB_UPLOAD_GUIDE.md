# GitHub Upload Guide

## ⚠️ IMPORTANT DISCLAIMER - EDUCATIONAL USE ONLY

**This repository is for EDUCATIONAL and RESEARCH purposes ONLY.**

Before uploading, ensure you:
- Have permission to analyze and share any included software
- Understand this is for learning, not exploitation
- Will comply with all applicable laws and regulations
- Accept full responsibility for the content you upload

---

## Prerequisites

1. **Git installed** on your system
   - Download from: https://git-scm.com/downloads
   - Verify installation: `git --version`

2. **GitHub account**
   - Create account at: https://github.com
   - Verify your email address

3. **Git configured** (first time only)
   ```bash
   git config --global user.name "Your Name"
   git config --global user.email "your.email@example.com"
   ```

---

## Step-by-Step Upload Instructions

### Method 1: Using Command Line (Recommended)

#### Step 1: Navigate to Your Project Folder

Open PowerShell or Command Prompt and navigate to your project:

```powershell
cd "E:\MMORPG\Decompile\Organized"
```

#### Step 2: Initialize Git Repository (First Time Only)

```bash
git init
```

This creates a `.git` folder in your project directory.

#### Step 3: Create .gitignore (Already Created)

The `.gitignore` file has already been created for you. It excludes:
- Binary files (.exe, .dll, .gbf, etc.)
- Ghidra project files
- Temporary files
- OS-specific files

**Verify it exists:**
```bash
dir .gitignore
```

#### Step 4: Add Files to Git

Add all files that should be tracked (respects .gitignore):

```bash
git add .
```

To see what will be added (dry run):
```bash
git status
```

#### Step 5: Create Initial Commit

```bash
git commit -m "Initial commit: PE Analysis Toolkit for educational purposes"
```

#### Step 6: Create Repository on GitHub

1. Go to https://github.com/new
2. **Repository name**: Choose a name (e.g., `pe-analysis-toolkit` or `reverse-engineering-notes`)
3. **Description**: "Educational reverse engineering and PE analysis toolkit"
4. **Visibility**: 
   - **Public**: Anyone can see it (recommended for educational repos)
   - **Private**: Only you (and collaborators) can see it
5. **DO NOT** check "Initialize with README" (you already have one)
6. Click **"Create repository"**

#### Step 7: Connect Local Repository to GitHub

After creating the repository, GitHub will show you commands. Use the ones that look like this:

```bash
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
```

Replace `YOUR_USERNAME` and `YOUR_REPO_NAME` with your actual values.

**Example:**
```bash
git remote add origin https://github.com/yourusername/pe-analysis-toolkit.git
```

#### Step 8: Push to GitHub

```bash
git branch -M main
git push -u origin main
```

You'll be prompted for your GitHub username and password (or use a Personal Access Token).

**If using GitHub CLI:**
```bash
gh auth login
git push -u origin main
```

#### Step 9: Verify Upload

1. Go to your repository page on GitHub
2. You should see all your files
3. Verify that binary files (.exe, .dll, .gbf) are **NOT** uploaded (thanks to .gitignore)

---

### Method 2: Using GitHub Desktop (GUI Method)

#### Step 1: Install GitHub Desktop

1. Download from: https://desktop.github.com/
2. Install and sign in with your GitHub account

#### Step 2: Add Local Repository

1. Open GitHub Desktop
2. Click **File → Add Local Repository**
3. Browse to: `E:\MMORPG\Decompile\Organized`
4. Click **Add Repository**

#### Step 3: Review Changes

GitHub Desktop will show:
- Files to be committed (documentation, scripts)
- Files ignored (.gitignore exclusions)

#### Step 4: Create Initial Commit

1. Enter commit message: "Initial commit: PE Analysis Toolkit for educational purposes"
2. Click **"Commit to main"**

#### Step 5: Publish to GitHub

1. Click **"Publish repository"** button
2. **Repository name**: Choose a name
3. **Description**: "Educational reverse engineering and PE analysis toolkit"
4. **Keep this code private**: Choose based on your preference
5. Click **"Publish Repository"**

---

## Verifying What Was Uploaded

After uploading, verify that:

✅ **Included (should be uploaded):**
- README.md
- ANALYSIS_GUIDE.md
- BGSTART_ANALYSIS.md
- QUICKSTART.md
- COMPLETE_FILE_INVENTORY.md
- START_HERE.txt
- .gitignore
- pe_extractor.py
- ghidra_project_copier.py
- GITHUB_UPLOAD_GUIDE.md (this file)

❌ **Excluded (should NOT be uploaded):**
- ACTIVTRAK_ATTACK.rep/ folder (contains .gbf, .prp files)
- Any .exe, .dll files
- Binary analysis outputs
- Temporary files

---

## Updating Repository (Making Changes)

After making changes to your files:

```bash
# Navigate to your project folder
cd "E:\MMORPG\Decompile\Organized"

# See what changed
git status

# Add changes
git add .

# Commit changes
git commit -m "Updated documentation with new findings"

# Push to GitHub
git push
```

---

## Troubleshooting

### Issue: "Permission denied" when pushing

**Solution 1: Use Personal Access Token**
1. Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token with `repo` scope
3. Use token as password when pushing

**Solution 2: Use SSH**
```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "your.email@example.com"

# Add to GitHub: Settings → SSH and GPG keys → New SSH key
# Then change remote URL:
git remote set-url origin git@github.com:USERNAME/REPO.git
```

### Issue: "Repository not found" or "fatal: remote origin already exists"

**Solution:**
```bash
# Check current remote
git remote -v

# Remove existing remote
git remote remove origin

# Add correct remote
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
```

### Issue: "Large files" error (if binaries were accidentally added)

**Solution:**
```bash
# Remove from git tracking (but keep local file)
git rm --cached path/to/file.exe

# Commit the removal
git commit -m "Remove binary files"

# Push
git push
```

### Issue: Want to upload but exclude specific files

**Solution:** Add to `.gitignore`:
```bash
# Edit .gitignore and add:
path/to/exclude/
specific-file.txt
*.extension
```

Then:
```bash
git rm --cached path/to/exclude/ -r
git commit -m "Update .gitignore"
git push
```

---

## Recommended Repository Settings

After creating your repository:

1. **Add Topics/Tags** (Repository → ⚙️ Settings → Topics):
   - `reverse-engineering`
   - `educational`
   - `pe-analysis`
   - `ghidra`
   - `security-research`

2. **Add Repository Description:**
   "Educational PE analysis and reverse engineering toolkit. For learning purposes only."

3. **Enable Issues** (if you want feedback):
   - Settings → General → Features → Issues ✓

4. **Add License** (Optional but recommended):
   - Create file: `LICENSE` (choose appropriate license like MIT, Apache 2.0, or Unlicense)

---

## Security Considerations

⚠️ **Before Uploading:**

1. **Review all files** - Make sure no sensitive information is included:
   - API keys
   - Passwords
   - Personal information
   - Proprietary code you don't own

2. **Check .gitignore** - Verify it's excluding:
   - Binary executables
   - Large project files
   - Temporary files

3. **Repository Visibility:**
   - **Public**: Anyone can see and clone
   - **Private**: Only you and collaborators

4. **Consider adding a LICENSE file** specifying:
   - Educational use only
   - No warranty
   - User responsibility

---

## Quick Command Reference

```bash
# Initialize repository
git init

# Check status
git status

# Add all files (respects .gitignore)
git add .

# Commit changes
git commit -m "Your commit message"

# Add remote repository
git remote add origin https://github.com/USERNAME/REPO.git

# Push to GitHub
git push -u origin main

# Pull latest changes
git pull

# See commit history
git log

# Create new branch
git checkout -b new-branch-name

# Switch branches
git checkout main
```

---

## Next Steps After Uploading

1. ✅ Verify all files are uploaded correctly
2. ✅ Check that binary files are excluded
3. ✅ Review repository README is visible
4. ✅ Consider adding a LICENSE file
5. ✅ Update repository description and topics
6. ✅ Share your repository (if public) for educational purposes

---

## Need Help?

- **Git Documentation**: https://git-scm.com/doc
- **GitHub Help**: https://docs.github.com
- **GitHub Desktop Guide**: https://docs.github.com/en/desktop

---

**Remember: This repository is for EDUCATIONAL purposes ONLY. Use responsibly and ethically!**

