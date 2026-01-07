#!/usr/bin/env python3
"""
Git Pre-Commit Hook: n8n Workflow Sanitization Check
=====================================================
Scans staged JSON files for potential credential leaks.
Install by copying to .git/hooks/pre-commit and making executable.

Usage:
    cp pre-commit-hook.py .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
"""

import json
import re
import subprocess
import sys
from pathlib import Path


# Patterns that indicate unsanitized content
DANGER_PATTERNS = [
    # Real Airtable IDs (not redacted placeholders)
    (re.compile(r'app[A-Za-z0-9]{14,17}(?!REDACTED)'), 'Airtable Base ID'),
    (re.compile(r'tbl[A-Za-z0-9]{14,17}(?!REDACTED)'), 'Airtable Table ID'),
    
    # Real API keys
    (re.compile(r'sk-or-v1-[A-Za-z0-9]{64}'), 'OpenRouter API Key'),
    (re.compile(r'sk-[A-Za-z0-9]{48,}(?!REDACTED)'), 'OpenAI API Key'),
    (re.compile(r'sk-ant-[A-Za-z0-9]{40,}'), 'Anthropic API Key'),
    (re.compile(r'pplx-[A-Za-z0-9]{48,}'), 'Perplexity API Key'),
    
    # Real UUIDs in webhook context (not the placeholder zeros)
    (re.compile(r'"webhookId"\s*:\s*"[0-9a-f]{8}-[0-9a-f]{4}-(?!0000)[0-9a-f]{4}'), 'Webhook ID'),
    
    # Google Drive IDs (long alphanumeric strings)
    (re.compile(r'"folderId"\s*:\s*"[A-Za-z0-9_-]{25,}(?!REDACTED)'), 'Google Drive Folder ID'),
    
    # Email addresses (not the placeholder)
    (re.compile(r'[a-zA-Z0-9._%+-]+@(?!example\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), 'Email Address'),
    
    # Bearer tokens
    (re.compile(r'Bearer\s+[A-Za-z0-9_-]{20,}(?!REDACTED)'), 'Bearer Token'),
    
    # Credential blocks with real IDs
    (re.compile(r'"credentials"\s*:\s*\{[^}]*"id"\s*:\s*"(?!REDACTED)[A-Za-z0-9]'), 'Credential ID'),
]

# Files/paths to always ignore
IGNORE_PATTERNS = [
    re.compile(r'\.git/'),
    re.compile(r'node_modules/'),
    re.compile(r'__pycache__/'),
    re.compile(r'\.pyc$'),
]


def get_staged_files() -> list[str]:
    """Get list of staged files from git."""
    result = subprocess.run(
        ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR'],
        capture_output=True,
        text=True
    )
    return result.stdout.strip().split('\n') if result.stdout.strip() else []


def should_check_file(filepath: str) -> bool:
    """Determine if a file should be checked."""
    # Must be JSON
    if not filepath.endswith('.json'):
        return False
    
    # Check ignore patterns
    for pattern in IGNORE_PATTERNS:
        if pattern.search(filepath):
            return False
    
    return True


def check_file_for_secrets(filepath: str) -> list[tuple[str, str, int]]:
    """
    Check a file for potential secrets.
    Returns list of (pattern_name, matched_text, line_number) tuples.
    """
    issues = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.split('\n')
    except (IOError, UnicodeDecodeError):
        return issues
    
    # Try to parse as JSON to verify it's a workflow
    try:
        data = json.loads(content)
        # Skip if it doesn't look like an n8n workflow
        if 'nodes' not in data:
            return issues
    except json.JSONDecodeError:
        return issues
    
    # Check each line for patterns
    for line_num, line in enumerate(lines, 1):
        for pattern, pattern_name in DANGER_PATTERNS:
            matches = pattern.findall(line)
            for match in matches:
                # Truncate match for display
                display_match = match[:30] + '...' if len(match) > 30 else match
                issues.append((pattern_name, display_match, line_num))
    
    return issues


def main() -> int:
    """Main entry point."""
    staged_files = get_staged_files()
    files_to_check = [f for f in staged_files if should_check_file(f)]
    
    if not files_to_check:
        return 0
    
    all_issues = []
    
    for filepath in files_to_check:
        if not Path(filepath).exists():
            continue
        
        issues = check_file_for_secrets(filepath)
        if issues:
            all_issues.append((filepath, issues))
    
    if all_issues:
        print("\n" + "=" * 70)
        print("🚨 POTENTIAL CREDENTIALS DETECTED IN STAGED WORKFLOWS")
        print("=" * 70)
        
        for filepath, issues in all_issues:
            print(f"\n📄 {filepath}")
            for pattern_name, matched_text, line_num in issues:
                print(f"   Line {line_num}: {pattern_name}")
                print(f"            └─ {matched_text}")
        
        print("\n" + "-" * 70)
        print("ACTION REQUIRED:")
        print("  1. Run the sanitization script on these files:")
        print("     python scripts/n8n_sanitize.py <file> <output>")
        print("  2. Stage the sanitized versions instead")
        print("  3. Or use --no-verify to bypass (not recommended)")
        print("-" * 70 + "\n")
        
        return 1
    
    print("✅ Workflow files passed credential check")
    return 0


if __name__ == '__main__':
    sys.exit(main())
