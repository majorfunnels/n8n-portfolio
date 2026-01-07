#!/usr/bin/env python3
"""
n8n Workflow Batch Sanitizer
============================
Process all workflow JSON files in a directory.

Usage:
    python n8n_sanitize_batch.py ./raw ./sanitized
    python n8n_sanitize_batch.py ./raw ./sanitized --redact-prompts

Author: JC (Passive Assets)
"""

import argparse
import json
from pathlib import Path
from datetime import datetime

# Import from the main sanitization script
from n8n_sanitize import WorkflowSanitizer, SanitizationReport


def process_directory(
    input_dir: Path,
    output_dir: Path,
    redact_prompts: bool = False
) -> dict:
    """
    Process all .json files in input_dir, save sanitized versions to output_dir.
    Returns a summary report.
    """
    # Find all JSON files
    json_files = list(input_dir.glob('*.json'))
    
    if not json_files:
        print(f"⚠️  No .json files found in {input_dir}")
        return {'files_processed': 0}
    
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Track results
    results = {
        'timestamp': datetime.now().isoformat(),
        'input_dir': str(input_dir),
        'output_dir': str(output_dir),
        'redact_prompts': redact_prompts,
        'files_processed': 0,
        'files_failed': 0,
        'total_redactions': 0,
        'files': []
    }
    
    print(f"\n📂 Processing {len(json_files)} workflow(s)...\n")
    
    for json_file in sorted(json_files):
        file_result = {
            'name': json_file.name,
            'status': 'unknown',
            'redactions': 0,
            'warnings': 0
        }
        
        try:
            # Load
            with open(json_file, 'r', encoding='utf-8') as f:
                workflow = json.load(f)
            
            # Skip if not a workflow (check for nodes key)
            if 'nodes' not in workflow:
                print(f"  ⏭️  {json_file.name} - skipped (not a workflow)")
                file_result['status'] = 'skipped'
                file_result['reason'] = 'not a workflow'
                results['files'].append(file_result)
                continue
            
            # Sanitize
            sanitizer = WorkflowSanitizer(redact_prompts=redact_prompts)
            sanitized = sanitizer.sanitize(workflow)
            
            # Write
            output_path = output_dir / json_file.name
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(sanitized, f, indent=2, ensure_ascii=False)
            
            # Track stats
            redaction_count = len(sanitizer.report.redactions)
            warning_count = len(sanitizer.report.warnings)
            
            file_result['status'] = 'success'
            file_result['redactions'] = redaction_count
            file_result['warnings'] = warning_count
            
            results['files_processed'] += 1
            results['total_redactions'] += redaction_count
            
            status_icon = '✅' if warning_count == 0 else '⚠️'
            print(f"  {status_icon} {json_file.name} - {redaction_count} redaction(s)")
            
            if warning_count > 0:
                print(f"      └─ {warning_count} warning(s)")
            
        except json.JSONDecodeError as e:
            print(f"  ❌ {json_file.name} - invalid JSON: {e}")
            file_result['status'] = 'failed'
            file_result['error'] = str(e)
            results['files_failed'] += 1
            
        except Exception as e:
            print(f"  ❌ {json_file.name} - error: {e}")
            file_result['status'] = 'failed'
            file_result['error'] = str(e)
            results['files_failed'] += 1
        
        results['files'].append(file_result)
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description='Batch sanitize n8n workflow JSON files'
    )
    
    parser.add_argument(
        'input_dir',
        type=Path,
        help='Directory containing raw workflow JSON files'
    )
    parser.add_argument(
        'output_dir',
        type=Path,
        help='Directory for sanitized output files'
    )
    parser.add_argument(
        '--redact-prompts', '-p',
        action='store_true',
        help='Also redact AI prompt content'
    )
    parser.add_argument(
        '--report-file',
        type=Path,
        help='Save batch report to JSON file'
    )
    
    args = parser.parse_args()
    
    # Validate input
    if not args.input_dir.exists():
        print(f"❌ Error: Input directory not found: {args.input_dir}")
        return 1
    
    if not args.input_dir.is_dir():
        print(f"❌ Error: Input path is not a directory: {args.input_dir}")
        return 1
    
    # Process
    results = process_directory(
        args.input_dir,
        args.output_dir,
        args.redact_prompts
    )
    
    # Summary
    print(f"\n{'='*50}")
    print("BATCH SUMMARY")
    print(f"{'='*50}")
    print(f"  Files processed: {results['files_processed']}")
    print(f"  Files failed:    {results['files_failed']}")
    print(f"  Total redactions: {results['total_redactions']}")
    print(f"{'='*50}\n")
    
    # Save report
    if args.report_file:
        with open(args.report_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(f"📄 Batch report saved to: {args.report_file}")
    
    return 0 if results['files_failed'] == 0 else 1


if __name__ == '__main__':
    exit(main())
