#!/usr/bin/env python3
"""
n8n Workflow Sanitization Script
================================
Sanitizes n8n workflow JSON exports for safe publication to GitHub.

Removes/redacts:
- Credentials (IDs and references)
- Webhook URLs and IDs
- Airtable base/table IDs
- Google Drive folder IDs
- API endpoints and URLs containing identifiers
- Hardcoded test data in fixture nodes
- Optionally: AI prompt content (for IP protection)

Usage:
    python n8n_sanitize.py input.json output.json
    python n8n_sanitize.py input.json output.json --redact-prompts
    python n8n_sanitize.py input.json output.json --report

Author: JC (Passive Assets)
"""

import json
import re
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Any
from copy import deepcopy


# =============================================================================
# CONFIGURATION
# =============================================================================

class SanitizationConfig:
    """Central configuration for sanitization patterns and replacements."""
    
    # Airtable patterns
    AIRTABLE_BASE_PATTERN = re.compile(r'app[A-Za-z0-9]{14,17}')
    AIRTABLE_TABLE_PATTERN = re.compile(r'tbl[A-Za-z0-9]{14,17}')
    AIRTABLE_VIEW_PATTERN = re.compile(r'viw[A-Za-z0-9]{14,17}')
    AIRTABLE_RECORD_PATTERN = re.compile(r'rec[A-Za-z0-9]{14,17}')
    AIRTABLE_FIELD_PATTERN = re.compile(r'fld[A-Za-z0-9]{14,17}')
    
    # Google patterns
    GDRIVE_FOLDER_PATTERN = re.compile(r'(?<=/folders/)[A-Za-z0-9_-]{25,45}')
    GDRIVE_FILE_PATTERN = re.compile(r'(?<=/d/)[A-Za-z0-9_-]{25,45}')
    GSHEET_ID_PATTERN = re.compile(r'(?<=spreadsheets/d/)[A-Za-z0-9_-]{25,45}')
    
    # Webhook patterns
    WEBHOOK_UUID_PATTERN = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        re.IGNORECASE
    )
    WEBHOOK_PATH_PATTERN = re.compile(r'/webhook[s]?/[A-Za-z0-9_-]+')
    
    # Generic API key patterns
    API_KEY_PATTERN = re.compile(
        r'(?:api[_-]?key|apikey|secret|token|password|auth)["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,})',
        re.IGNORECASE
    )
    
    # Bearer tokens
    BEARER_PATTERN = re.compile(r'Bearer\s+[A-Za-z0-9_-]{20,}', re.IGNORECASE)
    
    # OpenRouter / OpenAI patterns
    OPENROUTER_KEY_PATTERN = re.compile(r'sk-or-v1-[A-Za-z0-9]{64}')
    OPENAI_KEY_PATTERN = re.compile(r'sk-[A-Za-z0-9]{48,}')
    
    # Anthropic patterns
    ANTHROPIC_KEY_PATTERN = re.compile(r'sk-ant-[A-Za-z0-9_-]{40,}')
    
    # Perplexity patterns
    PERPLEXITY_KEY_PATTERN = re.compile(r'pplx-[A-Za-z0-9]{48,}')
    
    # YouTube patterns
    YOUTUBE_VIDEO_ID_PATTERN = re.compile(r'(?:v=|youtu\.be/|/v/|/embed/)([A-Za-z0-9_-]{11})')
    YOUTUBE_CHANNEL_ID_PATTERN = re.compile(r'UC[A-Za-z0-9_-]{22}')
    
    # Email patterns
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    
    # Replacement values
    REPLACEMENTS = {
        'airtable_base': 'appXXXXXXXXXXXXXXX',
        'airtable_table': 'tblXXXXXXXXXXXXXXX',
        'airtable_view': 'viwXXXXXXXXXXXXXXX',
        'airtable_record': 'recXXXXXXXXXXXXXXX',
        'airtable_field': 'fldXXXXXXXXXXXXXXX',
        'gdrive_folder': 'XXXXXXXXXXXXXXXXXXXXXXXXX',
        'gdrive_file': 'XXXXXXXXXXXXXXXXXXXXXXXXX',
        'webhook_id': '00000000-0000-0000-0000-000000000000',
        'webhook_path': '/webhook/REDACTED',
        'api_key': 'REDACTED_API_KEY',
        'bearer_token': 'Bearer REDACTED_TOKEN',
        'openrouter_key': 'sk-or-v1-REDACTED',
        'openai_key': 'sk-REDACTED',
        'anthropic_key': 'sk-ant-REDACTED',
        'perplexity_key': 'pplx-REDACTED',
        'youtube_video': 'xxxxxxxxxxx',
        'youtube_channel': 'UCxxxxxxxxxxxxxxxxxxxxxx',
        'email': 'redacted@example.com',
        'credential_id': 'REDACTED_CREDENTIAL_ID',
    }
    
    # Node types that typically contain sensitive prompts
    AI_PROMPT_NODE_TYPES = [
        'n8n-nodes-base.openAi',
        '@n8n/n8n-nodes-langchain.openAi',
        '@n8n/n8n-nodes-langchain.lmChatOpenAi',
        '@n8n/n8n-nodes-langchain.lmChatAnthropic',
        '@n8n/n8n-nodes-langchain.agent',
        '@n8n/n8n-nodes-langchain.chainLlm',
        'n8n-nodes-base.httpRequest',  # When used for AI APIs
    ]
    
    # Fields that typically contain prompts
    PROMPT_FIELDS = [
        'prompt',
        'systemMessage',
        'userMessage',
        'text',
        'messages',
        'content',
        'instructions',
    ]
    
    # Node names that suggest fixture/test data
    FIXTURE_NODE_PATTERNS = [
        re.compile(r'fixture', re.IGNORECASE),
        re.compile(r'test[-_\s]?data', re.IGNORECASE),
        re.compile(r'mock[-_\s]?data', re.IGNORECASE),
        re.compile(r'sample[-_\s]?data', re.IGNORECASE),
        re.compile(r'debug', re.IGNORECASE),
    ]


# =============================================================================
# SANITIZATION REPORT
# =============================================================================

class SanitizationReport:
    """Tracks what was sanitized for transparency."""
    
    def __init__(self):
        self.redactions = []
        self.warnings = []
        self.stats = {
            'credentials_removed': 0,
            'webhooks_redacted': 0,
            'airtable_ids_redacted': 0,
            'gdrive_ids_redacted': 0,
            'api_keys_redacted': 0,
            'emails_redacted': 0,
            'prompts_redacted': 0,
            'fixture_nodes_cleared': 0,
            'youtube_ids_redacted': 0,
        }
    
    def add_redaction(self, location: str, redaction_type: str, original_preview: str = None):
        """Log a redaction."""
        entry = {
            'location': location,
            'type': redaction_type,
            'timestamp': datetime.now().isoformat(),
        }
        if original_preview:
            # Only show first/last few chars for verification
            if len(original_preview) > 10:
                entry['preview'] = f"{original_preview[:4]}...{original_preview[-4:]}"
            else:
                entry['preview'] = '[short value]'
        self.redactions.append(entry)
        
        # Update stats
        stat_key = f"{redaction_type}s_redacted".replace('_id', '_ids')
        if stat_key in self.stats:
            self.stats[stat_key] += 1
    
    def add_warning(self, message: str):
        """Log a warning for manual review."""
        self.warnings.append(message)
    
    def to_dict(self) -> dict:
        """Export report as dictionary."""
        return {
            'generated_at': datetime.now().isoformat(),
            'stats': self.stats,
            'warnings': self.warnings,
            'redactions': self.redactions,
        }
    
    def print_summary(self):
        """Print human-readable summary."""
        print("\n" + "=" * 60)
        print("SANITIZATION REPORT")
        print("=" * 60)
        
        print("\nStatistics:")
        for key, value in self.stats.items():
            if value > 0:
                print(f"  • {key.replace('_', ' ').title()}: {value}")
        
        if self.warnings:
            print(f"\n⚠️  Warnings ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  • {warning}")
        
        print("\n" + "=" * 60)


# =============================================================================
# SANITIZATION ENGINE
# =============================================================================

class WorkflowSanitizer:
    """Main sanitization engine."""
    
    def __init__(self, config: SanitizationConfig = None, redact_prompts: bool = False):
        self.config = config or SanitizationConfig()
        self.redact_prompts = redact_prompts
        self.report = SanitizationReport()
        
        # Track unique IDs for consistent replacement
        self._id_map = {}
    
    def _get_consistent_replacement(self, original: str, replacement_type: str) -> str:
        """
        Generate consistent replacement for the same original value.
        This ensures the same ID gets the same replacement throughout.
        """
        cache_key = f"{replacement_type}:{original}"
        
        if cache_key not in self._id_map:
            base_replacement = self.config.REPLACEMENTS.get(replacement_type, 'REDACTED')
            
            # For certain types, add a hash suffix for uniqueness while maintaining consistency
            if replacement_type in ['airtable_base', 'airtable_table', 'gdrive_folder']:
                hash_suffix = hashlib.md5(original.encode()).hexdigest()[:6].upper()
                if replacement_type == 'airtable_base':
                    self._id_map[cache_key] = f"appREDACTED{hash_suffix}"
                elif replacement_type == 'airtable_table':
                    self._id_map[cache_key] = f"tblREDACTED{hash_suffix}"
                elif replacement_type == 'gdrive_folder':
                    self._id_map[cache_key] = f"REDACTED_FOLDER_{hash_suffix}"
                else:
                    self._id_map[cache_key] = base_replacement
            else:
                self._id_map[cache_key] = base_replacement
        
        return self._id_map[cache_key]
    
    def sanitize(self, workflow: dict) -> dict:
        """
        Main entry point: sanitize an entire workflow.
        Returns a deep copy with all sensitive data redacted.
        """
        sanitized = deepcopy(workflow)
        
        # Process nodes
        if 'nodes' in sanitized:
            sanitized['nodes'] = [
                self._sanitize_node(node) for node in sanitized['nodes']
            ]
        
        # Process workflow-level settings
        if 'settings' in sanitized:
            sanitized['settings'] = self._sanitize_settings(sanitized['settings'])
        
        # Remove workflow-level credentials if present
        if 'credentials' in sanitized:
            self.report.stats['credentials_removed'] += len(sanitized.get('credentials', {}))
            sanitized['credentials'] = {}
        
        # Sanitize any pinned data
        if 'pinData' in sanitized:
            sanitized['pinData'] = self._sanitize_pinned_data(sanitized['pinData'])
        
        # Add sanitization metadata
        sanitized['_sanitized'] = {
            'timestamp': datetime.now().isoformat(),
            'tool': 'n8n_sanitize.py',
            'prompts_redacted': self.redact_prompts,
        }
        
        return sanitized
    
    def _sanitize_node(self, node: dict) -> dict:
        """Sanitize a single node."""
        node_name = node.get('name', 'Unknown')
        node_type = node.get('type', '')
        
        # Handle credentials
        if 'credentials' in node:
            for cred_type, cred_data in node['credentials'].items():
                if isinstance(cred_data, dict) and 'id' in cred_data:
                    original_id = cred_data['id']
                    cred_data['id'] = self._get_consistent_replacement(
                        original_id, 'credential_id'
                    )
                    self.report.add_redaction(
                        f"nodes['{node_name}'].credentials.{cred_type}.id",
                        'credential',
                        original_id
                    )
                    self.report.stats['credentials_removed'] += 1
        
        # Handle webhook nodes
        if 'webhook' in node_type.lower() or node_type == 'n8n-nodes-base.webhook':
            node = self._sanitize_webhook_node(node, node_name)
        
        # Handle Airtable nodes
        if 'airtable' in node_type.lower():
            node = self._sanitize_airtable_node(node, node_name)
        
        # Handle Google Drive nodes
        if 'drive' in node_type.lower() or 'sheets' in node_type.lower():
            node = self._sanitize_gdrive_node(node, node_name)
        
        # Handle HTTP Request nodes (may contain API keys in headers/params)
        if node_type == 'n8n-nodes-base.httpRequest':
            node = self._sanitize_http_node(node, node_name)
        
        # Handle AI/LLM nodes
        if self.redact_prompts and node_type in self.config.AI_PROMPT_NODE_TYPES:
            node = self._sanitize_ai_node(node, node_name)
        
        # Handle fixture/test nodes
        if self._is_fixture_node(node):
            node = self._sanitize_fixture_node(node, node_name)
        
        # Recursively sanitize parameters
        if 'parameters' in node:
            node['parameters'] = self._sanitize_parameters(
                node['parameters'], 
                f"nodes['{node_name}'].parameters"
            )
        
        return node
    
    def _sanitize_webhook_node(self, node: dict, node_name: str) -> dict:
        """Sanitize webhook-specific fields."""
        params = node.get('parameters', {})
        
        # Redact webhook path
        if 'path' in params:
            original = params['path']
            params['path'] = 'redacted-webhook-path'
            self.report.add_redaction(
                f"nodes['{node_name}'].parameters.path",
                'webhook',
                original
            )
        
        # Redact webhookId
        if 'webhookId' in node:
            original = node['webhookId']
            node['webhookId'] = self.config.REPLACEMENTS['webhook_id']
            self.report.add_redaction(
                f"nodes['{node_name}'].webhookId",
                'webhook',
                original
            )
        
        return node
    
    def _sanitize_airtable_node(self, node: dict, node_name: str) -> dict:
        """Sanitize Airtable-specific fields."""
        params = node.get('parameters', {})
        
        # Base ID
        if 'application' in params:
            original = params['application']
            if isinstance(original, str) and self.config.AIRTABLE_BASE_PATTERN.match(original):
                params['application'] = self._get_consistent_replacement(original, 'airtable_base')
                self.report.add_redaction(
                    f"nodes['{node_name}'].parameters.application",
                    'airtable_id',
                    original
                )
        
        # Resource locator format (newer n8n)
        if 'base' in params:
            base_val = params['base']
            if isinstance(base_val, dict) and 'value' in base_val:
                original = base_val['value']
                if isinstance(original, str) and self.config.AIRTABLE_BASE_PATTERN.match(original):
                    base_val['value'] = self._get_consistent_replacement(original, 'airtable_base')
                    self.report.add_redaction(
                        f"nodes['{node_name}'].parameters.base.value",
                        'airtable_id',
                        original
                    )
            elif isinstance(base_val, str) and self.config.AIRTABLE_BASE_PATTERN.match(base_val):
                params['base'] = self._get_consistent_replacement(base_val, 'airtable_base')
                self.report.add_redaction(
                    f"nodes['{node_name}'].parameters.base",
                    'airtable_id',
                    base_val
                )
        
        # Table ID
        if 'table' in params:
            table_val = params['table']
            if isinstance(table_val, dict) and 'value' in table_val:
                original = table_val['value']
                if isinstance(original, str) and self.config.AIRTABLE_TABLE_PATTERN.match(original):
                    table_val['value'] = self._get_consistent_replacement(original, 'airtable_table')
                    self.report.add_redaction(
                        f"nodes['{node_name}'].parameters.table.value",
                        'airtable_id',
                        original
                    )
            elif isinstance(table_val, str) and self.config.AIRTABLE_TABLE_PATTERN.match(table_val):
                params['table'] = self._get_consistent_replacement(table_val, 'airtable_table')
                self.report.add_redaction(
                    f"nodes['{node_name}'].parameters.table",
                    'airtable_id',
                    table_val
                )
        
        return node
    
    def _sanitize_gdrive_node(self, node: dict, node_name: str) -> dict:
        """Sanitize Google Drive-specific fields."""
        params = node.get('parameters', {})
        
        # Folder ID
        for field in ['folderId', 'folderToWatch', 'parents', 'driveId']:
            if field in params:
                val = params[field]
                if isinstance(val, str) and len(val) > 20:
                    params[field] = self._get_consistent_replacement(val, 'gdrive_folder')
                    self.report.add_redaction(
                        f"nodes['{node_name}'].parameters.{field}",
                        'gdrive_id',
                        val
                    )
                elif isinstance(val, dict) and 'value' in val:
                    original = val['value']
                    if isinstance(original, str) and len(original) > 20:
                        val['value'] = self._get_consistent_replacement(original, 'gdrive_folder')
                        self.report.add_redaction(
                            f"nodes['{node_name}'].parameters.{field}.value",
                            'gdrive_id',
                            original
                        )
        
        return node
    
    def _sanitize_http_node(self, node: dict, node_name: str) -> dict:
        """Sanitize HTTP Request node fields."""
        params = node.get('parameters', {})
        
        # Check headers for auth tokens
        if 'headerParameters' in params:
            headers = params['headerParameters']
            if isinstance(headers, dict) and 'parameters' in headers:
                for param in headers['parameters']:
                    if isinstance(param, dict):
                        name = param.get('name', '').lower()
                        if 'auth' in name or 'token' in name or 'key' in name:
                            if 'value' in param:
                                original = param['value']
                                param['value'] = 'REDACTED_HEADER_VALUE'
                                self.report.add_redaction(
                                    f"nodes['{node_name}'].parameters.headerParameters.{name}",
                                    'api_key',
                                    original
                                )
        
        # Check URL for embedded credentials
        if 'url' in params:
            url = params['url']
            if isinstance(url, str):
                # Redact any API keys in URL
                sanitized_url = self.config.API_KEY_PATTERN.sub(
                    r'\g<0>'.split('=')[0] + '=REDACTED' if '=' in url else 'REDACTED',
                    url
                )
                if sanitized_url != url:
                    params['url'] = sanitized_url
                    self.report.add_redaction(
                        f"nodes['{node_name}'].parameters.url",
                        'api_key',
                        '[URL with credentials]'
                    )
        
        return node
    
    def _sanitize_ai_node(self, node: dict, node_name: str) -> dict:
        """Sanitize AI/LLM node prompts (when --redact-prompts is enabled)."""
        params = node.get('parameters', {})
        
        for field in self.config.PROMPT_FIELDS:
            if field in params:
                val = params[field]
                if isinstance(val, str) and len(val) > 50:
                    params[field] = f"[PROMPT REDACTED - {len(val)} chars]"
                    self.report.add_redaction(
                        f"nodes['{node_name}'].parameters.{field}",
                        'prompt',
                        f"[{len(val)} char prompt]"
                    )
                    self.report.stats['prompts_redacted'] += 1
                elif isinstance(val, list):
                    # Handle message arrays
                    params[field] = [{"role": "system", "content": "[PROMPT REDACTED]"}]
                    self.report.add_redaction(
                        f"nodes['{node_name}'].parameters.{field}",
                        'prompt',
                        f"[{len(val)} messages]"
                    )
                    self.report.stats['prompts_redacted'] += 1
        
        # Handle options.systemMessage pattern
        if 'options' in params and isinstance(params['options'], dict):
            for field in self.config.PROMPT_FIELDS:
                if field in params['options']:
                    val = params['options'][field]
                    if isinstance(val, str) and len(val) > 50:
                        params['options'][field] = f"[PROMPT REDACTED - {len(val)} chars]"
                        self.report.add_redaction(
                            f"nodes['{node_name}'].parameters.options.{field}",
                            'prompt',
                            f"[{len(val)} char prompt]"
                        )
                        self.report.stats['prompts_redacted'] += 1
        
        return node
    
    def _is_fixture_node(self, node: dict) -> bool:
        """Check if a node appears to be a fixture/test data node."""
        node_name = node.get('name', '')
        node_type = node.get('type', '')
        
        # Check node name against fixture patterns
        for pattern in self.config.FIXTURE_NODE_PATTERNS:
            if pattern.search(node_name):
                return True
        
        # Manual trigger or set nodes with fixture-like names
        if node_type in ['n8n-nodes-base.set', 'n8n-nodes-base.manualTrigger']:
            for pattern in self.config.FIXTURE_NODE_PATTERNS:
                if pattern.search(node_name):
                    return True
        
        return False
    
    def _sanitize_fixture_node(self, node: dict, node_name: str) -> dict:
        """Clear test data from fixture nodes."""
        params = node.get('parameters', {})
        
        # Clear JSON data in Set nodes
        if 'values' in params:
            params['values'] = {"string": [{"name": "sample", "value": "REDACTED_TEST_DATA"}]}
            self.report.add_redaction(
                f"nodes['{node_name}'].parameters.values",
                'fixture',
                '[test data]'
            )
            self.report.stats['fixture_nodes_cleared'] += 1
        
        # Clear jsonOutput in newer Set nodes
        if 'jsonOutput' in params:
            params['jsonOutput'] = '{"sample": "REDACTED_TEST_DATA"}'
            self.report.add_redaction(
                f"nodes['{node_name}'].parameters.jsonOutput",
                'fixture',
                '[test data]'
            )
            self.report.stats['fixture_nodes_cleared'] += 1
        
        return node
    
    def _sanitize_parameters(self, params: Any, path: str) -> Any:
        """Recursively sanitize parameters, catching any remaining sensitive patterns."""
        if isinstance(params, dict):
            return {
                key: self._sanitize_parameters(value, f"{path}.{key}")
                for key, value in params.items()
            }
        elif isinstance(params, list):
            return [
                self._sanitize_parameters(item, f"{path}[{i}]")
                for i, item in enumerate(params)
            ]
        elif isinstance(params, str):
            return self._sanitize_string(params, path)
        else:
            return params
    
    def _sanitize_string(self, value: str, path: str) -> str:
        """Sanitize a string value for any remaining sensitive patterns."""
        original = value
        
        # Airtable IDs
        value = self.config.AIRTABLE_BASE_PATTERN.sub(
            lambda m: self._get_consistent_replacement(m.group(), 'airtable_base'), value
        )
        value = self.config.AIRTABLE_TABLE_PATTERN.sub(
            lambda m: self._get_consistent_replacement(m.group(), 'airtable_table'), value
        )
        value = self.config.AIRTABLE_VIEW_PATTERN.sub(
            lambda m: self._get_consistent_replacement(m.group(), 'airtable_view'), value
        )
        value = self.config.AIRTABLE_RECORD_PATTERN.sub(
            lambda m: self._get_consistent_replacement(m.group(), 'airtable_record'), value
        )
        
        # API Keys
        value = self.config.OPENROUTER_KEY_PATTERN.sub(
            self.config.REPLACEMENTS['openrouter_key'], value
        )
        value = self.config.OPENAI_KEY_PATTERN.sub(
            self.config.REPLACEMENTS['openai_key'], value
        )
        value = self.config.ANTHROPIC_KEY_PATTERN.sub(
            self.config.REPLACEMENTS['anthropic_key'], value
        )
        value = self.config.PERPLEXITY_KEY_PATTERN.sub(
            self.config.REPLACEMENTS['perplexity_key'], value
        )
        
        # Bearer tokens
        value = self.config.BEARER_PATTERN.sub(
            self.config.REPLACEMENTS['bearer_token'], value
        )
        
        # YouTube IDs (optional - uncomment if you want to redact these)
        # value = self.config.YOUTUBE_CHANNEL_ID_PATTERN.sub(
        #     self.config.REPLACEMENTS['youtube_channel'], value
        # )
        
        # Emails
        value = self.config.EMAIL_PATTERN.sub(
            self.config.REPLACEMENTS['email'], value
        )
        
        # Log if anything changed
        if value != original:
            self.report.add_redaction(path, 'pattern_match', original[:20] if len(original) > 20 else original)
        
        return value
    
    def _sanitize_settings(self, settings: dict) -> dict:
        """Sanitize workflow-level settings."""
        # Remove execution data if present
        if 'executionData' in settings:
            del settings['executionData']
        
        return settings
    
    def _sanitize_pinned_data(self, pin_data: dict) -> dict:
        """Sanitize pinned execution data."""
        # Pinned data often contains real execution results - clear it
        if pin_data:
            self.report.add_warning(
                f"Cleared pinData for {len(pin_data)} node(s) - contained execution results"
            )
            return {}
        return pin_data


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Sanitize n8n workflow JSON for safe GitHub publication',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s workflow.json sanitized.json
  %(prog)s workflow.json sanitized.json --redact-prompts
  %(prog)s workflow.json sanitized.json --report --report-file report.json
  
The script will:
  1. Remove credential IDs
  2. Redact webhook URLs and paths
  3. Replace Airtable base/table IDs with placeholders
  4. Replace Google Drive folder IDs with placeholders
  5. Redact API keys found in strings
  6. Clear fixture/test data nodes
  7. Optionally redact AI prompts (--redact-prompts)
        """
    )
    
    parser.add_argument('input', type=Path, help='Input workflow JSON file')
    parser.add_argument('output', type=Path, help='Output sanitized JSON file')
    parser.add_argument(
        '--redact-prompts', '-p',
        action='store_true',
        help='Also redact AI prompt content (protects IP)'
    )
    parser.add_argument(
        '--report', '-r',
        action='store_true',
        help='Print sanitization report to console'
    )
    parser.add_argument(
        '--report-file',
        type=Path,
        help='Save detailed report to JSON file'
    )
    parser.add_argument(
        '--pretty', 
        action='store_true',
        default=True,
        help='Pretty-print output JSON (default: True)'
    )
    parser.add_argument(
        '--compact',
        action='store_true',
        help='Output compact JSON (no indentation)'
    )
    
    args = parser.parse_args()
    
    # Validate input
    if not args.input.exists():
        print(f"❌ Error: Input file not found: {args.input}")
        return 1
    
    # Load workflow
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            workflow = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in input file: {e}")
        return 1
    
    # Sanitize
    sanitizer = WorkflowSanitizer(redact_prompts=args.redact_prompts)
    sanitized = sanitizer.sanitize(workflow)
    
    # Write output
    indent = None if args.compact else 2
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(sanitized, f, indent=indent, ensure_ascii=False)
    
    # Reports
    if args.report:
        sanitizer.report.print_summary()
    
    if args.report_file:
        with open(args.report_file, 'w', encoding='utf-8') as f:
            json.dump(sanitizer.report.to_dict(), f, indent=2)
        print(f"📄 Detailed report saved to: {args.report_file}")
    
    print(f"✅ Sanitized workflow saved to: {args.output}")
    
    # Show warnings count
    if sanitizer.report.warnings:
        print(f"⚠️  {len(sanitizer.report.warnings)} warning(s) - review with --report")
    
    return 0


if __name__ == '__main__':
    exit(main())
