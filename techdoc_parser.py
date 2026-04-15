#!/usr/bin/env python3
"""
Technical Documentation Parser and Intelligence Extractor
Extract structured data from technical documents, manuals, and specifications

Features:
- Multi-format document parsing (PDF, DOCX, HTML, Markdown)
- Code extraction and analysis
- Configuration file parsing
- API documentation extraction
- Network diagram parsing
- Structured data extraction

License: MIT
Version: 2.0 (April 2026)
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import hashlib


class DocumentType(Enum):
    """Types of technical documents"""
    API_SPEC = "api_specification"
    CONFIG = "configuration"
    NETWORK_DIAGRAM = "network_diagram"
    ARCHITECTURE = "architecture_doc"
    SECURITY_POLICY = "security_policy"
    INCIDENT_REPORT = "incident_report"
    AUDIT_LOG = "audit_log"
    SOURCE_CODE = "source_code"
    DATABASE_SCHEMA = "database_schema"
    DEPLOYMENT = "deployment_guide"
    RUNBOOK = "operational_runbook"


@dataclass
class ExtractedEntity:
    """Entity extracted from technical document"""
    entity_type: str
    value: str
    context: str
    confidence: float
    location: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)


@dataclass
class ParsedDocument:
    """Parsed technical document"""
    filename: str
    doc_type: DocumentType
    content: str
    entities: List[ExtractedEntity] = field(default_factory=list)
    structure: Dict = field(default_factory=dict)
    parsed_at: datetime = field(default_factory=datetime.now)


class TechnicalDocumentParser:
    """
    Technical Documentation Parser
    
    Extracts structured intelligence from technical documents
    of various formats and types.
    """
    
    # Extraction patterns for different entity types
    PATTERNS = {
        # Network and infrastructure
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'mac_address': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
        
        # Authentication and secrets
        'api_key': r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
        'secret_key': r'(?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
        'token': r'(?:token|bearer)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
        'password': r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?',
        'private_key': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        
        # Cryptographic
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
        
        # Identifiers
        'uuid': r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
        'cve': r'CVE-\d{4}-\d{4,}',
        'cwe': r'CWE-\d+',
        
        # File paths
        'unix_path': r'/(?:[a-zA-Z0-9_\-\.]+/)*[a-zA-Z0-9_\-\.]+',
        'windows_path': r'[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        
        # Email and contact
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
        
        # Cloud and infrastructure
        'aws_arn': r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d*:[a-z0-9-]+/[^\s]+',
        'azure_id': r'/subscriptions/[0-9a-f-]+/resourceGroups/[^\s]+',
        'gcp_project': r'projects/[a-z][a-z0-9-]{4,28}[a-z0-9]',
        'docker_image': r'[a-z0-9]+(?:[._-][a-z0-9]+)*[:/][a-z0-9]+(?:[._-][a-z0-9]+)*(?::[\w.\-]+)?',
        'kubernetes_resource': r'[a-z-]+/[a-z0-9-]+',
    }
    
    # Configuration file patterns
    CONFIG_PATTERNS = {
        'yaml_key_value': r'^(\w+):\s*(.+)$',
        'ini_section': r'^\[(\w+)\]$',
        'ini_key_value': r'^(\w+)\s*=\s*(.+)$',
        'env_variable': r'^([A-Z_]+)\s*=\s*(.+)$',
        'json_key': r'"(\w+)":\s*"?([^",\}]*)"?',
        'xml_tag': r'<(\w+)[^>]*>([^<]*)</\1>',
    }
    
    def __init__(self):
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.PATTERNS.items()
        }
    
    def parse_text(self, content: str, filename: str = "unknown",
                   doc_type: Optional[DocumentType] = None) -> ParsedDocument:
        """
        Parse text content and extract entities
        
        Args:
            content: Document content
            filename: Source filename
            doc_type: Document type (auto-detected if not specified)
        
        Returns:
            Parsed document with extracted entities
        """
        # Auto-detect document type if not specified
        if doc_type is None:
            doc_type = self._detect_document_type(content, filename)
        
        # Extract entities
        entities = self._extract_entities(content)
        
        # Parse structure
        structure = self._parse_structure(content, doc_type)
        
        return ParsedDocument(
            filename=filename,
            doc_type=doc_type,
            content=content[:100000],  # Limit stored content
            entities=entities,
            structure=structure
        )
    
    def parse_file(self, filepath: str) -> ParsedDocument:
        """
        Parse a file and extract intelligence
        
        Args:
            filepath: Path to file
        
        Returns:
            Parsed document
        """
        path = Path(filepath)
        
        # Read file content
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            content = f"Error reading file: {e}"
        
        # Detect document type from extension and content
        doc_type = self._detect_document_type(content, path.name)
        
        return self.parse_text(content, path.name, doc_type)
    
    def _detect_document_type(self, content: str, filename: str) -> DocumentType:
        """Detect document type from content and filename"""
        filename_lower = filename.lower()
        content_lower = content.lower()[:5000]
        
        # Check filename patterns
        if any(ext in filename_lower for ext in ['api', 'swagger', 'openapi']):
            return DocumentType.API_SPEC
        
        if any(ext in filename_lower for ext in ['config', '.conf', '.cfg', '.ini', '.env']):
            return DocumentType.CONFIG
        
        if any(ext in filename_lower for ext in ['network', 'topology', 'diagram']):
            return DocumentType.NETWORK_DIAGRAM
        
        if any(ext in filename_lower for ext in ['arch', 'architecture', 'design']):
            return DocumentType.ARCHITECTURE
        
        if any(ext in filename_lower for ext in ['security', 'policy', 'compliance']):
            return DocumentType.SECURITY_POLICY
        
        if any(ext in filename_lower for ext in ['incident', 'postmortem', 'outage']):
            return DocumentType.INCIDENT_REPORT
        
        if any(ext in filename_lower for ext in ['audit', 'log']):
            return DocumentType.AUDIT_LOG
        
        if any(ext in filename_lower for ext in ['.py', '.js', '.java', '.go', '.rs', '.c', '.cpp']):
            return DocumentType.SOURCE_CODE
        
        if any(ext in filename_lower for ext in ['schema', 'migration', '.sql']):
            return DocumentType.DATABASE_SCHEMA
        
        if any(ext in filename_lower for ext in ['deploy', 'deployment', 'install']):
            return DocumentType.DEPLOYMENT
        
        if any(ext in filename_lower for ext in ['runbook', 'playbook', 'procedure']):
            return DocumentType.RUNBOOK
        
        # Check content patterns
        if 'openapi' in content_lower or 'swagger' in content_lower:
            return DocumentType.API_SPEC
        
        if 'incident' in content_lower and 'postmortem' in content_lower:
            return DocumentType.INCIDENT_REPORT
        
        if 'security policy' in content_lower or 'compliance' in content_lower:
            return DocumentType.SECURITY_POLICY
        
        return DocumentType.ARCHITECTURE  # Default
    
    def _extract_entities(self, content: str) -> List[ExtractedEntity]:
        """Extract entities from content"""
        entities = []
        seen = set()
        
        for pattern_name, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(content):
                value = match.group(0)
                
                # Deduplicate
                key = f"{pattern_name}:{value}"
                if key in seen:
                    continue
                seen.add(key)
                
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end]
                
                # Calculate confidence
                confidence = self._calculate_confidence(pattern_name, value, context)
                
                entity = ExtractedEntity(
                    entity_type=pattern_name,
                    value=value,
                    context=context,
                    confidence=confidence,
                    location={
                        'start': match.start(),
                        'end': match.end(),
                        'line': content[:match.start()].count('\n') + 1
                    }
                )
                
                entities.append(entity)
        
        return entities
    
    def _calculate_confidence(self, entity_type: str, value: str, 
                              context: str) -> float:
        """Calculate confidence score for extracted entity"""
        confidence = 0.7  # Base confidence
        
        # Increase confidence for longer values
        if len(value) > 20:
            confidence += 0.1
        
        # Check for suspicious patterns that might be false positives
        if entity_type in ['password', 'secret_key', 'api_key']:
            # Check if it's in a comment or example
            if 'example' in context.lower() or 'sample' in context.lower():
                confidence -= 0.3
            if '#' in context[:context.find(value)]:
                confidence -= 0.2
        
        # Validate IP addresses
        if entity_type == 'ipv4':
            try:
                import ipaddress
                ipaddress.IPv4Address(value)
                confidence += 0.2
            except:
                confidence -= 0.5
        
        return max(0.0, min(1.0, confidence))
    
    def _parse_structure(self, content: str, doc_type: DocumentType) -> Dict:
        """Parse document structure based on type"""
        structure = {
            'sections': [],
            'headers': [],
            'lists': [],
            'tables': [],
            'code_blocks': []
        }
        
        # Extract headers
        header_pattern = r'^(#{1,6}\s+.+|\w+\s*\n={3,}|\w+\s*\n-{3,})$'
        for match in re.finditer(header_pattern, content, re.MULTILINE):
            structure['headers'].append({
                'text': match.group(0).strip(),
                'position': match.start()
            })
        
        # Extract code blocks
        code_pattern = r'```[\w]*\n(.*?)```'
        for match in re.finditer(code_pattern, content, re.DOTALL):
            structure['code_blocks'].append({
                'content': match.group(1)[:500],  # Limit size
                'position': match.start()
            })
        
        # Type-specific parsing
        if doc_type == DocumentType.API_SPEC:
            structure['endpoints'] = self._parse_api_endpoints(content)
        
        elif doc_type == DocumentType.CONFIG:
            structure['config'] = self._parse_config(content)
        
        elif doc_type == DocumentType.SOURCE_CODE:
            structure['functions'] = self._parse_code_functions(content)
        
        return structure
    
    def _parse_api_endpoints(self, content: str) -> List[Dict]:
        """Parse API endpoints from specification"""
        endpoints = []
        
        # OpenAPI/Swagger patterns
        patterns = [
            r'["\']?(get|post|put|delete|patch)["\']?\s*:\s*\{[^}]*["\']?summary["\']?\s*:\s*["\']([^"\']+)',
            r'(GET|POST|PUT|DELETE|PATCH)\s+(/[\w/{}-]+)',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                endpoints.append({
                    'method': match.group(1).upper(),
                    'path': match.group(2) if len(match.groups()) > 1 else 'unknown',
                    'position': match.start()
                })
        
        return endpoints
    
    def _parse_config(self, content: str) -> Dict:
        """Parse configuration file"""
        config = {}
        
        # Try YAML/JSON style
        for match in re.finditer(self.CONFIG_PATTERNS['yaml_key_value'], 
                                  content, re.MULTILINE):
            key = match.group(1)
            value = match.group(2).strip()
            config[key] = value
        
        # Try INI style
        current_section = 'default'
        for line in content.split('\n'):
            section_match = re.match(self.CONFIG_PATTERNS['ini_section'], line)
            if section_match:
                current_section = section_match.group(1)
                if current_section not in config:
                    config[current_section] = {}
            
            kv_match = re.match(self.CONFIG_PATTERNS['ini_key_value'], line)
            if kv_match:
                key = kv_match.group(1)
                value = kv_match.group(2)
                if current_section not in config:
                    config[current_section] = {}
                config[current_section][key] = value
        
        return config
    
    def _parse_code_functions(self, content: str) -> List[Dict]:
        """Parse function definitions from source code"""
        functions = []
        
        # Python functions
        python_pattern = r'def\s+(\w+)\s*\([^)]*\)(?:\s*->\s*\w+)?\s*:'
        for match in re.finditer(python_pattern, content):
            functions.append({
                'language': 'python',
                'name': match.group(1),
                'position': match.start()
            })
        
        # JavaScript/TypeScript functions
        js_pattern = r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)'
        for match in re.finditer(js_pattern, content):
            name = match.group(1) or match.group(2)
            functions.append({
                'language': 'javascript',
                'name': name,
                'position': match.start()
            })
        
        return functions
    
    # Specialized parsers
    
    def parse_log_file(self, content: str, log_format: Optional[str] = None) -> List[Dict]:
        """
        Parse log file and extract events
        
        Args:
            content: Log file content
            log_format: Log format (syslog, apache, json, etc.)
        
        Returns:
            List of parsed log entries
        """
        entries = []
        
        # Common log patterns
        patterns = {
            'syslog': r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[?(\d*)\]?\s*:\s*(.+)$',
            'apache': r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\S+)',
            'json': r'^\{.*\}$',
        }
        
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            entry = {'raw': line}
            
            # Try each pattern
            for fmt, pattern in patterns.items():
                match = re.match(pattern, line)
                if match:
                    entry['format'] = fmt
                    entry['parsed'] = match.groups()
                    break
            
            entries.append(entry)
        
        return entries
    
    def parse_network_config(self, content: str) -> Dict:
        """
        Parse network configuration file
        
        Args:
            content: Configuration content
        
        Returns:
            Parsed network configuration
        """
        config = {
            'interfaces': [],
            'routes': [],
            'vlans': [],
            'access_lists': [],
            'nat_rules': []
        }
        
        # Cisco IOS patterns
        interface_pattern = r'^interface\s+(\S+)\s*\n(.*?)(?=^\w|\Z)'
        for match in re.finditer(interface_pattern, content, re.MULTILINE | re.DOTALL):
            interface_name = match.group(1)
            interface_config = match.group(2)
            
            interface = {
                'name': interface_name,
                'ip_address': None,
                'subnet_mask': None,
                'description': None,
                'shutdown': 'shutdown' in interface_config
            }
            
            # Extract IP address
            ip_match = re.search(r'ip address\s+(\S+)\s+(\S+)', interface_config)
            if ip_match:
                interface['ip_address'] = ip_match.group(1)
                interface['subnet_mask'] = ip_match.group(2)
            
            # Extract description
            desc_match = re.search(r'description\s+(.+)', interface_config)
            if desc_match:
                interface['description'] = desc_match.group(1).strip()
            
            config['interfaces'].append(interface)
        
        return config
    
    def extract_credentials(self, content: str) -> List[Dict]:
        """
        Extract potential credentials from content
        
        WARNING: This is for security auditing purposes only
        
        Args:
            content: Content to analyze
        
        Returns:
            List of potential credentials
        """
        credentials = []
        
        # Pattern for various credential formats
        patterns = {
            'basic_auth': r'(?:https?://)([^:]+):([^@]+)@',
            'connection_string': r'(?:Server|Data Source|Host)\s*=\s*([^;]+).*?(?:Password|Pwd)\s*=\s*([^;]+)',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        }
        
        for cred_type, pattern in patterns.items():
            for match in re.finditer(pattern, content):
                credentials.append({
                    'type': cred_type,
                    'position': match.start(),
                    'context': content[max(0, match.start()-30):match.end()+30],
                    'warning': 'Potential credential exposure'
                })
        
        return credentials
    
    def generate_document_report(self, parsed_doc: ParsedDocument) -> Dict:
        """
        Generate analysis report for parsed document
        
        Args:
            parsed_doc: Parsed document
        
        Returns:
            Analysis report
        """
        report = {
            'filename': parsed_doc.filename,
            'document_type': parsed_doc.doc_type.value,
            'parsed_at': parsed_doc.parsed_at.isoformat(),
            'statistics': {
                'total_entities': len(parsed_doc.entities),
                'entity_types': {},
                'high_confidence_entities': 0,
                'potential_secrets': 0
            },
            'entity_summary': [],
            'security_findings': [],
            'recommendations': []
        }
        
        # Count entity types
        for entity in parsed_doc.entities:
            entity_type = entity.entity_type
            if entity_type not in report['statistics']['entity_types']:
                report['statistics']['entity_types'][entity_type] = 0
            report['statistics']['entity_types'][entity_type] += 1
            
            if entity.confidence > 0.8:
                report['statistics']['high_confidence_entities'] += 1
            
            if entity.entity_type in ['password', 'api_key', 'secret_key', 'private_key']:
                report['statistics']['potential_secrets'] += 1
                report['security_findings'].append({
                    'type': 'potential_secret',
                    'entity_type': entity.entity_type,
                    'location': entity.location,
                    'context': entity.context[:100]
                })
        
        # Generate recommendations
        if report['statistics']['potential_secrets'] > 0:
            report['recommendations'].append(
                "Document contains potential secrets that should be reviewed"
            )
        
        if 'password' in report['statistics']['entity_types']:
            report['recommendations'].append(
                "Passwords detected - ensure they are not hardcoded credentials"
            )
        
        if 'private_key' in report['statistics']['entity_types']:
            report['recommendations'].append(
                "Private keys detected - verify they are not production keys"
            )
        
        return report


def demo():
    """Demonstration of technical document parser"""
    print("=" * 70)
    print("TECHNICAL DOCUMENTATION PARSER")
    print("=" * 70)
    
    parser = TechnicalDocumentParser()
    
    # Sample technical document
    sample_doc = """
    # Network Configuration
    
    ## Server Details
    
    Primary server: 192.168.1.100
    Backup server: 192.168.1.101
    
    Domain: example.com
    Admin email: admin@example.com
    
    ## API Configuration
    
    ```yaml
    api:
      endpoint: https://api.example.com/v1
      key: sk_live_1234567890abcdef
      timeout: 30
    ```
    
    ## Database Connection
    
    Connection string: Server=db.example.com;Database=prod;User=admin;Password=Secret123!
    
    ## Security Notes
    
    CVE-2021-44228 was patched on 2022-01-15.
    
    Contact: +1-555-123-4567
    """
    
    print("\n1. Parsing Sample Document")
    print("-" * 50)
    
    parsed = parser.parse_text(sample_doc, "network_config.md")
    
    print(f"Document type: {parsed.doc_type.value}")
    print(f"Entities found: {len(parsed.entities)}")
    
    print("\n2. Extracted Entities")
    print("-" * 50)
    
    for entity in parsed.entities[:10]:
        print(f"  [{entity.entity_type}] {entity.value[:40]}... (confidence: {entity.confidence:.2f})")
    
    print("\n3. Document Structure")
    print("-" * 50)
    
    print(f"Headers: {len(parsed.structure.get('headers', []))}")
    print(f"Code blocks: {len(parsed.structure.get('code_blocks', []))}")
    
    print("\n4. Security Report")
    print("-" * 50)
    
    report = parser.generate_document_report(parsed)
    
    print(f"Potential secrets: {report['statistics']['potential_secrets']}")
    print(f"Security findings: {len(report['security_findings'])}")
    
    for finding in report['security_findings'][:3]:
        print(f"  - {finding['type']}: {finding['entity_type']}")
    
    print("\n5. Recommendations")
    print("-" * 50)
    
    for rec in report['recommendations']:
        print(f"  - {rec}")
    
    print("\n" + "=" * 70)
    print("Technical Document Parser Ready")
    print("=" * 70)


if __name__ == "__main__":
    demo()
