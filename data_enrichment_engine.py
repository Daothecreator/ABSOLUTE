#!/usr/bin/env python3
"""
Advanced Data Enrichment Engine (ADEE)
Real-time integration, data acquisition, and discovery system

Features:
- Multi-source data fusion and correlation
- Real-time stream processing
- Entity resolution and linking
- Automated data quality assessment
- Cross-reference validation

License: MIT
Version: 2.0 (April 2026)
"""

import asyncio
import aiohttp
import json
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from enum import Enum
import ipaddress
import socket
import ssl
import urllib.parse


class DataSourceType(Enum):
    """Types of data sources"""
    TECHNICAL_DOC = "technical_documentation"
    GOVERNMENT = "government_open_data"
    LEAK_DATABASE = "leak_database"
    DNS = "dns_infrastructure"
    CERTIFICATE = "certificate_transparency"
    OSINT = "open_source_intelligence"
    DARK_WEB = "dark_web_monitor"
    SOCIAL_MEDIA = "social_media"
    ACADEMIC = "academic_database"
    CORPORATE = "corporate_registry"


@dataclass
class DataEntity:
    """Unified data entity for enrichment"""
    entity_type: str  # domain, ip, email, hash, username, etc.
    value: str
    source: str
    confidence: float = 0.0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)
    related_entities: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict:
        return {
            'entity_type': self.entity_type,
            'value': self.value,
            'source': self.source,
            'confidence': self.confidence,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'metadata': self.metadata,
            'related_entities': self.related_entities,
            'tags': list(self.tags)
        }


@dataclass
class EnrichmentResult:
    """Result of data enrichment operation"""
    entity: DataEntity
    enriched_data: Dict
    sources_used: List[str]
    enrichment_time: float
    confidence_score: float
    related_findings: List[Dict]


class DataEnrichmentEngine:
    """
    Advanced Data Enrichment Engine
    
    Core capabilities:
    - Entity extraction and normalization
    - Multi-source correlation
    - Confidence scoring
    - Automated enrichment pipelines
    """
    
    # Known data patterns
    PATTERNS = {
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'phone': r'\b\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'url': r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
        'mac_address': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
        'cve': r'CVE-\d{4}-\d{4,}',
    }
    
    def __init__(self, api_keys: Optional[Dict] = None):
        self.api_keys = api_keys or {}
        self.entity_cache: Dict[str, DataEntity] = {}
        self.enrichment_cache: Dict[str, EnrichmentResult] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.rate_limiters: Dict[str, asyncio.Semaphore] = {}
        self.source_handlers: Dict[DataSourceType, Callable] = {
            DataSourceType.DNS: self._enrich_dns,
            DataSourceType.CERTIFICATE: self._enrich_certificate,
            DataSourceType.GOVERNMENT: self._enrich_government,
            DataSourceType.TECHNICAL_DOC: self._enrich_technical,
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'ADEE/2.0 (Advanced Data Enrichment Engine)',
                'Accept': 'application/json, text/html, */*'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def extract_entities(self, text: str) -> List[DataEntity]:
        """
        Extract entities from text using pattern matching
        
        Args:
            text: Text to analyze
        
        Returns:
            List of extracted entities
        """
        entities = []
        seen = set()
        
        for entity_type, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, text)
            for match in matches:
                value = match.group()
                
                # Deduplicate
                key = f"{entity_type}:{value}"
                if key in seen:
                    continue
                seen.add(key)
                
                # Validate and create entity
                if self._validate_entity(entity_type, value):
                    entity = DataEntity(
                        entity_type=entity_type,
                        value=value,
                        source="pattern_extraction",
                        confidence=0.7,
                        tags={"auto_extracted"}
                    )
                    entities.append(entity)
        
        return entities
    
    def _validate_entity(self, entity_type: str, value: str) -> bool:
        """Validate extracted entity"""
        if entity_type == 'ipv4':
            try:
                ipaddress.IPv4Address(value)
                return True
            except:
                return False
        
        elif entity_type == 'ipv6':
            try:
                ipaddress.IPv6Address(value)
                return True
            except:
                return False
        
        elif entity_type == 'email':
            # Additional email validation
            return '@' in value and '.' in value.split('@')[1]
        
        elif entity_type in ['md5', 'sha1', 'sha256']:
            # Check if it looks like a real hash (not all same char)
            return len(set(value)) > 4
        
        return True
    
    async def enrich_entity(self, entity: DataEntity, 
                           sources: Optional[List[DataSourceType]] = None) -> EnrichmentResult:
        """
        Enrich a single entity with data from multiple sources
        
        Args:
            entity: Entity to enrich
            sources: List of sources to query (default: all)
        
        Returns:
            Enrichment result
        """
        start_time = datetime.now()
        
        if sources is None:
            sources = list(self.source_handlers.keys())
        
        enriched_data = {}
        sources_used = []
        related_findings = []
        
        # Query each source
        for source_type in sources:
            if source_type in self.source_handlers:
                try:
                    result = await self.source_handlers[source_type](entity)
                    if result:
                        enriched_data[source_type.value] = result
                        sources_used.append(source_type.value)
                        
                        # Extract related entities
                        if 'related' in result:
                            related_findings.extend(result['related'])
                except Exception as e:
                    enriched_data[source_type.value] = {'error': str(e)}
        
        # Calculate confidence based on sources
        confidence = self._calculate_confidence(entity, sources_used, enriched_data)
        
        enrichment_time = (datetime.now() - start_time).total_seconds()
        
        result = EnrichmentResult(
            entity=entity,
            enriched_data=enriched_data,
            sources_used=sources_used,
            enrichment_time=enrichment_time,
            confidence_score=confidence,
            related_findings=related_findings
        )
        
        # Cache result
        cache_key = f"{entity.entity_type}:{entity.value}"
        self.enrichment_cache[cache_key] = result
        
        return result
    
    async def enrich_batch(self, entities: List[DataEntity],
                          max_concurrent: int = 10) -> List[EnrichmentResult]:
        """
        Enrich multiple entities concurrently
        
        Args:
            entities: List of entities to enrich
            max_concurrent: Maximum concurrent operations
        
        Returns:
            List of enrichment results
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def enrich_with_limit(entity):
            async with semaphore:
                return await self.enrich_entity(entity)
        
        tasks = [enrich_with_limit(e) for e in entities]
        return await asyncio.gather(*tasks)
    
    def _calculate_confidence(self, entity: DataEntity, 
                             sources_used: List[str],
                             enriched_data: Dict) -> float:
        """Calculate confidence score based on enrichment results"""
        base_confidence = entity.confidence
        
        # More sources = higher confidence
        source_multiplier = min(1.5, 1 + (len(sources_used) * 0.1))
        
        # Check data quality
        quality_score = 1.0
        for source, data in enriched_data.items():
            if isinstance(data, dict):
                if 'error' in data:
                    quality_score -= 0.1
                if 'verified' in data and data['verified']:
                    quality_score += 0.1
        
        quality_score = max(0.5, min(1.5, quality_score))
        
        return min(1.0, base_confidence * source_multiplier * quality_score)
    
    # Source-specific enrichment handlers
    
    async def _enrich_dns(self, entity: DataEntity) -> Optional[Dict]:
        """Enrich with DNS data"""
        if entity.entity_type == 'domain':
            return await self._query_dns(entity.value)
        elif entity.entity_type == 'ipv4':
            return await self._query_reverse_dns(entity.value)
        return None
    
    async def _query_dns(self, domain: str) -> Dict:
        """Query DNS records for domain"""
        import dns.resolver
        
        result = {
            'domain': domain,
            'records': {},
            'related': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result['records'][record_type] = [str(rdata) for rdata in answers]
                
                # Extract related entities
                for rdata in answers:
                    if record_type == 'A':
                        result['related'].append({
                            'type': 'ip',
                            'value': str(rdata),
                            'relation': 'resolves_to'
                        })
            except:
                pass
        
        return result
    
    async def _query_reverse_dns(self, ip: str) -> Dict:
        """Query reverse DNS for IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {
                'ip': ip,
                'hostname': hostname,
                'related': [{
                    'type': 'domain',
                    'value': hostname,
                    'relation': 'reverse_dns'
                }]
            }
        except:
            return {'ip': ip, 'hostname': None}
    
    async def _enrich_certificate(self, entity: DataEntity) -> Optional[Dict]:
        """Enrich with certificate transparency data"""
        if entity.entity_type == 'domain':
            return await self._query_ct_logs(entity.value)
        return None
    
    async def _query_ct_logs(self, domain: str) -> Dict:
        """Query Certificate Transparency logs via crt.sh"""
        url = f"https://crt.sh/?q={domain}&output=json"
        
        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    certificates = []
                    related_domains = set()
                    
                    for cert in data:
                        cert_info = {
                            'id': cert.get('id'),
                            'issuer': cert.get('issuer_name'),
                            'not_before': cert.get('not_before'),
                            'not_after': cert.get('not_after'),
                            'serial': cert.get('serial_number')
                        }
                        certificates.append(cert_info)
                        
                        # Extract related domains from SAN
                        name_value = cert.get('name_value', '')
                        if name_value:
                            related_domains.update(name_value.split('\n'))
                    
                    return {
                        'domain': domain,
                        'certificate_count': len(certificates),
                        'certificates': certificates[:10],  # Limit results
                        'related_domains': list(related_domains)[:20],
                        'related': [{'type': 'domain', 'value': d, 'relation': 'cert_related'} 
                                   for d in related_domains if d != domain][:10]
                    }
        except Exception as e:
            return {'error': str(e)}
        
        return {'domain': domain, 'certificates': []}
    
    async def _enrich_government(self, entity: DataEntity) -> Optional[Dict]:
        """Enrich with government/open data"""
        results = {}
        
        # Try multiple government data sources
        if entity.entity_type == 'domain':
            # Censys data
            censys_result = await self._query_censys(entity.value)
            if censys_result:
                results['censys'] = censys_result
        
        return results if results else None
    
    async def _query_censys(self, domain: str) -> Optional[Dict]:
        """Query Censys for host data"""
        # Note: Requires API credentials
        if 'censys_api_id' not in self.api_keys:
            return None
        
        api_id = self.api_keys['censys_api_id']
        api_secret = self.api_keys['censys_api_secret']
        
        url = f"https://search.censys.io/api/v2/hosts/search"
        params = {'q': domain}
        auth = aiohttp.BasicAuth(api_id, api_secret)
        
        try:
            async with self.session.get(url, params=params, auth=auth) as response:
                if response.status == 200:
                    return await response.json()
        except:
            pass
        
        return None
    
    async def _enrich_technical(self, entity: DataEntity) -> Optional[Dict]:
        """Enrich with technical documentation data"""
        if entity.entity_type == 'cve':
            return await self._query_cve(entity.value)
        return None
    
    async def _query_cve(self, cve_id: str) -> Dict:
        """Query CVE data from NVD"""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    vulnerabilities = data.get('vulnerabilities', [])
                    if vulnerabilities:
                        vuln = vulnerabilities[0].get('cve', {})
                        
                        return {
                            'cve_id': cve_id,
                            'description': vuln.get('descriptions', [{}])[0].get('value'),
                            'severity': vuln.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity'),
                            'score': vuln.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore'),
                            'published': vuln.get('published'),
                            'modified': vuln.get('lastModified'),
                            'references': [r.get('url') for r in vuln.get('references', [])]
                        }
        except Exception as e:
            return {'error': str(e)}
        
        return {'cve_id': cve_id}
    
    # Data correlation and fusion
    
    def correlate_entities(self, entities: List[DataEntity]) -> Dict[str, List[DataEntity]]:
        """
        Correlate entities to find relationships
        
        Returns:
            Dictionary mapping correlation types to entity groups
        """
        correlations = defaultdict(list)
        
        # Group by IP subnet
        ip_entities = [e for e in entities if e.entity_type == 'ipv4']
        subnets = defaultdict(list)
        
        for entity in ip_entities:
            try:
                ip = ipaddress.IPv4Address(entity.value)
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                subnets[str(network)].append(entity)
            except:
                pass
        
        for subnet, subnet_entities in subnets.items():
            if len(subnet_entities) > 1:
                correlations[f'subnet_{subnet}'] = subnet_entities
        
        # Group by domain suffix
        domain_entities = [e for e in entities if e.entity_type == 'domain']
        suffixes = defaultdict(list)
        
        for entity in domain_entities:
            parts = entity.value.split('.')
            if len(parts) >= 2:
                suffix = '.'.join(parts[-2:])
                suffixes[suffix].append(entity)
        
        for suffix, suffix_entities in suffixes.items():
            if len(suffix_entities) > 1:
                correlations[f'domain_suffix_{suffix}'] = suffix_entities
        
        # Group by email domain
        email_entities = [e for e in entities if e.entity_type == 'email']
        email_domains = defaultdict(list)
        
        for entity in email_entities:
            domain = entity.value.split('@')[1]
            email_domains[domain].append(entity)
        
        for domain, domain_entities in email_domains.items():
            if len(domain_entities) > 1:
                correlations[f'email_domain_{domain}'] = domain_entities
        
        return dict(correlations)
    
    def generate_entity_graph(self, entities: List[DataEntity]) -> Dict:
        """
        Generate entity relationship graph
        
        Returns:
            Graph structure with nodes and edges
        """
        nodes = []
        edges = []
        node_ids = {}
        
        # Create nodes
        for i, entity in enumerate(entities):
            node_id = f"node_{i}"
            node_ids[entity.value] = node_id
            
            nodes.append({
                'id': node_id,
                'type': entity.entity_type,
                'value': entity.value,
                'confidence': entity.confidence,
                'source': entity.source
            })
        
        # Create edges from related entities
        for entity in entities:
            if entity.value in node_ids:
                source_id = node_ids[entity.value]
                
                for related_value in entity.related_entities:
                    if related_value in node_ids:
                        target_id = node_ids[related_value]
                        edges.append({
                            'source': source_id,
                            'target': target_id,
                            'relation': 'related'
                        })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'stats': {
                'node_count': len(nodes),
                'edge_count': len(edges)
            }
        }


# Real-time Data Stream Processor
class RealtimeStreamProcessor:
    """
    Real-time data stream processing
    
    Handles continuous data ingestion and processing
    """
    
    def __init__(self, enrichment_engine: DataEnrichmentEngine):
        self.engine = enrichment_engine
        self.processors: Dict[str, Callable] = {}
        self.active_streams: Dict[str, asyncio.Task] = {}
        self.results_queue: asyncio.Queue = asyncio.Queue()
    
    def register_processor(self, stream_name: str, 
                          processor: Callable[[Any], Any]):
        """Register a processor for a stream"""
        self.processors[stream_name] = processor
    
    async def start_stream(self, stream_name: str, 
                          data_source: Callable[[], Any],
                          interval: float = 1.0):
        """
        Start processing a data stream
        
        Args:
            stream_name: Name of the stream
            data_source: Async generator or callable that returns data
            interval: Polling interval in seconds
        """
        async def process_loop():
            while True:
                try:
                    # Get data from source
                    if asyncio.iscoroutinefunction(data_source):
                        data = await data_source()
                    else:
                        data = data_source()
                    
                    # Process data
                    if stream_name in self.processors:
                        result = self.processors[stream_name](data)
                        if asyncio.iscoroutine(result):
                            result = await result
                        
                        await self.results_queue.put({
                            'stream': stream_name,
                            'timestamp': datetime.now().isoformat(),
                            'data': data,
                            'result': result
                        })
                
                except Exception as e:
                    await self.results_queue.put({
                        'stream': stream_name,
                        'timestamp': datetime.now().isoformat(),
                        'error': str(e)
                    })
                
                await asyncio.sleep(interval)
        
        task = asyncio.create_task(process_loop())
        self.active_streams[stream_name] = task
    
    async def stop_stream(self, stream_name: str):
        """Stop a running stream"""
        if stream_name in self.active_streams:
            self.active_streams[stream_name].cancel()
            del self.active_streams[stream_name]
    
    async def get_results(self, timeout: Optional[float] = None) -> Optional[Dict]:
        """Get next result from queue"""
        try:
            return await asyncio.wait_for(self.results_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None


# Data Quality Assessment
class DataQualityAssessor:
    """Assess quality of enriched data"""
    
    @staticmethod
    def assess_completeness(data: Dict) -> float:
        """Assess data completeness (0-1)"""
        if not data:
            return 0.0
        
        total_fields = len(data)
        filled_fields = sum(1 for v in data.values() if v is not None and v != '')
        
        return filled_fields / total_fields if total_fields > 0 else 0.0
    
    @staticmethod
    def assess_freshness(timestamp: Optional[datetime], 
                        max_age: timedelta = timedelta(days=30)) -> float:
        """Assess data freshness (0-1)"""
        if timestamp is None:
            return 0.0
        
        age = datetime.now() - timestamp
        if age > max_age:
            return 0.0
        
        return 1.0 - (age / max_age)
    
    @staticmethod
    def assess_consistency(data: Dict, schema: Dict) -> float:
        """Assess data consistency against schema"""
        if not schema:
            return 1.0
        
        consistent_fields = 0
        
        for field, field_type in schema.items():
            if field in data:
                value = data[field]
                
                # Type checking
                if field_type == 'str' and isinstance(value, str):
                    consistent_fields += 1
                elif field_type == 'int' and isinstance(value, int):
                    consistent_fields += 1
                elif field_type == 'float' and isinstance(value, (int, float)):
                    consistent_fields += 1
                elif field_type == 'list' and isinstance(value, list):
                    consistent_fields += 1
                elif field_type == 'dict' and isinstance(value, dict):
                    consistent_fields += 1
        
        return consistent_fields / len(schema) if schema else 1.0


async def demo():
    """Demonstration of data enrichment engine"""
    print("=" * 70)
    print("ADVANCED DATA ENRICHMENT ENGINE (ADEE)")
    print("=" * 70)
    
    async with DataEnrichmentEngine() as engine:
        # 1. Entity extraction
        print("\n1. Entity Extraction from Sample Text")
        print("-" * 50)
        
        sample_text = """
        Contact us at admin@example.com or support@company.org.
        Our servers are at 192.168.1.1 and 10.0.0.1.
        Visit https://example.com/login for more info.
        CVE-2021-44228 is a critical vulnerability.
        Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        """
        
        entities = engine.extract_entities(sample_text)
        print(f"Found {len(entities)} entities:")
        for entity in entities[:5]:
            print(f"  [{entity.entity_type}] {entity.value}")
        
        # 2. Domain enrichment
        print("\n2. Domain Enrichment (example.com)")
        print("-" * 50)
        
        domain_entity = DataEntity(
            entity_type='domain',
            value='example.com',
            source='manual',
            confidence=1.0
        )
        
        result = await engine.enrich_entity(domain_entity)
        print(f"Enrichment time: {result.enrichment_time:.2f}s")
        print(f"Confidence: {result.confidence_score:.2f}")
        print(f"Sources: {', '.join(result.sources_used)}")
        
        # 3. CVE enrichment
        print("\n3. CVE Enrichment (CVE-2021-44228)")
        print("-" * 50)
        
        cve_entity = DataEntity(
            entity_type='cve',
            value='CVE-2021-44228',
            source='manual',
            confidence=1.0
        )
        
        result = await engine.enrich_entity(cve_entity)
        if 'technical_documentation' in result.enriched_data:
            cve_data = result.enriched_data['technical_documentation']
            print(f"Description: {cve_data.get('description', 'N/A')[:100]}...")
            print(f"Severity: {cve_data.get('severity', 'N/A')}")
            print(f"Score: {cve_data.get('score', 'N/A')}")
        
        # 4. Entity correlation
        print("\n4. Entity Correlation")
        print("-" * 50)
        
        test_entities = [
            DataEntity('ipv4', '192.168.1.1', 'test'),
            DataEntity('ipv4', '192.168.1.2', 'test'),
            DataEntity('ipv4', '10.0.0.1', 'test'),
            DataEntity('domain', 'mail.example.com', 'test'),
            DataEntity('domain', 'www.example.com', 'test'),
            DataEntity('email', 'admin@example.com', 'test'),
            DataEntity('email', 'user@example.com', 'test'),
        ]
        
        correlations = engine.correlate_entities(test_entities)
        print(f"Found {len(correlations)} correlation groups:")
        for corr_type, corr_entities in correlations.items():
            print(f"  {corr_type}: {len(corr_entities)} entities")
    
    print("\n" + "=" * 70)
    print("Data Enrichment Engine Ready")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(demo())
