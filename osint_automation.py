#!/usr/bin/env python3
"""
OSINT Automation Framework
For information gathering, surveillance defense, and digital intelligence

Features:
- Multi-source academic/scientific data acquisition
- DNS and infrastructure intelligence
- Google dorking automation
- Continuous monitoring capabilities

License: MIT
Version: 1.0 (April 2026)
"""

import asyncio
import aiohttp
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import socket
import hashlib


@dataclass
class IntelligenceReport:
    """Structured intelligence report"""
    source: str
    query: str
    timestamp: datetime
    data: Dict
    confidence: float  # 0.0 to 1.0


class OSINTFramework:
    """
    Comprehensive OSINT automation toolkit
    
    The global OSINT market is expected to grow from $5.02 billion (2018)
    to $29.19 billion by 2026 (CAGR 24.7%).
    """
    
    # API endpoints
    SOURCES = {
        'inspire_hep': 'https://inspirehep.net/api/',
        'arxiv': 'http://export.arxiv.org/api/query',
        'cern_opendata': 'https://opendata.cern.ch/api/',
        'doi': 'https://doi.org/',
        'securitytrails': 'https://api.securitytrails.com/v1/',
    }
    
    # Rate limits (requests per time window)
    RATE_LIMITS = {
        'inspire_hep': (15, 5),  # 15 requests per 5 seconds
        'arxiv': (1, 3),  # 1 request per 3 seconds
        'cern_opendata': (10, 1),  # 10 requests per second
    }
    
    def __init__(self, api_keys: Optional[Dict] = None):
        """
        Initialize OSINT framework
        
        Args:
            api_keys: Dictionary of API keys for various services
        """
        self.api_keys = api_keys or {}
        self.cache: Dict[str, Dict] = {}
        self.last_request: Dict[str, datetime] = {}
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            headers={'User-Agent': 'OSINT-Framework/1.0'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _rate_limited_request(self, source: str, url: str, 
                                     params: Optional[Dict] = None) -> Optional[Dict]:
        """
        Make rate-limited API request
        """
        if source in self.RATE_LIMITS:
            max_req, window = self.RATE_LIMITS[source]
            now = datetime.now()
            
            if source in self.last_request:
                elapsed = (now - self.last_request[source]).total_seconds()
                min_interval = window / max_req
                
                if elapsed < min_interval:
                    await asyncio.sleep(min_interval - elapsed)
            
            self.last_request[source] = datetime.now()
        
        try:
            async with self.session.get(url, params=params, timeout=30) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    if 'application/json' in content_type:
                        return await response.json()
                    elif 'application/xml' in content_type or 'text/xml' in content_type:
                        text = await response.text()
                        return {'xml_content': text}
                    else:
                        text = await response.text()
                        return {'text_content': text}
                
                elif response.status == 429:
                    # Rate limited - exponential backoff
                    await asyncio.sleep(5)
                    return await self._rate_limited_request(source, url, params)
                
                else:
                    return {'error': f'HTTP {response.status}'}
        
        except asyncio.TimeoutError:
            return {'error': 'Request timeout'}
        except Exception as e:
            return {'error': str(e)}
    
    async def search_inspire(self, query: str, max_results: int = 25,
                             sort_by: str = 'mostrecent') -> List[Dict]:
        """
        Search INSPIRE-HEP for High Energy Physics literature
        
        Args:
            query: Search query string
            max_results: Maximum number of results
            sort_by: Sort order (mostrecent, mostcited, etc.)
        """
        url = f"{self.SOURCES['inspire_hep']}literature"
        params = {
            'q': query,
            'sort': sort_by,
            'size': max_results
        }
        
        data = await self._rate_limited_request('inspire_hep', url, params)
        
        if data and 'hits' in data:
            return data['hits'].get('hits', [])
        return []
    
    async def search_arxiv(self, query: str, max_results: int = 100,
                          sort_by: str = 'submittedDate') -> List[Dict]:
        """
        Search arXiv for preprints
        
        Args:
            query: Search query (can include category filters like cat:hep-ex)
            max_results: Maximum results to return
            sort_by: Sort criterion
        """
        url = self.SOURCES['arxiv']
        params = {
            'search_query': query,
            'start': 0,
            'max_results': max_results,
            'sortBy': sort_by,
            'sortOrder': 'descending'
        }
        
        data = await self._rate_limited_request('arxiv', url, params)
        
        if data and 'xml_content' in data:
            return self._parse_arxiv_feed(data['xml_content'])
        return []
    
    def _parse_arxiv_feed(self, xml_text: str) -> List[Dict]:
        """Parse arXiv Atom feed"""
        try:
            root = ET.fromstring(xml_text)
            entries = []
            ns = {'atom': 'http://www.w3.org/2005/Atom'}
            
            for entry in root.findall('atom:entry', ns):
                title = entry.find('atom:title', ns)
                summary = entry.find('atom:summary', ns)
                published = entry.find('atom:published', ns)
                updated = entry.find('atom:updated', ns)
                
                # Get authors
                authors = []
                for author in entry.findall('atom:author', ns):
                    name = author.find('atom:name', ns)
                    if name is not None:
                        authors.append(name.text)
                
                # Get categories
                categories = []
                for cat in entry.findall('atom:category', ns):
                    term = cat.get('term')
                    if term:
                        categories.append(term)
                
                # Get arXiv ID
                arxiv_id = ''
                for id_elem in entry.findall('atom:id', ns):
                    if id_elem.text:
                        arxiv_id = id_elem.text.split('/')[-1]
                
                entries.append({
                    'title': title.text.strip() if title is not None else '',
                    'abstract': summary.text.strip() if summary is not None else '',
                    'published': published.text if published is not None else '',
                    'updated': updated.text if updated is not None else '',
                    'authors': authors,
                    'categories': categories,
                    'arxiv_id': arxiv_id,
                })
            
            return entries
        
        except ET.ParseError as e:
            return [{'error': f'XML parse error: {str(e)}'}]
    
    async def search_cern_opendata(self, experiment: Optional[str] = None,
                                    data_type: Optional[str] = None) -> List[Dict]:
        """
        Search CERN Open Data Portal
        
        Args:
            experiment: Filter by experiment (ATLAS, CMS, ALICE, LHCb)
            data_type: Filter by data type (dataset, software, etc.)
        """
        url = f"{self.SOURCES['cern_opendata']}records/"
        params = {}
        
        if experiment:
            params['experiment'] = experiment
        if data_type:
            params['type'] = data_type
        
        data = await self._rate_limited_request('cern_opendata', url, params)
        
        if data and 'hits' in data:
            return data['hits'].get('hits', [])
        return []
    
    async def resolve_doi(self, doi: str) -> Optional[Dict]:
        """Resolve DOI to publication metadata"""
        url = f"{self.SOURCES['doi']}{doi}"
        
        headers = {'Accept': 'application/json'}
        
        try:
            async with self.session.get(url, headers=headers, allow_redirects=True) as response:
                if response.status == 200:
                    return await response.json()
                return None
        except Exception:
            return None
    
    async def monitor_topic(self, query: str, interval: int = 3600,
                           callback=None) -> None:
        """
        Continuously monitor a topic for new publications
        
        Args:
            query: Search query to monitor
            interval: Check interval in seconds
            callback: Function to call with new items
        """
        seen_ids: Set[str] = set()
        
        while True:
            print(f"[{datetime.now()}] Monitoring: {query}")
            
            # Search multiple sources
            try:
                inspire_results = await self.search_inspire(query)
                arxiv_results = await self.search_arxiv(query)
                
                all_results = [
                    ('inspire', r) for r in inspire_results
                ] + [
                    ('arxiv', r) for r in arxiv_results
                ]
                
                # Check for new items
                for source, item in all_results:
                    item_id = item.get('id') or item.get('arxiv_id')
                    if item_id and item_id not in seen_ids:
                        seen_ids.add(item_id)
                        
                        report = IntelligenceReport(
                            source=source,
                            query=query,
                            timestamp=datetime.now(),
                            data=item,
                            confidence=0.8
                        )
                        
                        if callback:
                            callback(report)
                        else:
                            self._default_alert(report)
            
            except Exception as e:
                print(f"Monitor error: {e}")
            
            await asyncio.sleep(interval)
    
    def _default_alert(self, report: IntelligenceReport) -> None:
        """Default alert handler for new publications"""
        print(f"\n[!] New Publication from {report.source.upper()}")
        print(f"    Query: {report.query}")
        print(f"    Time: {report.timestamp}")
        
        data = report.data
        if 'title' in data:
            print(f"    Title: {data['title'][:100]}...")
        if 'authors' in data:
            authors = data['authors']
            if isinstance(authors, list) and authors:
                print(f"    Authors: {', '.join(authors[:3])}")
        print()
    
    # Google Dorking
    @staticmethod
    def google_dork_generator(target: str, dork_type: str = 'files') -> List[str]:
        """
        Generate Google dorking queries
        
        Args:
            target: Target domain or site
            dork_type: Type of dork (files, directories, sensitive, infrastructure)
        
        Returns:
            List of Google dork queries
        """
        dorks = {
            'files': [
                f'site:{target} filetype:pdf',
                f'site:{target} filetype:doc OR filetype:docx',
                f'site:{target} filetype:xls OR filetype:xlsx',
                f'site:{target} filetype:ppt OR filetype:pptx',
                f'site:{target} ext:sql | ext:db | ext:sqlite | ext:backup',
                f'site:{target} ext:log | ext:txt | ext:xml',
                f'site:{target} ext:json | ext:yaml | ext:yml',
            ],
            'directories': [
                f'site:{target} intitle:index.of',
                f'site:{target} inurl:admin',
                f'site:{target} inurl:backup',
                f'site:{target} inurl:config',
                f'site:{target} inurl:api | inurl:swagger',
                f'site:{target} inurl:.git | inurl:.svn',
            ],
            'sensitive': [
                f'site:{target} "password" | "passwd" | "pwd" | "credentials"',
                f'site:{target} "api_key" | "apikey" | "api-key"',
                f'site:{target} "secret" | "token" | "auth"',
                f'site:{target} "database" | "db_password" | "connection_string"',
                f'site:{target} "aws_access_key_id" | "aws_secret_access_key"',
                f'site:{target} "private_key" | "ssh_key" | "pem"',
            ],
            'infrastructure': [
                f'site:{target} inurl:phpinfo',
                f'site:{target} inurl:server-status',
                f'site:{target} "Apache" "server at"',
                f'site:{target} "nginx" "server"',
                f'site:{target} intitle:"IIS" "Microsoft"',
            ],
            'people': [
                f'site:linkedin.com "{target}"',
                f'site:twitter.com OR site:x.com "{target}"',
                f'site:github.com "{target}"',
                f'site:{target} "contact" | "email" | "phone"',
            ]
        }
        
        return dorks.get(dork_type, [])
    
    @staticmethod
    def generate_dork_report(target: str) -> Dict:
        """Generate comprehensive dorking report for target"""
        report = {
            'target': target,
            'generated_at': datetime.now().isoformat(),
            'dorks': {}
        }
        
        for dork_type in ['files', 'directories', 'sensitive', 'infrastructure', 'people']:
            report['dorks'][dork_type] = OSINTFramework.google_dork_generator(target, dork_type)
        
        return report


# Infrastructure Intelligence
class InfrastructureIntel:
    """Infrastructure intelligence gathering"""
    
    @staticmethod
    def analyze_dns_history(domain: str, api_key: Optional[str] = None) -> Dict:
        """
        Analyze DNS history
        
        Note: Requires SecurityTrails or similar API key for full functionality
        """
        # Basic DNS lookup
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = None
        
        return {
            'domain': domain,
            'current_ip': ip,
            'a_records': [ip] if ip else [],
            'mx_records': [],
            'ns_records': [],
            'historical_ips': [],
            'subdomains': [],
            'note': 'Full history requires SecurityTrails API'
        }
    
    @staticmethod
    def subdomain_enumeration(domain: str, 
                              wordlist: Optional[List[str]] = None) -> List[str]:
        """
        Enumerate subdomains using wordlist
        
        Args:
            domain: Target domain
            wordlist: List of subdomain prefixes to try
        
        Returns:
            List of discovered subdomains
        """
        if wordlist is None:
            wordlist = [
                'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop',
                'dev', 'test', 'staging', 'vpn', 'remote', 'portal',
                'support', 'help', 'docs', 'wiki', 'forum', 'chat',
                'app', 'mobile', 'cdn', 'static', 'media', 'assets',
                'secure', 'login', 'auth', 'account', 'user', 'member',
                'dashboard', 'panel', 'control', 'manage', 'system'
            ]
        
        found = []
        
        for sub in wordlist:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                found.append(subdomain)
            except socket.gaierror:
                pass
        
        return found
    
    @staticmethod
    def port_scan(target: str, ports: List[int] = None) -> Dict[int, bool]:
        """
        Basic TCP port scan
        
        Args:
            target: Target IP or hostname
            ports: List of ports to scan
        
        Returns:
            Dictionary mapping port to open status
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 8080]
        
        results = {}
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            results[port] = (result == 0)
            sock.close()
        
        return results


# Hash verification utilities
class HashVerifier:
    """Cryptographic hash verification"""
    
    SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512', 'blake2b']
    
    @staticmethod
    def file_hash(filepath: str, algorithm: str = 'sha256') -> str:
        """Calculate file hash"""
        if algorithm not in HashVerifier.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hash_obj = hashlib.new(algorithm)
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    @staticmethod
    def verify_integrity(filepath: str, expected_hash: str,
                         algorithm: str = 'sha256') -> bool:
        """Verify file integrity against expected hash"""
        actual_hash = HashVerifier.file_hash(filepath, algorithm)
        return actual_hash.lower() == expected_hash.lower()
    
    @staticmethod
    def hash_string(data: str, algorithm: str = 'sha256') -> str:
        """Hash a string"""
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data.encode())
        return hash_obj.hexdigest()


async def demo():
    """Demonstration of OSINT framework capabilities"""
    print("=" * 60)
    print("OSINT AUTOMATION FRAMEWORK")
    print("=" * 60)
    
    async with OSINTFramework() as framework:
        print("\n1. Google Dork Generation")
        print("-" * 40)
        dorks = OSINTFramework.google_dork_generator('example.com', 'sensitive')
        for dork in dorks[:3]:
            print(f"  {dork}")
        
        print("\n2. Infrastructure Intelligence")
        print("-" * 40)
        infra = InfrastructureIntel()
        dns_info = infra.analyze_dns_history('google.com')
        print(f"  Domain: {dns_info['domain']}")
        print(f"  Current IP: {dns_info['current_ip']}")
        
        print("\n3. Academic Search (INSPIRE-HEP)")
        print("-" * 40)
        results = await framework.search_inspire('dark matter', max_results=3)
        for r in results:
            metadata = r.get('metadata', {})
            titles = metadata.get('titles', [{}])
            if titles:
                print(f"  - {titles[0].get('title', 'N/A')[:60]}...")
        
        print("\n4. arXiv Search")
        print("-" * 40)
        arxiv_results = await framework.search_arxiv('cat:hep-ex', max_results=3)
        for r in arxiv_results:
            print(f"  - {r.get('title', 'N/A')[:60]}...")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(demo())
