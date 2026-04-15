#!/usr/bin/env python3
"""
DNS over HTTPS (DoH) Discovery and Analysis Tool
Infrastructure reconnaissance through encrypted DNS channels

Features:
- DoH server discovery and validation
- DNSSEC verification
- Subdomain enumeration via DoH
- Certificate transparency correlation
- Infrastructure mapping

License: MIT
Version: 2.0 (April 2026)
"""

import asyncio
import aiohttp
import ssl
import json
import base64
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import hashlib


class DNSRecordType(Enum):
    """DNS record types"""
    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    CNAME = "CNAME"
    PTR = "PTR"
    SRV = "SRV"
    CAA = "CAA"
    DNSKEY = "DNSKEY"
    DS = "DS"


@dataclass
class DNSRecord:
    """DNS record structure"""
    name: str
    record_type: DNSRecordType
    ttl: int
    data: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'type': self.record_type.value,
            'ttl': self.ttl,
            'data': self.data,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class DoHServer:
    """DoH server configuration"""
    name: str
    url: str
    ips: List[str]
    supports_post: bool = True
    supports_get: bool = True
    dnssec: bool = False
    edns: bool = False
    last_tested: Optional[datetime] = None
    response_time_ms: Optional[float] = None
    reliability_score: float = 1.0


class DoHDiscovery:
    """
    DNS over HTTPS Discovery and Analysis
    
    Provides encrypted DNS resolution and infrastructure discovery
    capabilities through DoH endpoints.
    """
    
    # Known DoH providers
    DOH_PROVIDERS = [
        DoHServer(
            name="Cloudflare",
            url="https://cloudflare-dns.com/dns-query",
            ips=["1.1.1.1", "1.0.0.1"],
            dnssec=True,
            edns=True
        ),
        DoHServer(
            name="Cloudflare-Malware",
            url="https://security.cloudflare-dns.com/dns-query",
            ips=["1.1.1.2", "1.0.0.2"],
            dnssec=True,
            edns=True
        ),
        DoHServer(
            name="Google",
            url="https://dns.google/dns-query",
            ips=["8.8.8.8", "8.8.4.4"],
            dnssec=True,
            edns=True
        ),
        DoHServer(
            name="Quad9",
            url="https://dns.quad9.net/dns-query",
            ips=["9.9.9.9", "149.112.112.112"],
            dnssec=True,
            edns=True
        ),
        DoHServer(
            name="OpenDNS",
            url="https://doh.opendns.com/dns-query",
            ips=["208.67.222.222", "208.67.220.220"],
            dnssec=True,
            edns=True
        ),
        DoHServer(
            name="AdGuard",
            url="https://dns.adguard-dns.com/dns-query",
            ips=["94.140.14.14", "94.140.15.15"],
            dnssec=True,
            edns=True
        ),
        DoHServer(
            name="DNS.SB",
            url="https://doh.dns.sb/dns-query",
            ips=["185.222.222.222", "45.11.45.11"],
            dnssec=True,
            edns=True
        ),
        DoHServer(
            name="AliDNS",
            url="https://dns.alidns.com/dns-query",
            ips=["223.5.5.5", "223.6.6.6"],
            dnssec=True,
            edns=True
        ),
        DoHServer(
            name="DNSPod",
            url="https://doh.pub/dns-query",
            ips=["119.29.29.29"],
            dnssec=True,
            edns=True
        ),
        DoHServer(
            name="360DNS",
            url="https://doh.360.cn/dns-query",
            ips=["101.226.4.6", "218.30.118.6"],
            dnssec=True,
            edns=True
        ),
    ]
    
    def __init__(self, custom_servers: Optional[List[DoHServer]] = None):
        self.servers = self.DOH_PROVIDERS.copy()
        if custom_servers:
            self.servers.extend(custom_servers)
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.active_server: Optional[DoHServer] = None
        self.cache: Dict[str, Dict] = {}
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        # SSL context that allows us to inspect certificates
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'Accept': 'application/dns-json',
                'User-Agent': 'DoH-Discovery/2.0'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def test_servers(self) -> List[DoHServer]:
        """
        Test all DoH servers and rank by response time
        
        Returns:
            List of servers sorted by response time
        """
        results = []
        
        for server in self.servers:
            try:
                start = datetime.now()
                
                # Test with a simple query
                result = await self._query_doh(
                    server, 
                    "cloudflare.com", 
                    DNSRecordType.A
                )
                
                elapsed = (datetime.now() - start).total_seconds() * 1000
                
                server.last_tested = datetime.now()
                server.response_time_ms = elapsed
                server.reliability_score = 1.0 if result else 0.5
                
                results.append((server, elapsed))
                
            except Exception as e:
                server.reliability_score = 0.0
                results.append((server, float('inf')))
        
        # Sort by response time
        results.sort(key=lambda x: x[1])
        
        return [s for s, _ in results]
    
    async def _query_doh(self, server: DoHServer, name: str,
                        record_type: DNSRecordType) -> Optional[Dict]:
        """
        Query DoH server
        
        Args:
            server: DoH server to query
            name: Domain name to query
            record_type: Type of DNS record
        
        Returns:
            DNS response data
        """
        params = {
            'name': name,
            'type': record_type.value
        }
        
        try:
            async with self.session.get(
                server.url, 
                params=params,
                headers={'Accept': 'application/dns-json'}
            ) as response:
                if response.status == 200:
                    return await response.json()
        except Exception:
            pass
        
        return None
    
    async def resolve(self, name: str, record_type: DNSRecordType = DNSRecordType.A,
                     prefer_server: Optional[str] = None) -> List[DNSRecord]:
        """
        Resolve DNS name via DoH
        
        Args:
            name: Domain to resolve
            record_type: DNS record type
            prefer_server: Preferred server name
        
        Returns:
            List of DNS records
        """
        # Check cache
        cache_key = f"{name}:{record_type.value}"
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            if datetime.now().timestamp() - cache_entry['timestamp'] < 300:  # 5 min TTL
                return [DNSRecord(**r) for r in cache_entry['records']]
        
        # Select server
        servers = self.servers
        if prefer_server:
            servers = [s for s in servers if s.name == prefer_server] + \
                     [s for s in servers if s.name != prefer_server]
        
        # Try each server
        for server in servers:
            if server.reliability_score <= 0:
                continue
            
            result = await self._query_doh(server, name, record_type)
            
            if result and 'Answer' in result:
                records = []
                for answer in result['Answer']:
                    record = DNSRecord(
                        name=answer.get('name', name),
                        record_type=record_type,
                        ttl=answer.get('TTL', 300),
                        data=answer.get('data', '')
                    )
                    records.append(record)
                
                # Cache result
                self.cache[cache_key] = {
                    'timestamp': datetime.now().timestamp(),
                    'records': [r.to_dict() for r in records]
                }
                
                return records
        
        return []
    
    async def bulk_resolve(self, names: List[str],
                          record_type: DNSRecordType = DNSRecordType.A,
                          max_concurrent: int = 10) -> Dict[str, List[DNSRecord]]:
        """
        Resolve multiple names concurrently
        
        Args:
            names: List of domain names
            record_type: DNS record type
            max_concurrent: Maximum concurrent queries
        
        Returns:
            Dictionary mapping names to records
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def resolve_with_limit(name):
            async with semaphore:
                records = await self.resolve(name, record_type)
                return name, records
        
        tasks = [resolve_with_limit(name) for name in names]
        results = await asyncio.gather(*tasks)
        
        return dict(results)
    
    async def enumerate_subdomains(self, domain: str,
                                   wordlist: Optional[List[str]] = None,
                                   record_types: List[DNSRecordType] = None) -> Dict:
        """
        Enumerate subdomains via DoH
        
        Args:
            domain: Base domain
            wordlist: Subdomain prefixes to try
            record_types: DNS record types to query
        
        Returns:
            Dictionary of found subdomains
        """
        if wordlist is None:
            wordlist = self._default_wordlist()
        
        if record_types is None:
            record_types = [DNSRecordType.A, DNSRecordType.AAAA, DNSRecordType.CNAME]
        
        found = {}
        
        # Generate subdomain candidates
        candidates = [f"{sub}.{domain}" for sub in wordlist]
        
        # Query each candidate
        for candidate in candidates:
            for record_type in record_types:
                records = await self.resolve(candidate, record_type)
                
                if records:
                    if candidate not in found:
                        found[candidate] = {}
                    
                    found[candidate][record_type.value] = [r.to_dict() for r in records]
        
        return found
    
    def _default_wordlist(self) -> List[str]:
        """Default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop',
            'dev', 'test', 'staging', 'vpn', 'remote', 'portal',
            'support', 'help', 'docs', 'wiki', 'forum', 'chat',
            'app', 'mobile', 'cdn', 'static', 'media', 'assets',
            'secure', 'login', 'auth', 'account', 'user', 'member',
            'dashboard', 'panel', 'control', 'manage', 'system',
            'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop', 'imap',
            'webmail', 'email', 'exchange', 'owa', 'autodiscover',
            'git', 'svn', 'cvs', 'repo', 'repository', 'source',
            'ci', 'build', 'jenkins', 'gitlab', 'github', 'bitbucket',
            'monitor', 'nagios', 'zabbix', 'grafana', 'prometheus',
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
            'elastic', 'search', 'solr', 'kibana', 'logstash',
            'kube', 'k8s', 'kubernetes', 'docker', 'swarm',
            'promo', 'marketing', 'campaign', 'ads', 'analytics',
            'careers', 'jobs', 'hr', 'people', 'team', 'staff',
            'investors', 'ir', 'press', 'news', 'media', 'pr',
            'partners', 'affiliates', 'reseller', 'wholesale',
            'sandbox', 'demo', 'trial', 'beta', 'alpha', 'preview',
            'old', 'legacy', 'archive', 'backup', 'bak', 'copy',
            'test1', 'test2', 'dev1', 'dev2', 'stage', 'staging2',
            'internal', 'intranet', 'extranet', 'private', 'corp',
            'upload', 'download', 'files', 'storage', 's3', 'blob',
            'ws', 'websocket', 'socket', 'io', 'realtime', 'push',
            'graphql', 'rest', 'api-v1', 'api-v2', 'api-v3',
            'swagger', 'openapi', 'docs-api', 'developer', 'devs',
        ]
    
    async def get_dnssec_info(self, domain: str) -> Dict:
        """
        Get DNSSEC information for domain
        
        Args:
            domain: Domain to check
        
        Returns:
            DNSSEC status information
        """
        result = {
            'domain': domain,
            'dnssec_enabled': False,
            'records': {}
        }
        
        # Query DNSKEY records
        dnskey_records = await self.resolve(domain, DNSRecordType.DNSKEY)
        if dnskey_records:
            result['dnssec_enabled'] = True
            result['records']['DNSKEY'] = [r.to_dict() for r in dnskey_records]
        
        # Query DS records
        ds_records = await self.resolve(domain, DNSRecordType.DS)
        if ds_records:
            result['records']['DS'] = [r.to_dict() for r in ds_records]
        
        return result
    
    async def get_spf_dmarc(self, domain: str) -> Dict:
        """
        Get SPF and DMARC records
        
        Args:
            domain: Domain to check
        
        Returns:
            Email security configuration
        """
        result = {
            'domain': domain,
            'spf': None,
            'dmarc': None,
            'dkim': None
        }
        
        # Query TXT records for SPF
        txt_records = await self.resolve(domain, DNSRecordType.TXT)
        
        for record in txt_records:
            data = record.data.strip('"')
            
            if data.startswith('v=spf1'):
                result['spf'] = {
                    'record': data,
                    'parsed': self._parse_spf(data)
                }
            
            if data.startswith('v=DMARC'):
                result['dmarc'] = {
                    'record': data,
                    'parsed': self._parse_dmarc(data)
                }
        
        # Check for DKIM selectors
        dkim_selectors = ['default', 'google', 'mail', 'dkim', 'selector1', 'selector2']
        for selector in dkim_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dkim_records = await self.resolve(dkim_domain, DNSRecordType.TXT)
            
            if dkim_records:
                result['dkim'] = {
                    'selector': selector,
                    'records': [r.to_dict() for r in dkim_records]
                }
                break
        
        return result
    
    def _parse_spf(self, record: str) -> Dict:
        """Parse SPF record"""
        mechanisms = record.split()
        
        parsed = {
            'version': None,
            'mechanisms': [],
            'modifiers': {},
            'all_mechanism': None
        }
        
        for mech in mechanisms:
            if mech.startswith('v='):
                parsed['version'] = mech
            elif mech in ['+all', '-all', '~all', '?all']:
                parsed['all_mechanism'] = mech
            elif ':' in mech:
                key, value = mech.split(':', 1)
                parsed['mechanisms'].append({key: value})
            else:
                parsed['mechanisms'].append(mech)
        
        return parsed
    
    def _parse_dmarc(self, record: str) -> Dict:
        """Parse DMARC record"""
        tags = {}
        
        for tag in record.split(';'):
            tag = tag.strip()
            if '=' in tag:
                key, value = tag.split('=', 1)
                tags[key.strip()] = value.strip()
        
        return {
            'version': tags.get('v'),
            'policy': tags.get('p'),
            'subdomain_policy': tags.get('sp'),
            'percentage': tags.get('pct'),
            'report_uri': tags.get('rua'),
            'failure_report_uri': tags.get('ruf'),
            'adkim': tags.get('adkim'),
            'aspf': tags.get('aspf')
        }
    
    async def discover_infrastructure(self, domain: str) -> Dict:
        """
        Comprehensive infrastructure discovery
        
        Args:
            domain: Domain to analyze
        
        Returns:
            Complete infrastructure map
        """
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'dns_records': {},
            'subdomains': {},
            'dnssec': {},
            'email_security': {},
            'infrastructure': {}
        }
        
        # Get all DNS record types
        record_types = [
            DNSRecordType.A, DNSRecordType.AAAA, DNSRecordType.MX,
            DNSRecordType.NS, DNSRecordType.TXT, DNSRecordType.SOA,
            DNSRecordType.CNAME
        ]
        
        for record_type in record_types:
            records = await self.resolve(domain, record_type)
            if records:
                result['dns_records'][record_type.value] = [r.to_dict() for r in records]
        
        # Enumerate subdomains
        result['subdomains'] = await self.enumerate_subdomains(domain)
        
        # Get DNSSEC info
        result['dnssec'] = await self.get_dnssec_info(domain)
        
        # Get email security
        result['email_security'] = await self.get_spf_dmarc(domain)
        
        # Extract infrastructure insights
        result['infrastructure'] = self._analyze_infrastructure(result)
        
        return result
    
    def _analyze_infrastructure(self, data: Dict) -> Dict:
        """Analyze infrastructure data for insights"""
        analysis = {
            'hosting_providers': [],
            'cdn_detected': False,
            'email_providers': [],
            'name_servers': [],
            'security_features': []
        }
        
        # Check for CDN
        cdn_signatures = {
            'cloudflare': ['cloudflare', 'cf-dns'],
            'akamai': ['akamai', 'akadns'],
            'fastly': ['fastly'],
            'cloudfront': ['cloudfront'],
            'maxcdn': ['maxcdn'],
        }
        
        # Analyze NS records
        ns_records = data.get('dns_records', {}).get('NS', [])
        for ns in ns_records:
            ns_data = ns.get('data', '').lower()
            analysis['name_servers'].append(ns_data)
            
            for cdn, signatures in cdn_signatures.items():
                if any(sig in ns_data for sig in signatures):
                    analysis['cdn_detected'] = True
                    analysis['hosting_providers'].append(cdn)
        
        # Analyze MX records
        mx_records = data.get('dns_records', {}).get('MX', [])
        for mx in mx_records:
            mx_data = mx.get('data', '').lower()
            
            email_providers = {
                'google': ['google', 'gmail', 'googlemail'],
                'microsoft': ['outlook', 'office365', 'microsoft'],
                'zoho': ['zoho'],
                'protonmail': ['protonmail'],
            }
            
            for provider, signatures in email_providers.items():
                if any(sig in mx_data for sig in signatures):
                    analysis['email_providers'].append(provider)
        
        # Check security features
        email_sec = data.get('email_security', {})
        if email_sec.get('spf'):
            analysis['security_features'].append('SPF')
        if email_sec.get('dmarc'):
            analysis['security_features'].append('DMARC')
        if email_sec.get('dkim'):
            analysis['security_features'].append('DKIM')
        
        dnssec = data.get('dnssec', {})
        if dnssec.get('dnssec_enabled'):
            analysis['security_features'].append('DNSSEC')
        
        return analysis


# Certificate Transparency Monitor
class CTMonitor:
    """Monitor Certificate Transparency logs"""
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def query_crtsh(self, domain: str) -> List[Dict]:
        """
        Query crt.sh for certificates
        
        Args:
            domain: Domain to query
        
        Returns:
            List of certificate entries
        """
        url = f"https://crt.sh/?q={domain}&output=json"
        
        try:
            async with self.session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    certificates = []
                    for cert in data:
                        cert_info = {
                            'id': cert.get('id'),
                            'issuer': cert.get('issuer_name'),
                            'common_name': cert.get('common_name'),
                            'name_value': cert.get('name_value'),
                            'not_before': cert.get('not_before'),
                            'not_after': cert.get('not_after'),
                            'serial_number': cert.get('serial_number'),
                            'issuer_ca_id': cert.get('issuer_ca_id')
                        }
                        certificates.append(cert_info)
                    
                    return certificates
        except Exception as e:
            return [{'error': str(e)}]
        
        return []
    
    async def get_subdomains_from_ct(self, domain: str) -> Set[str]:
        """
        Extract subdomains from Certificate Transparency logs
        
        Args:
            domain: Domain to analyze
        
        Returns:
            Set of discovered subdomains
        """
        certificates = await self.query_crtsh(domain)
        
        subdomains = set()
        
        for cert in certificates:
            if 'error' in cert:
                continue
            
            name_value = cert.get('name_value', '')
            
            # Parse name_value (can contain multiple domains separated by newlines)
            for name in name_value.split('\n'):
                name = name.strip()
                
                # Check if it's a subdomain of our target
                if name.endswith(f'.{domain}') or name == domain:
                    subdomains.add(name)
        
        return subdomains


async def demo():
    """Demonstration of DoH discovery tool"""
    print("=" * 70)
    print("DNS OVER HTTPS (DoH) DISCOVERY TOOL")
    print("=" * 70)
    
    async with DoHDiscovery() as doh:
        # 1. Test DoH servers
        print("\n1. Testing DoH Servers")
        print("-" * 50)
        
        ranked_servers = await doh.test_servers()
        print("Server rankings by response time:")
        for i, server in enumerate(ranked_servers[:5], 1):
            status = "✓" if server.response_time_ms else "✗"
            time_str = f"{server.response_time_ms:.0f}ms" if server.response_time_ms else "FAILED"
            print(f"  {status} {i}. {server.name}: {time_str}")
        
        # 2. Resolve domain
        print("\n2. DNS Resolution (cloudflare.com)")
        print("-" * 50)
        
        records = await doh.resolve('cloudflare.com', DNSRecordType.A)
        print(f"A records:")
        for record in records:
            print(f"  {record.data} (TTL: {record.ttl})")
        
        # 3. DNSSEC check
        print("\n3. DNSSEC Verification (cloudflare.com)")
        print("-" * 50)
        
        dnssec_info = await doh.get_dnssec_info('cloudflare.com')
        print(f"DNSSEC enabled: {dnssec_info['dnssec_enabled']}")
        
        # 4. Email security
        print("\n4. Email Security (gmail.com)")
        print("-" * 50)
        
        email_sec = await doh.get_spf_dmarc('gmail.com')
        print(f"SPF: {'✓' if email_sec['spf'] else '✗'}")
        print(f"DMARC: {'✓' if email_sec['dmarc'] else '✗'}")
        print(f"DKIM: {'✓' if email_sec['dkim'] else '✗'}")
        
        # 5. Subdomain enumeration (limited)
        print("\n5. Subdomain Enumeration (example.com)")
        print("-" * 50)
        
        subdomains = await doh.enumerate_subdomains(
            'example.com',
            wordlist=['www', 'mail', 'ftp', 'api', 'test']
        )
        print(f"Found {len(subdomains)} subdomains")
        for subdomain in list(subdomains.keys())[:5]:
            print(f"  {subdomain}")
    
    # 6. Certificate Transparency
    print("\n6. Certificate Transparency (cloudflare.com)")
    print("-" * 50)
    
    async with CTMonitor() as ct:
        subdomains = await ct.get_subdomains_from_ct('cloudflare.com')
        print(f"Found {len(subdomains)} subdomains in CT logs")
        for subdomain in list(subdomains)[:5]:
            print(f"  {subdomain}")
    
    print("\n" + "=" * 70)
    print("DoH Discovery Tool Ready")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(demo())
