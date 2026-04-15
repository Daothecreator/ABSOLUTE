#!/usr/bin/env python3
"""
Government and Open Data Integration Module
Access to public datasets, government reports, and official records

Features:
- Multi-country government data access
- Corporate registry lookups
- Patent and trademark databases
- Legislative and regulatory tracking
- Environmental and safety data
- Procurement and contract databases

License: MIT
Version: 2.0 (April 2026)
"""

import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import xml.etree.ElementTree as ET


class GovernmentDataType(Enum):
    """Types of government data"""
    CORPORATE_REGISTRY = "corporate_registry"
    PATENT = "patent_database"
    TRADEMARK = "trademark_database"
    LEGISLATION = "legislation"
    REGULATION = "regulation"
    PROCUREMENT = "procurement"
    ENVIRONMENTAL = "environmental"
    SAFETY = "safety"
    TAX = "tax_record"
    POLITICAL = "political_contribution"
    LOBBYING = "lobbying"
    FOIA = "foia_release"


@dataclass
class GovernmentRecord:
    """Government record structure"""
    record_type: GovernmentDataType
    source: str
    country: str
    data: Dict
    retrieved_at: datetime = field(default_factory=datetime.now)
    confidence: float = 0.8


class GovernmentDataIntegration:
    """
    Government and Open Data Integration
    
    Provides unified access to public government datasets
    across multiple jurisdictions.
    """
    
    # API endpoints for various government data sources
    ENDPOINTS = {
        # United States
        'us_sec': 'https://www.sec.gov/Archives/edgar/daily-index/',
        'us_uspto': 'https://developer.uspto.gov/api/v1/',
        'us_fec': 'https://api.open.fec.gov/v1/',
        'us_regulations': 'https://www.federalregister.gov/api/v1/',
        'us_congress': 'https://api.congress.gov/v3/',
        'us_sam': 'https://sam.gov/api/prod/opportunities/v1/',
        'us_census': 'https://api.census.gov/data/',
        'us_epa': 'https://enviro.epa.gov/enviro/efservice/',
        
        # European Union
        'eu_opendata': 'https://data.europa.eu/api/hub/search/',
        'eu_epo': 'https://ops.epo.org/3.2/rest-services/',
        'eu_europarl': 'https://www.europarl.europa.eu/doceo/document/',
        'eu_ted': 'https://ted.europa.eu/api/v2.0/',
        
        # United Kingdom
        'uk_companies': 'https://api.company-information.service.gov.uk/',
        'uk_legislation': 'https://www.legislation.gov.uk/id/',
        
        # Canada
        'ca_opendata': 'https://open.canada.ca/data/en/api/3/',
        'ca_ic': 'https://www.ic.gc.ca/app/scr/cc/CorporationsCanada/',
        
        # Australia
        'au_asx': 'https://www.asx.com.au/asx/1/',
        'au_abr': 'https://abr.business.gov.au/json/',
        
        # International
        'worldbank': 'https://api.worldbank.org/v2/',
        'un_data': 'https://data.un.org/ws/rest/',
        'opencorporates': 'https://api.opencorporates.com/v0.4/',
        'opencollective': 'https://api.opencollective.com/graphql/v2/',
    }
    
    def __init__(self, api_keys: Optional[Dict] = None):
        self.api_keys = api_keys or {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.cache: Dict[str, Dict] = {}
        self.rate_limiters: Dict[str, asyncio.Semaphore] = {}
        
        # Initialize rate limiters
        for source in self.ENDPOINTS:
            self.rate_limiters[source] = asyncio.Semaphore(5)
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=60)
        
        headers = {
            'User-Agent': 'GovData-Integration/2.0 (Research Project)',
            'Accept': 'application/json'
        }
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _query(self, endpoint_key: str, path: str = '',
                     params: Optional[Dict] = None,
                     headers: Optional[Dict] = None) -> Optional[Dict]:
        """
        Query government API endpoint
        
        Args:
            endpoint_key: Key from ENDPOINTS dict
            path: API path
            params: Query parameters
            headers: Additional headers
        
        Returns:
            API response data
        """
        if endpoint_key not in self.ENDPOINTS:
            return None
        
        url = f"{self.ENDPOINTS[endpoint_key]}{path}"
        
        async with self.rate_limiters[endpoint_key]:
            try:
                request_headers = {}
                if headers:
                    request_headers.update(headers)
                
                async with self.session.get(
                    url, 
                    params=params,
                    headers=request_headers
                ) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '')
                        
                        if 'application/json' in content_type:
                            return await response.json()
                        else:
                            text = await response.text()
                            return {'text_content': text}
                    
                    elif response.status == 429:
                        # Rate limited
                        await asyncio.sleep(5)
                        return await self._query(endpoint_key, path, params, headers)
                    
                    else:
                        return {'error': f'HTTP {response.status}'}
            
            except Exception as e:
                return {'error': str(e)}
        
        return None
    
    # US SEC EDGAR
    async def search_sec_filings(self, cik: Optional[str] = None,
                                  ticker: Optional[str] = None,
                                  filing_type: Optional[str] = None) -> Dict:
        """
        Search SEC EDGAR filings
        
        Args:
            cik: Company CIK number
            ticker: Stock ticker symbol
            filing_type: Filing type (10-K, 10-Q, etc.)
        
        Returns:
            Filing information
        """
        # SEC requires specific User-Agent
        headers = {
            'User-Agent': 'Research Project contact@research.local'
        }
        
        if cik:
            # Get company filings
            url = f"https://data.sec.gov/submissions/CIK{cik.zfill(10)}.json"
            
            try:
                async with self.session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
            except Exception as e:
                return {'error': str(e)}
        
        return {'error': 'CIK or ticker required'}
    
    async def get_company_facts(self, cik: str) -> Dict:
        """Get company facts from SEC"""
        headers = {
            'User-Agent': 'Research Project contact@research.local'
        }
        
        url = f"https://data.sec.gov/api/xbrl/companyfacts/CIK{cik.zfill(10)}.json"
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            return {'error': str(e)}
        
        return {}
    
    # USPTO Patents
    async def search_patents(self, query: str, limit: int = 10) -> List[Dict]:
        """
        Search USPTO patent database
        
        Args:
            query: Search query
            limit: Maximum results
        
        Returns:
            List of patent records
        """
        # Use PatentsView API
        url = "https://api.patentsview.org/patents/query"
        
        data = {
            'q': {'_text_any': {'patent_title': query}},
            'f': ['patent_number', 'patent_title', 'patent_date', 
                  'inventor_first_name', 'inventor_last_name', 'assignee_organization'],
            'o': {'per_page': limit}
        }
        
        try:
            async with self.session.post(url, json=data) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get('patents', [])
        except Exception as e:
            return [{'error': str(e)}]
        
        return []
    
    # OpenCorporates
    async def search_companies(self, name: str, 
                               jurisdiction: Optional[str] = None) -> List[Dict]:
        """
        Search OpenCorporates database
        
        Args:
            name: Company name
            jurisdiction: Country/jurisdiction code
        
        Returns:
            List of company records
        """
        params = {
            'q': name,
            'format': 'json'
        }
        
        if jurisdiction:
            params['jurisdiction_code'] = jurisdiction
        
        result = await self._query('opencorporates', 'companies/search', params)
        
        if result and 'results' in result:
            return result['results'].get('companies', [])
        
        return []
    
    async def get_company_details(self, jurisdiction: str, 
                                   company_number: str) -> Dict:
        """
        Get detailed company information
        
        Args:
            jurisdiction: Jurisdiction code
            company_number: Company registration number
        
        Returns:
            Company details
        """
        path = f"companies/{jurisdiction}/{company_number}"
        result = await self._query('opencorporates', path, {'format': 'json'})
        
        if result and 'results' in result:
            return result['results'].get('company', {})
        
        return {}
    
    # UK Companies House
    async def search_uk_companies(self, name: str, 
                                   api_key: Optional[str] = None) -> List[Dict]:
        """
        Search UK Companies House
        
        Args:
            name: Company name
            api_key: Companies House API key
        
        Returns:
            List of company records
        """
        key = api_key or self.api_keys.get('uk_companies_house')
        
        if not key:
            return [{'error': 'API key required'}]
        
        headers = {
            'Authorization': f'Basic {key}'
        }
        
        params = {
            'q': name,
            'items_per_page': 20
        }
        
        result = await self._query('uk_companies', 'search/companies', params, headers)
        
        if result:
            return result.get('items', [])
        
        return []
    
    # Federal Register
    async def search_federal_register(self, query: str,
                                       document_type: Optional[str] = None,
                                       agency: Optional[str] = None,
                                       date_range: Optional[tuple] = None) -> List[Dict]:
        """
        Search Federal Register
        
        Args:
            query: Search query
            document_type: Type of document
            agency: Agency code
            date_range: (start_date, end_date) tuple
        
        Returns:
            List of documents
        """
        params = {
            'conditions[term]': query,
            'per_page': 20,
            'format': 'json'
        }
        
        if document_type:
            params['conditions[type][]'] = document_type
        
        if agency:
            params['conditions[agencies][]'] = agency
        
        if date_range:
            params['conditions[publication_date][gte]'] = date_range[0]
            params['conditions[publication_date][lte]'] = date_range[1]
        
        result = await self._query('us_regulations', 'documents.json', params)
        
        if result:
            return result.get('results', [])
        
        return []
    
    # Congress API
    async def get_legislation(self, congress: int, 
                              bill_type: Optional[str] = None,
                              bill_number: Optional[int] = None) -> List[Dict]:
        """
        Get legislation from Congress API
        
        Args:
            congress: Congress number
            bill_type: Type of bill (hr, s, etc.)
            bill_number: Bill number
        
        Returns:
            List of bills
        """
        api_key = self.api_keys.get('congress_api')
        
        if not api_key:
            return [{'error': 'Congress API key required'}]
        
        path = f"bill/{congress}"
        
        if bill_type:
            path += f"/{bill_type}"
        
        if bill_number:
            path += f"/{bill_number}"
        
        params = {
            'api_key': api_key,
            'format': 'json',
            'limit': 20
        }
        
        result = await self._query('us_congress', path, params)
        
        if result:
            return result.get('bills', [])
        
        return []
    
    # FEC Campaign Finance
    async def search_fec_candidates(self, name: str,
                                     office: Optional[str] = None,
                                     party: Optional[str] = None) -> List[Dict]:
        """
        Search FEC candidate database
        
        Args:
            name: Candidate name
            office: Office sought (P, S, H)
            party: Party affiliation
        
        Returns:
            List of candidates
        """
        api_key = self.api_keys.get('fec_api')
        
        params = {
            'q': name,
            'per_page': 20
        }
        
        if office:
            params['office'] = office
        
        if party:
            params['party'] = party
        
        if api_key:
            params['api_key'] = api_key
        
        result = await self._query('us_fec', 'candidates/search/', params)
        
        if result:
            return result.get('results', [])
        
        return []
    
    async def get_candidate_financials(self, candidate_id: str,
                                        cycle: Optional[int] = None) -> Dict:
        """
        Get candidate financial information
        
        Args:
            candidate_id: FEC candidate ID
            cycle: Election cycle
        
        Returns:
            Financial data
        """
        api_key = self.api_keys.get('fec_api')
        
        path = f"candidate/{candidate_id}/"
        
        params = {}
        if cycle:
            params['cycle'] = cycle
        
        if api_key:
            params['api_key'] = api_key
        
        return await self._query('us_fec', path, params) or {}
    
    # World Bank Data
    async def get_worldbank_indicator(self, indicator: str,
                                       country: str = 'all',
                                       date_range: Optional[str] = None) -> List[Dict]:
        """
        Get World Bank indicator data
        
        Args:
            indicator: Indicator code
            country: Country code or 'all'
            date_range: Date range (e.g., '2010:2020')
        
        Returns:
            Indicator data
        """
        path = f"country/{country}/indicator/{indicator}"
        
        params = {
            'format': 'json',
            'per_page': 100
        }
        
        if date_range:
            params['date'] = date_range
        
        result = await self._query('worldbank', path, params)
        
        if result and len(result) > 1:
            return result[1]  # World Bank returns metadata in first element
        
        return []
    
    async def search_worldbank_indicators(self, query: str) -> List[Dict]:
        """Search World Bank indicators"""
        path = "indicator"
        
        params = {
            'format': 'json',
            'per_page': 20
        }
        
        # World Bank doesn't support direct search, so we filter
        result = await self._query('worldbank', path, params)
        
        if result and len(result) > 1:
            indicators = result[1]
            # Filter by query
            return [
                i for i in indicators 
                if query.lower() in i.get('name', '').lower() or
                   query.lower() in i.get('id', '').lower()
            ][:20]
        
        return []
    
    # EPA Environmental Data
    async def search_epa_facilities(self, name: Optional[str] = None,
                                     zip_code: Optional[str] = None,
                                     state: Optional[str] = None) -> List[Dict]:
        """
        Search EPA facility registry
        
        Args:
            name: Facility name
            zip_code: ZIP code
            state: State code
        
        Returns:
            List of facilities
        """
        params = {}
        
        if name:
            params['fac_name'] = name
        
        if zip_code:
            params['postal_code'] = zip_code
        
        if state:
            params['state_code'] = state
        
        result = await self._query('us_epa', 'FACILITY/', params)
        
        return result if isinstance(result, list) else []
    
    # Data correlation and analysis
    def correlate_records(self, records: List[GovernmentRecord]) -> Dict:
        """
        Correlate government records to find connections
        
        Args:
            records: List of government records
        
        Returns:
            Correlation analysis
        """
        correlations = {
            'by_company': {},
            'by_person': {},
            'by_location': {},
            'by_date': {},
            'cross_references': []
        }
        
        for record in records:
            data = record.data
            
            # Extract company names
            company_names = self._extract_company_names(data)
            for name in company_names:
                if name not in correlations['by_company']:
                    correlations['by_company'][name] = []
                correlations['by_company'][name].append(record)
            
            # Extract person names
            person_names = self._extract_person_names(data)
            for name in person_names:
                if name not in correlations['by_person']:
                    correlations['by_person'][name] = []
                correlations['by_person'][name].append(record)
        
        # Find cross-references
        for company, company_records in correlations['by_company'].items():
            if len(company_records) > 1:
                correlations['cross_references'].append({
                    'type': 'company',
                    'value': company,
                    'record_count': len(company_records),
                    'record_types': list(set(r.record_type.value for r in company_records))
                })
        
        return correlations
    
    def _extract_company_names(self, data: Dict) -> Set[str]:
        """Extract company names from record data"""
        names = set()
        
        # Common field names for companies
        company_fields = [
            'company_name', 'name', 'organization', 'assignee_organization',
            'filer', 'registrant', 'contractor', 'vendor'
        ]
        
        for field in company_fields:
            if field in data and data[field]:
                if isinstance(data[field], str):
                    names.add(data[field])
                elif isinstance(data[field], list):
                    names.update(data[field])
        
        return names
    
    def _extract_person_names(self, data: Dict) -> Set[str]:
        """Extract person names from record data"""
        names = set()
        
        # Common field names for people
        person_fields = [
            'inventor_first_name', 'inventor_last_name', 'officer',
            'director', 'signatory', 'lobbyist', 'candidate_name'
        ]
        
        for field in person_fields:
            if field in data and data[field]:
                if isinstance(data[field], str):
                    names.add(data[field])
                elif isinstance(data[field], list):
                    names.update(data[field])
        
        return names
    
    # Report generation
    def generate_compliance_report(self, company_name: str,
                                    records: List[GovernmentRecord]) -> Dict:
        """
        Generate compliance report for a company
        
        Args:
            company_name: Company name
            records: Related government records
        
        Returns:
            Compliance report
        """
        report = {
            'company': company_name,
            'generated_at': datetime.now().isoformat(),
            'record_summary': {},
            'regulatory_exposure': [],
            'political_activity': {},
            'intellectual_property': {},
            'recommendations': []
        }
        
        # Summarize records by type
        for record in records:
            record_type = record.record_type.value
            if record_type not in report['record_summary']:
                report['record_summary'][record_type] = 0
            report['record_summary'][record_type] += 1
        
        # Identify regulatory exposure
        if GovernmentDataType.SAFETY in [r.record_type for r in records]:
            report['regulatory_exposure'].append('Safety violations found')
        
        if GovernmentDataType.ENVIRONMENTAL in [r.record_type for r in records]:
            report['regulatory_exposure'].append('Environmental compliance issues')
        
        # Analyze political activity
        fec_records = [r for r in records if r.record_type == GovernmentDataType.POLITICAL]
        if fec_records:
            report['political_activity']['contributions_found'] = len(fec_records)
        
        return report


async def demo():
    """Demonstration of government data integration"""
    print("=" * 70)
    print("GOVERNMENT AND OPEN DATA INTEGRATION")
    print("=" * 70)
    
    async with GovernmentDataIntegration() as gov:
        # 1. Search OpenCorporates
        print("\n1. Company Search (OpenCorporates)")
        print("-" * 50)
        
        companies = await gov.search_companies("Apple", jurisdiction='us_de')
        print(f"Found {len(companies)} companies")
        for company in companies[:3]:
            c = company.get('company', {})
            print(f"  {c.get('name')} ({c.get('jurisdiction_code')})")
        
        # 2. Search patents
        print("\n2. Patent Search (USPTO)")
        print("-" * 50)
        
        patents = await gov.search_patents("artificial intelligence", limit=5)
        print(f"Found {len(patents)} patents")
        for patent in patents[:3]:
            p = patent.get('patent_title', 'N/A')
            print(f"  {p[:60]}...")
        
        # 3. Federal Register search
        print("\n3. Federal Register Search")
        print("-" * 50)
        
        documents = await gov.search_federal_register(
            "cybersecurity",
            agency="DHS"
        )
        print(f"Found {len(documents)} documents")
        for doc in documents[:3]:
            print(f"  {doc.get('title', 'N/A')[:60]}...")
        
        # 4. World Bank data
        print("\n4. World Bank Indicator")
        print("-" * 50)
        
        indicators = await gov.get_worldbank_indicator(
            'NY.GDP.MKTP.CD',  # GDP (current US$)
            country='US',
            date_range='2020:2023'
        )
        print(f"Found {len(indicators)} data points")
        for ind in indicators[:3]:
            print(f"  {ind.get('date')}: ${float(ind.get('value', 0))/1e12:.2f}T")
    
    print("\n" + "=" * 70)
    print("Government Data Integration Ready")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(demo())
