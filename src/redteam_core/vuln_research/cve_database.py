"""
CVE Database

Interface to CVE databases for vulnerability research.
"""

import json
import requests
import sqlite3
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path


@dataclass
class CVE:
    """Represents a CVE entry"""
    cve_id: str
    published_date: datetime
    last_modified_date: datetime
    description: str
    cvss_score: float
    cvss_vector: str
    cvss_severity: str
    affected_software: List[Dict[str, Any]]
    references: List[str]
    weakneses: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'cve_id': self.cve_id,
            'published_date': self.published_date.isoformat(),
            'last_modified_date': self.last_modified_date.isoformat(),
            'description': self.description,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cvss_severity': self.cvss_severity,
            'affected_software': self.affected_software,
            'references': self.references,
            'weakneses': self.weakneses
        }


@dataclass
class CVEQuery:
    """Represents a CVE query"""
    keyword: Optional[str] = None
    cvss_score_min: Optional[float] = None
    cvss_score_max: Optional[float] = None
    cvss_severity: Optional[str] = None
    published_after: Optional[datetime] = None
    published_before: Optional[datetime] = None
    last_modified_after: Optional[datetime] = None
    cpe: Optional[str] = None
    limit: int = 100
    
    def to_dict(self) -> Dict[str, Any]:
        result = {}
        if self.keyword:
            result['keyword'] = self.keyword
        if self.cvss_score_min is not None:
            result['cvssScoreMin'] = self.cvss_score_min
        if self.cvss_score_max is not None:
            result['cvssScoreMax'] = self.cvss_score_max
        if self.cvss_severity:
            result['cvssSeverity'] = self.cvss_severity
        if self.published_after:
            result['publishedAfter'] = self.published_after.isoformat()
        if self.published_before:
            result['publishedBefore'] = self.published_before.isoformat()
        if self.last_modified_after:
            result['lastModifiedAfter'] = self.last_modified_after.isoformat()
        if self.cpe:
            result['cpe'] = self.cpe
        result['limit'] = self.limit
        return result


class CVEDatabase:
    """
    Interface to CVE databases for vulnerability research.
    
    Supports:
    - NVD (National Vulnerability Database) API
    - Local SQLite cache
    - CVE searching and filtering
    - CVSS scoring
    - CPE matching
    
    Usage:
    >>> db = CVEDatabase()
    >>> cves = db.search(CVEQuery(
    ...     keyword='log4j',
    ...     cvss_score_min=7.0,
    ...     limit=10
    ... ))
    >>> for cve in cves:
    ...     print(f"{cve.cve_id}: {cve.description}")
    """
    
    def __init__(self, cache_path: str = ".cve_cache.db"):
        """
        Initialize the CVE database.
        
        Args:
            cache_path: Path to SQLite cache database
        """
        self.cache_path = Path(cache_path)
        self._initialize_cache()
        self.api_key = None  # NVD API key (optional)
    
    def _initialize_cache(self):
        """Initialize the SQLite cache database"""
        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    published_date TEXT NOT NULL,
                    last_modified_date TEXT NOT NULL,
                    description TEXT NOT NULL,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    cvss_severity TEXT,
                    references TEXT NOT NULL,
                    weakneses TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    last_updated TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS affected_software (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    cpe TEXT NOT NULL,
                    vendor TEXT,
                    product TEXT,
                    version TEXT,
                    version_end_excluding TEXT,
                    version_end_including TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_score)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_affected_cpe ON affected_software(cpe)
            ''')
            
            conn.commit()
    
    def set_api_key(self, api_key: str):
        """Set NVD API key for higher rate limits"""
        self.api_key = api_key
    
    def search(self, query: CVEQuery) -> List[CVE]:
        """
        Search for CVEs matching the query.
        
        Args:
            query: CVE query parameters
            
        Returns:
            List[CVE]: List of matching CVEs
        """
        # First, try to get from cache
        cached_cves = self._search_cache(query)
        if cached_cves:
            return cached_cves
        
        # If not in cache or cache is stale, fetch from NVD
        nvd_cves = self._fetch_from_nvd(query)
        
        # Cache the results
        if nvd_cves:
            self._cache_cves(nvd_cves)
        
        return nvd_cves
    
    def _search_cache(self, query: CVEQuery) -> List[CVE]:
        """Search the local cache"""
        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()
            
            # Build query
            sql = "SELECT * FROM cves WHERE 1=1"
            params = []
            
            if query.keyword:
                sql += " AND (description LIKE ? OR cve_id LIKE ?)"
                keyword_param = f"%{query.keyword}%"
                params.extend([keyword_param, keyword_param])
            
            if query.cvss_score_min is not None:
                sql += " AND cvss_score >= ?"
                params.append(query.cvss_score_min)
            
            if query.cvss_score_max is not None:
                sql += " AND cvss_score <= ?"
                params.append(query.cvss_score_max)
            
            if query.cvss_severity:
                sql += " AND cvss_severity = ?"
                params.append(query.cvss_severity)
            
            if query.published_after:
                sql += " AND published_date >= ?"
                params.append(query.published_after.isoformat())
            
            if query.published_before:
                sql += " AND published_date <= ?"
                params.append(query.published_before.isoformat())
            
            if query.last_modified_after:
                sql += " AND last_modified_date >= ?"
                params.append(query.last_modified_after.isoformat())
            
            sql += " ORDER BY published_date DESC LIMIT ?"
            params.append(query.limit)
            
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            
            cves = []
            for row in rows:
                cve = self._row_to_cve(row)
                
                # Filter by CPE if specified
                if query.cpe:
                    affected = self._get_affected_software(row[0])
                    if not any(query.cpe in cpe for cpe in affected):
                        continue
                
                cves.append(cve)
            
            return cves
    
    def _fetch_from_nvd(self, query: CVEQuery) -> List[CVE]:
        """Fetch CVEs from NVD API"""
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Build query parameters
        params = {}
        
        if query.keyword:
            params['keywordSearch'] = query.keyword
        
        if query.cvss_score_min is not None or query.cvss_score_max is not None:
            cvss_range = ""
            if query.cvss_score_min is not None:
                cvss_range += f"{query.cvss_score_min}"
            cvss_range += "-"
            if query.cvss_score_max is not None:
                cvss_range += f"{query.cvss_score_max}"
            else:
                cvss_range += "10.0"
            params['cvssV3Score'] = cvss_range
        
        if query.cvss_severity:
            params['cvssV3Severity'] = query.cvss_severity
        
        if query.published_after:
            params['pubStartDate'] = query.published_after.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
        
        if query.published_before:
            params['pubEndDate'] = query.published_before.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
        
        if query.last_modified_after:
            params['modStartDate'] = query.last_modified_after.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
        
        params['resultsPerPage'] = min(query.limit, 2000)
        
        # Add API key if available
        headers = {}
        if self.api_key:
            headers['api-key'] = self.api_key
        
        try:
            response = requests.get(base_url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for item in data.get('vulnerabilities', []):
                cve_data = item.get('cve', {})
                cve = self._parse_nvd_cve(cve_data)
                if cve:
                    cves.append(cve)
            
            return cves
            
        except Exception as e:
            print(f"Error fetching from NVD: {e}")
            return []
    
    def _parse_nvd_cve(self, cve_data: Dict[str, Any]) -> Optional[CVE]:
        """Parse NVD CVE data"""
        try:
            cve_id = cve_data.get('id', '')
            
            # Parse dates
            published_date = self._parse_nvd_date(cve_data.get('published'))
            last_modified_date = self._parse_nvd_date(cve_data.get('lastModified'))
            
            # Get description
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS
            metrics = cve_data.get('metrics', {})
            cvss_metrics = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
            cvss_data = cvss_metrics.get('cvssData', {})
            
            cvss_score = cvss_data.get('baseScore', 0.0)
            cvss_vector = cvss_data.get('vectorString', '')
            cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            
            # Get references
            references = []
            for ref in cve_data.get('references', []):
                references.append(ref.get('url', ''))
            
            # Get weaknesses (CWE)
            weaknesses = []
            for weakness in cve_data.get('weaknesses', []):
                weaknesses.append({
                    'cwe_id': weakness.get('cweId', ''),
                    'type': weakness.get('type', ''),
                    'description': weakness.get('description', [{}])[0].get('value', '')
                })
            
            # Get affected software
            affected_software = []
            for config in cve_data.get('configurations', []):
                for node in config.get('nodes', []):
                    for cpe in node.get('cpeMatch', []):
                        affected_software.append({
                            'cpe': cpe.get('criteria', ''),
                            'vulnerable': cpe.get('vulnerable', False)
                        })
            
            return CVE(
                cve_id=cve_id,
                published_date=published_date,
                last_modified_date=last_modified_date,
                description=description,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cvss_severity=cvss_severity,
                affected_software=affected_software,
                references=references,
                weakneses=weaknesses
            )
            
        except Exception as e:
            print(f"Error parsing CVE: {e}")
            return None
    
    def _parse_nvd_date(self, date_str: str) -> datetime:
        """Parse NVD date string"""
        if not date_str:
            return datetime.now(timezone.utc)
        
        try:
            # Try ISO format
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except:
            try:
                # Try NVD format
                return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%f')
            except:
                return datetime.now(timezone.utc)
    
    def _cache_cves(self, cves: List[CVE]):
        """Cache CVEs in the local database"""
        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()
            
            for cve in cves:
                # Check if already in cache
                cursor.execute("SELECT 1 FROM cves WHERE cve_id = ?", (cve.cve_id,))
                if cursor.fetchone():
                    continue
                
                # Insert CVE
                cursor.execute('''
                    INSERT INTO cves (
                        cve_id, published_date, last_modified_date, description,
                        cvss_score, cvss_vector, cvss_severity, references, weakneses,
                        raw_json, last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve.cve_id,
                    cve.published_date.isoformat(),
                    cve.last_modified_date.isoformat(),
                    cve.description,
                    cve.cvss_score,
                    cve.cvss_vector,
                    cve.cvss_severity,
                    json.dumps(cve.references),
                    json.dumps(cve.weakneses),
                    json.dumps(cve.to_dict()),
                    datetime.now(timezone.utc).isoformat()
                ))
                
                # Insert affected software
                for software in cve.affected_software:
                    cursor.execute('''
                        INSERT INTO affected_software (
                            cve_id, cpe, vendor, product, version,
                            version_end_excluding, version_end_including
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve.cve_id,
                        software.get('cpe', ''),
                        '',  # Vendor
                        '',  # Product
                        '',  # Version
                        '',  # version_end_excluding
                        ''   # version_end_including
                    ))
            
            conn.commit()
    
    def _row_to_cve(self, row: Tuple) -> CVE:
        """Convert database row to CVE object"""
        return CVE(
            cve_id=row[0],
            published_date=datetime.fromisoformat(row[1]),
            last_modified_date=datetime.fromisoformat(row[2]),
            description=row[3],
            cvss_score=row[4] or 0.0,
            cvss_vector=row[5] or '',
            cvss_severity=row[6] or 'UNKNOWN',
            affected_software=self._get_affected_software(row[0]),
            references=json.loads(row[7]) if row[7] else [],
            weakneses=json.loads(row[8]) if row[8] else []
        )
    
    def _get_affected_software(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get affected software for a CVE"""
        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT cpe FROM affected_software WHERE cve_id = ?", (cve_id,))
            rows = cursor.fetchall()
            return [{'cpe': row[0]} for row in rows]
    
    def get_cve(self, cve_id: str) -> Optional[CVE]:
        """
        Get a specific CVE by ID.
        
        Args:
            cve_id: CVE ID to retrieve
            
        Returns:
            CVE: The CVE object, or None if not found
        """
        # Try cache first
        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_cve(row)
        
        # If not in cache, fetch from NVD
        cve = self._fetch_single_from_nvd(cve_id)
        if cve:
            self._cache_cves([cve])
        
        return cve
    
    def _fetch_single_from_nvd(self, cve_id: str) -> Optional[CVE]:
        """Fetch a single CVE from NVD"""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        headers = {}
        if self.api_key:
            headers['api-key'] = self.api_key
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            if vulnerabilities:
                cve_data = vulnerabilities[0].get('cve', {})
                return self._parse_nvd_cve(cve_data)
            
        except Exception as e:
            print(f"Error fetching CVE {cve_id}: {e}")
        
        return None
    
    def get_recent_cves(self, days: int = 7, limit: int = 100) -> List[CVE]:
        """
        Get recently published CVEs.
        
        Args:
            days: Number of days to look back
            limit: Maximum number of CVEs to return
            
        Returns:
            List[CVE]: List of recent CVEs
        """
        since_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        return self.search(CVEQuery(
            published_after=since_date,
            limit=limit
        ))
    
    def get_high_severity_cves(self, min_score: float = 7.0, limit: int = 100) -> List[CVE]:
        """
        Get high severity CVEs.
        
        Args:
            min_score: Minimum CVSS score
            limit: Maximum number of CVEs to return
            
        Returns:
            List[CVE]: List of high severity CVEs
        """
        return self.search(CVEQuery(
            cvss_score_min=min_score,
            limit=limit
        ))
    
    def get_cves_by_cpe(self, cpe: str, limit: int = 100) -> List[CVE]:
        """
        Get CVEs affecting a specific CPE.
        
        Args:
            cpe: CPE string (e.g., 'cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*')
            limit: Maximum number of CVEs to return
            
        Returns:
            List[CVE]: List of CVEs affecting the CPE
        """
        return self.search(CVEQuery(
            cpe=cpe,
            limit=limit
        ))
    
    def get_cves_by_vendor(self, vendor: str, limit: int = 100) -> List[CVE]:
        """
        Get CVEs affecting a specific vendor.
        
        Args:
            vendor: Vendor name (e.g., 'microsoft', 'apache')
            limit: Maximum number of CVEs to return
            
        Returns:
            List[CVE]: List of CVEs affecting the vendor
        """
        return self.search(CVEQuery(
            keyword=vendor,
            limit=limit
        ))
    
    def update_cache(self, days: int = 7):
        """
        Update the local cache with recent CVEs.
        
        Args:
            days: Number of days of CVEs to fetch
        """
        since_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Fetch recent CVEs
        cves = self._fetch_from_nvd(CVEQuery(
            published_after=since_date,
            limit=2000
        ))
        
        # Cache them
        if cves:
            self._cache_cves(cves)
        
        return len(cves)
    
    def clear_cache(self):
        """Clear the local cache"""
        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cves")
            cursor.execute("DELETE FROM affected_software")
            conn.commit()
