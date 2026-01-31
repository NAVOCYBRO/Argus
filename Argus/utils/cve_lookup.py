import requests
import json
import re
from datetime import datetime, timedelta

class CVELookup:
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}
    
    def search_cves(self, product, version=None):
        """Search for CVEs related to a product and version"""
        if not product or product == 'unknown':
            return []
        
        cache_key = f"{product}_{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        cves = []
        
        try:
            # Build search query
            keywords = self._extract_keywords(product)
            
            for keyword in keywords:
                params = {
                    'keywordSearch': keyword,
                    'resultsPerPage': 10
                }
                
                if version:
                    params['keywordSearch'] = f"{keyword} {version}"
                
                response = requests.get(self.nvd_api_url, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for item in data.get('vulnerabilities', []):
                        cve_data = item.get('cve', {})
                        
                        cve_id = cve_data.get('id', '')
                        description = self._get_description(cve_data)
                        cvss_score = self._get_cvss_score(cve_data)
                        
                        # Filter by product name in description
                        if self._is_relevant(cve_data, product, version):
                            cves.append({
                                'id': cve_id,
                                'description': description[:200] + '...' if len(description) > 200 else description,
                                'cvss_score': cvss_score,
                                'published': cve_data.get('published', ''),
                                'severity': self._get_severity(cvss_score)
                            })
            
            # Sort by CVSS score (highest first)
            cves.sort(key=lambda x: x['cvss_score'] or 0, reverse=True)
            
            # Cache results
            self.cache[cache_key] = cves[:5]  # Limit to top 5
            
        except Exception as e:
            print(f"CVE lookup failed for {product}: {e}")
            # Fallback to offline database or return empty
        
        return self.cache.get(cache_key, [])
    
    def _extract_keywords(self, product):
        """Extract search keywords from product name"""
        keywords = []
        
        # Common product mappings
        product_lower = product.lower()
        
        if 'apache' in product_lower:
            if 'http' in product_lower:
                keywords.append('apache http server')
            elif 'tomcat' in product_lower:
                keywords.append('apache tomcat')
        elif 'nginx' in product_lower:
            keywords.append('nginx')
        elif 'iis' in product_lower:
            keywords.append('internet information services')
        elif 'openssh' in product_lower:
            keywords.append('openssh')
        elif 'mysql' in product_lower:
            keywords.append('mysql')
        elif 'postgres' in product_lower:
            keywords.append('postgresql')
        elif 'redis' in product_lower:
            keywords.append('redis')
        elif 'mongodb' in product_lower:
            keywords.append('mongodb')
        else:
            keywords.append(product)
        
        return keywords
    
    def _get_description(self, cve_data):
        """Extract description from CVE data"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', 'No description')
        return 'No description available'
    
    def _get_cvss_score(self, cve_data):
        """Extract CVSS score from CVE data"""
        try:
            metrics = cve_data.get('metrics', {})
            
            # Try CVSS v3 first
            if 'cvssMetricV31' in metrics:
                for metric in metrics['cvssMetricV31']:
                    return metric.get('cvssData', {}).get('baseScore')
            
            # Try CVSS v2
            if 'cvssMetricV2' in metrics:
                for metric in metrics['cvssMetricV2']:
                    return metric.get('cvssData', {}).get('baseScore')
                    
        except:
            pass
        
        return None
    
    def _get_severity(self, cvss_score):
        """Determine severity based on CVSS score"""
        if cvss_score is None:
            return 'UNKNOWN'
        elif cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        elif cvss_score > 0:
            return 'LOW'
        else:
            return 'NONE'
    
    def _is_relevant(self, cve_data, product, version):
        """Check if CVE is relevant to the product and version"""
        # Basic relevance check
        description = self._get_description(cve_data).lower()
        product_lower = product.lower()
        
        if product_lower in description:
            return True
        
        # Check configurations
        configurations = cve_data.get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    cpe_string = cpe.get('criteria', '').lower()
                    if product_lower in cpe_string:
                        if version:
                            if version in cpe_string:
                                return True
                        else:
                            return True
        
        return False
