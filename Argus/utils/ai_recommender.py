import openai
import json
import os
from typing import Dict, List
from dotenv import load_dotenv

# Try to import Groq
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

load_dotenv()

class AIRecommender:
    def __init__(self):
        """Initialize AI Recommender with multiple backends"""
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        self.groq_api_key = os.getenv('GROQ_API_KEY')
        self.use_local = False
        
        # Initialize API clients
        self.openai_client = None
        self.groq_client = None
        
        if self.openai_api_key:
            try:
                self.openai_client = openai.OpenAI(api_key=self.openai_api_key)
                print("✅ OpenAI client initialized")
            except Exception as e:
                print(f"❌ OpenAI initialization failed: {e}")
        
        if self.groq_api_key and GROQ_AVAILABLE:
            try:
                self.groq_client = Groq(api_key=self.groq_api_key)
                print("✅ Groq client initialized")
            except Exception as e:
                print(f"❌ Groq initialization failed: {e}")
        
        # Fallback patterns
        self.recommendation_patterns = {
            'critical': [
                "🚨 IMMEDIATE ACTION: {issue} - Patch within 24 hours",
                "🔒 Restrict access to affected service immediately",
                "📋 Implement emergency firewall rules",
                "👁️ Enable enhanced monitoring for exploitation attempts"
            ],
            'high': [
                "⚠️ PRIORITY FIX: {issue} - Address within 48 hours",
                "🔄 Update to latest secure version",
                "🔐 Implement strong authentication",
                "📊 Review access logs for suspicious activity"
            ],
            'medium': [
                "📅 SCHEDULE FIX: {issue} - Address in next patch cycle",
                "⚙️ Harden configuration settings",
                "🔍 Conduct security review",
                "📈 Monitor for related vulnerabilities"
            ],
            'low': [
                "💡 CONSIDER: {issue} - Address during routine maintenance",
                "📝 Document for security improvement",
                "🎯 Implement if resources allow",
                "📋 Add to security backlog"
            ]
        }
    
    def generate_recommendations(self, scan_data: Dict) -> List[Dict]:
        """Generate AI-powered recommendations"""
        # Try AI APIs in order of preference
        if self.groq_client:
            try:
                return self._get_groq_recommendations(scan_data)
            except Exception as e:
                print(f"Groq recommendations failed: {e}")
        
        if self.openai_client:
            try:
                return self._get_openai_recommendations(scan_data)
            except Exception as e:
                print(f"OpenAI recommendations failed: {e}")
        
        # Fallback to pattern-based
        return self._get_pattern_recommendations(scan_data)
    
    def _get_groq_recommendations(self, scan_data: Dict) -> List[Dict]:
        """Get recommendations from Groq API"""
        prompt = self._create_recommendation_prompt(scan_data)
        
        response = self.groq_client.chat.completions.create(
            model="qwen/qwen3-32b",
            messages=[
                {
                    "role": "system", 
                    "content": """You are a cybersecurity expert. Generate specific, actionable remediation recommendations.
                    Return valid JSON in this format:
                    {
                        "recommendations": [
                            {
                                "id": "rec_001",
                                "title": "Short descriptive title",
                                "description": "Detailed description",
                                "severity": "critical|high|medium|low",
                                "category": "network|web|service|configuration|patch",
                                "steps": ["Step 1", "Step 2", "Step 3"],
                                "priority": 1-10,
                                "estimated_time": "e.g., 1 hour",
                                "tools_needed": ["tool1", "tool2"],
                                "cve_references": ["CVE-XXXX-XXXX"],
                                "business_impact": "Low|Medium|High"
                            }
                        ]
                    }"""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.7,
            max_tokens=2000,
            response_format={"type": "json_object"}
        )
        
        content = response.choices[0].message.content
        
        try:
            result = json.loads(content)
            recommendations = result.get('recommendations', [])
            
            # Add IDs if missing
            for i, rec in enumerate(recommendations):
                if 'id' not in rec:
                    rec['id'] = f"rec_{i+1:03d}"
            
            return recommendations
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse Groq response: {e}")
            return self._get_pattern_recommendations(scan_data)
    
    def _get_openai_recommendations(self, scan_data: Dict) -> List[Dict]:
        """Get recommendations from OpenAI API"""
        prompt = self._create_recommendation_prompt(scan_data)
        
        response = self.openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": """You are a cybersecurity expert providing remediation recommendations.
                    Return valid JSON only."""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.7,
            max_tokens=1500
        )
        
        content = response.choices[0].message.content
        
        try:
            # Extract JSON from response
            start = content.find('{')
            end = content.rfind('}') + 1
            json_str = content[start:end]
            
            result = json.loads(json_str)
            recommendations = result.get('recommendations', [])
            
            # Add IDs if missing
            for i, rec in enumerate(recommendations):
                if 'id' not in rec:
                    rec['id'] = f"rec_{i+1:03d}"
            
            return recommendations
            
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Failed to parse OpenAI response: {e}")
            return self._parse_text_recommendations(content)
    
    def _create_recommendation_prompt(self, scan_data: Dict) -> str:
        """Create prompt for AI recommendations"""
        summary = self.generate_summary(scan_data)
        
        return f"""
        Generate security remediation recommendations based on these scan results:
        
        TARGET: {scan_data.get('target', 'Unknown')}
        RISK SCORE: {summary.get('risk_score')}/100 ({summary.get('risk_level')})
        
        FINDINGS:
        - Critical: {summary.get('critical')}
        - High: {summary.get('high')}
        - Medium: {summary.get('medium')}
        - Low: {summary.get('low')}
        
        OPEN PORTS ({len(scan_data.get('open_ports', []))}):
        {scan_data.get('open_ports', [])}
        
        SERVICES ({len(scan_data.get('services', []))}):
        {json.dumps(scan_data.get('services', []), indent=2)}
        
        VULNERABILITIES:
        {json.dumps(scan_data.get('vulnerabilities', {}), indent=2)}
        
        CVEs ({summary.get('cves_found')}):
        {json.dumps(scan_data.get('cves', {}), indent=2)}
        
        Provide 5-10 specific, actionable recommendations sorted by priority.
        Include practical steps, estimated time, and required tools.
        """
    
    def _get_pattern_recommendations(self, scan_data: Dict) -> List[Dict]:
        """Generate recommendations using patterns"""
        recommendations = []
        rec_id = 1
        
        summary = self.generate_summary(scan_data)
        vulns = scan_data.get('vulnerabilities', {})
        cves = scan_data.get('cves', {})
        
        # Critical vulnerabilities
        if summary.get('critical', 0) > 0:
            recommendations.append({
                'id': f"rec_{rec_id:03d}",
                'title': "Patch Critical Vulnerabilities Immediately",
                'description': f"{summary.get('critical')} critical vulnerabilities require emergency patching",
                'severity': 'critical',
                'category': 'patch',
                'steps': [
                    "Identify affected systems and services",
                    "Apply emergency security patches",
                    "Restart services if required",
                    "Verify patch installation",
                    "Monitor for stability issues"
                ],
                'priority': 1,
                'estimated_time': '2-4 hours',
                'tools_needed': ['Patch Management', 'System Monitoring'],
                'business_impact': 'High'
            })
            rec_id += 1
        
        # Open ports
        open_ports = scan_data.get('open_ports', [])
        if len(open_ports) > 20:  # Many open ports
            recommendations.append({
                'id': f"rec_{rec_id:03d}",
                'title': "Reduce Network Attack Surface",
                'description': f"Too many open ports ({len(open_ports)}) increase attack surface",
                'severity': 'high',
                'category': 'network',
                'steps': [
                    "Review necessity of each open port",
                    "Close unnecessary ports",
                    "Implement firewall rules",
                    "Document allowed ports",
                    "Regular port scanning"
                ],
                'priority': 2,
                'estimated_time': '4-8 hours',
                'tools_needed': ['Firewall', 'Port Scanner'],
                'business_impact': 'Medium'
            })
            rec_id += 1
        
        # Service-specific recommendations
        services = scan_data.get('services', [])
        for service in services[:3]:  # Top 3 services
            service_name = service.get('name', '').lower()
            
            if 'ssh' in service_name:
                recommendations.append({
                    'id': f"rec_{rec_id:03d}",
                    'title': "Harden SSH Configuration",
                    'description': "SSH service detected - implement security hardening",
                    'severity': 'high',
                    'category': 'configuration',
                    'steps': [
                        "Disable root login",
                        "Use key-based authentication",
                        "Change default port (optional)",
                        "Implement fail2ban",
                        "Restrict allowed users"
                    ],
                    'priority': 3,
                    'estimated_time': '1-2 hours',
                    'tools_needed': ['SSH Client', 'Text Editor'],
                    'business_impact': 'High'
                })
                rec_id += 1
            
            if 'http' in service_name or 'apache' in service_name or 'nginx' in service_name:
                recommendations.append({
                    'id': f"rec_{rec_id:03d}",
                    'title': "Secure Web Server Configuration",
                    'description': "Web server requires security hardening",
                    'severity': 'medium',
                    'category': 'web',
                    'steps': [
                        "Implement security headers",
                        "Disable directory listing",
                        "Remove version information",
                        "Configure proper permissions",
                        "Enable HTTPS only"
                    ],
                    'priority': 4,
                    'estimated_time': '2-3 hours',
                    'tools_needed': ['Web Server Config', 'SSL Tools'],
                    'business_impact': 'Medium'
                })
                rec_id += 1
        
        # CVE-specific recommendations
        for service_name, cve_list in cves.items():
            if cve_list:
                critical_cves = [cve for cve in cve_list if cve.get('severity') in ['CRITICAL', 'HIGH']]
                if critical_cves:
                    cve_ids = [cve.get('id', 'CVE') for cve in critical_cves[:3]]
                    recommendations.append({
                        'id': f"rec_{rec_id:03d}",
                        'title': f"Patch {service_name} CVEs",
                        'description': f"Critical CVEs affecting {service_name}: {', '.join(cve_ids)}",
                        'severity': 'critical' if 'CRITICAL' in [c.get('severity') for c in critical_cves] else 'high',
                        'category': 'patch',
                        'steps': [
                            f"Check {service_name} vendor advisory",
                            "Apply security updates",
                            "Test functionality after patching",
                            "Monitor for issues",
                            "Document changes"
                        ],
                        'priority': 2,
                        'estimated_time': '3-6 hours',
                        'tools_needed': ['Patch Manager', 'Testing Tools'],
                        'cve_references': cve_ids,
                        'business_impact': 'High'
                    })
                    rec_id += 1
        
        # Web vulnerabilities
        web_vulns = vulns.get('web_vulns', [])
        if web_vulns:
            recommendations.append({
                'id': f"rec_{rec_id:03d}",
                'title': "Fix Web Application Vulnerabilities",
                'description': f"{len(web_vulns)} web security issues detected",
                'severity': 'high',
                'category': 'web',
                'steps': [
                    "Implement input validation",
                    "Add security headers",
                    "Fix authentication issues",
                    "Secure session management",
                    "Regular web scanning"
                ],
                'priority': 3,
                'estimated_time': '4-8 hours',
                'tools_needed': ['Web Scanner', 'Development Tools'],
                'business_impact': 'High'
            })
            rec_id += 1
        
        # Sort by priority (critical first)
        severity_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4}
        recommendations.sort(key=lambda x: (severity_order.get(x['severity'], 5), x.get('priority', 10)))
        
        return recommendations
    
    def generate_summary(self, scan_data: Dict) -> Dict:
        """Generate summary of findings"""
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        
        vulns = scan_data.get('vulnerabilities', {})
        
        # Count from vulnerabilities
        total_critical += len(vulns.get('critical_findings', []))
        total_high += len(vulns.get('high_findings', []))
        total_medium += len(vulns.get('medium_findings', []))
        total_low += len(vulns.get('low_findings', []))
        
        # Count from CVEs
        cves = scan_data.get('cves', {})
        for service_cves in cves.values():
            for cve in service_cves:
                severity = cve.get('severity', '').upper()
                if 'CRITICAL' in severity:
                    total_critical += 1
                elif 'HIGH' in severity:
                    total_high += 1
                elif 'MEDIUM' in severity:
                    total_medium += 1
                else:
                    total_low += 1
        
        # Count web vulnerabilities
        for web_vuln in vulns.get('web_vulns', []):
            risk = web_vuln.get('risk', 'medium').lower()
            if risk == 'critical':
                total_critical += 1
            elif risk == 'high':
                total_high += 1
            elif risk == 'medium':
                total_medium += 1
            else:
                total_low += 1
        
        # Calculate risk score
        risk_score = min(100, (
            total_critical * 10 +
            total_high * 5 +
            total_medium * 2 +
            total_low * 1
        ))
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = 'CRITICAL'
        elif risk_score >= 60:
            risk_level = 'HIGH'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
        elif risk_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'INFO'
        
        return {
            'total_findings': total_critical + total_high + total_medium + total_low,
            'critical': total_critical,
            'high': total_high,
            'medium': total_medium,
            'low': total_low,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'ports_open': len(scan_data.get('open_ports', [])),
            'services_found': len(scan_data.get('services', [])),
            'cves_found': sum(len(c) for c in cves.values())
        }
    
    def _parse_text_recommendations(self, text: str) -> List[Dict]:
        """Parse text recommendations into structured format"""
        recommendations = []
        lines = text.strip().split('\n')
        
        current_rec = None
        in_steps = False
        
        for line in lines:
            line = line.strip()
            
            if not line:
                continue
            
            # Detect new recommendation
            if line.lower().startswith(('recommendation', 'rec ', 'fix:', 'action:')) or line.startswith('##') or line.startswith('**'):
                if current_rec:
                    recommendations.append(current_rec)
                
                # Extract severity from title
                severity = 'medium'
                if 'critical' in line.lower():
                    severity = 'critical'
                elif 'high' in line.lower():
                    severity = 'high'
                elif 'low' in line.lower():
                    severity = 'low'
                
                current_rec = {
                    'id': f"rec_{len(recommendations) + 1:03d}",
                    'title': line.replace('##', '').replace('**', '').strip(),
                    'description': '',
                    'severity': severity,
                    'category': 'general',
                    'steps': [],
                    'priority': 5,
                    'estimated_time': 'Unknown',
                    'tools_needed': []
                }
                in_steps = False
            
            # Detect steps
            elif line.startswith(('- ', '* ', '1.', '2.', '3.', '4.', '5.')):
                if current_rec:
                    in_steps = True
                    step = line.lstrip('-*1234567890. ').strip()
                    if step:
                        current_rec['steps'].append(step)
            
            # Description text
            elif current_rec and not in_steps:
                current_rec['description'] += line + ' '
        
        # Add last recommendation
        if current_rec:
            recommendations.append(current_rec)
        
        return recommendations
