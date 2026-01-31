import os
import json
from typing import Dict, List, Optional, Union
from datetime import datetime
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

class AIAssistant:
    def __init__(self):
        """Initialize Groq AI Assistant"""
        self.api_key = os.getenv('GROQ_API_KEY')
        self.client = None
        self.model = "qwen/qwen3-32b"  # Groq's available Qwen model
        
        if self.api_key:
            try:
                self.client = Groq(api_key=self.api_key)
                print(f"✅ Groq AI Assistant initialized with model: {self.model}")
            except Exception as e:
                print(f"❌ Failed to initialize Groq client: {e}")
                self.client = None
        else:
            print("⚠️  GROQ_API_KEY not found in environment variables")
            self.client = None
    
    def analyze_scan_results(self, scan_data: Dict) -> str:
        """Analyze scan results and provide expert analysis"""
        if not self.client:
            return self._fallback_analysis(scan_data)
        
        prompt = self._create_analysis_prompt(scan_data)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a senior cybersecurity analyst with 15+ years of experience.
                        Analyze security scan results and provide:
                        1. Executive summary (for management)
                        2. Technical analysis (for security team)
                        3. Risk assessment with business impact
                        4. Immediate action items
                        5. Strategic recommendations
                        
                        Be specific, cite CVEs when applicable, and provide actionable steps."""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=3000,
                top_p=1,
                stream=False
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"Groq API error: {e}")
            return self._fallback_analysis(scan_data)
    
    def answer_security_question(self, question: str, context: Optional[Dict] = None) -> str:
        """Answer user's security-related questions"""
        if not self.client:
            return self._fallback_response(question)
        
        messages = [
            {
                "role": "system",
                "content": """You are a cybersecurity expert assistant specializing in:
                - Network security
                - Vulnerability management
                - Incident response
                - Security best practices
                - Compliance (NIST, ISO27001, PCI-DSS)
                
                Provide accurate, practical advice. If unsure, say so and suggest resources."""
            }
        ]
        
        if context:
            context_str = json.dumps({
                'target': context.get('target'),
                'critical_findings': context.get('summary', {}).get('critical', 0),
                'high_findings': context.get('summary', {}).get('high', 0),
                'open_ports': len(context.get('open_ports', [])),
                'services': [s['name'] for s in context.get('services', [])][:5]
            }, indent=2)
            messages.append({
                "role": "system",
                "content": f"Current scan context:\n{context_str}"
            })
        
        messages.append({
            "role": "user",
            "content": question
        })
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7,
                max_tokens=1500,
                top_p=1,
                stream=False
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"Groq API error: {e}")
            return self._fallback_response(question)
    
    def generate_remediation_plan(self, scan_data: Dict, specific_issue: str = None) -> str:
        """Generate detailed remediation plan"""
        if not self.client:
            return self._fallback_remediation_plan(scan_data)
        
        summary = scan_data.get('summary', {})
        
        prompt = f"""Generate a comprehensive remediation plan based on these security findings:
        
        TARGET: {scan_data.get('target', 'Unknown')}
        RISK LEVEL: {summary.get('risk_level', 'UNKNOWN')} ({summary.get('risk_score', 0)}/100)
        CRITICAL FINDINGS: {summary.get('critical', 0)}
        HIGH FINDINGS: {summary.get('high', 0)}
        OPEN PORTS: {len(scan_data.get('open_ports', []))}
        
        """
        
        if specific_issue:
            prompt += f"\nFOCUS AREA: {specific_issue}\n"
        
        prompt += """
        Provide a detailed plan with:
        
        PHASE 1: IMMEDIATE ACTIONS (First 24 hours)
        - Emergency patches
        - Access restrictions
        - Monitoring setup
        
        PHASE 2: SHORT-TERM REMEDIATION (1 week)
        - Patch management
        - Configuration hardening
        - Basic security controls
        
        PHASE 3: LONG-TERM IMPROVEMENTS (1 month)
        - Security architecture review
        - Process improvements
        - Training and awareness
        
        PHASE 4: VERIFICATION & VALIDATION
        - Rescan procedures
        - Success criteria
        - Compliance checks
        
        Include specific commands, configuration examples, and tool recommendations.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity incident response and remediation specialist."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=4000,
                top_p=1,
                stream=False
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"Groq API error: {e}")
            return self._fallback_remediation_plan(scan_data)
    
    def chat(self, message: str, history: List = None, context: Dict = None) -> str:
        """Interactive chat with context"""
        if not self.client:
            return "AI assistant is currently unavailable. Please check your API key configuration."
        
        messages = []
        
        # System prompt
        messages.append({
            "role": "system",
            "content": """You are a helpful cybersecurity AI assistant. You help with:
            - Explaining security findings
            - Providing remediation guidance
            - Answering security questions
            - Suggesting best practices
            - Interpreting scan results
            
            Be conversational but professional. Use markdown for formatting when helpful."""
        })
        
        # Add context if available
        if context:
            context_summary = f"""
            Current Scan Context:
            - Target: {context.get('target', 'Unknown')}
            - Risk Score: {context.get('summary', {}).get('risk_score', 0)}/100
            - Critical Issues: {context.get('summary', {}).get('critical', 0)}
            - Open Ports: {len(context.get('open_ports', []))}
            - Top Services: {', '.join([s['name'] for s in context.get('services', [])[:3]])}
            """
            messages.append({
                "role": "system",
                "content": context_summary
            })
        
        # Add conversation history
        if history:
            for msg in history[-6:]:  # Last 6 messages for context
                messages.append({
                    "role": msg.get("role", "user"),
                    "content": msg.get("content", "")
                })
        
        # Add current message
        messages.append({
            "role": "user",
            "content": message
        })
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.8,
                max_tokens=2000,
                top_p=1,
                stream=False
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"Groq chat error: {e}")
            return "I apologize, but I'm having trouble responding right now. Please try again or check your connection."
    
    def _create_analysis_prompt(self, scan_data: Dict) -> str:
        """Create analysis prompt from scan data"""
        summary = scan_data.get('summary', {})
        
        prompt = f"""
        SECURITY SCAN ANALYSIS REQUEST
        
        TARGET INFORMATION:
        - Target: {scan_data.get('target', 'Unknown')}
        - Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        EXECUTIVE SUMMARY:
        - Risk Level: {summary.get('risk_level', 'UNKNOWN')}
        - Risk Score: {summary.get('risk_score', 0)}/100
        - Total Findings: {summary.get('total_findings', 0)}
        - Critical: {summary.get('critical', 0)}
        - High: {summary.get('high', 0)}
        - Medium: {summary.get('medium', 0)}
        - Low: {summary.get('low', 0)}
        
        NETWORK FINDINGS:
        - Open Ports: {len(scan_data.get('open_ports', []))}
        - Ports List: {scan_data.get('open_ports', [])}
        
        SERVICES DETECTED ({len(scan_data.get('services', []))}):
        """
        
        for service in scan_data.get('services', []):
            prompt += f"- {service.get('port')}: {service.get('name')} {service.get('version', '')}\n"
        
        prompt += f"""
        
        VULNERABILITIES:
        {json.dumps(scan_data.get('vulnerabilities', {}), indent=2)}
        
        CVE FINDINGS ({summary.get('cves_found', 0)}):
        """
        
        for service_name, cves in scan_data.get('cves', {}).items():
            if cves:
                prompt += f"\n{service_name.upper()}:\n"
                for cve in cves[:3]:  # Top 3 CVEs per service
                    prompt += f"- {cve.get('id')}: {cve.get('description', '')[:100]}...\n"
        
        prompt += """
        
        Please provide a comprehensive security analysis focusing on:
        1. Business impact assessment
        2. Likelihood of exploitation
        3. Attack vectors
        4. Compliance implications
        5. Priority-based remediation roadmap
        """
        
        return prompt
    
    def _fallback_analysis(self, scan_data: Dict) -> str:
        """Fallback analysis when AI is unavailable"""
        summary = scan_data.get('summary', {})
        
        return f"""
        ## ⚠️ BASIC SECURITY ANALYSIS (AI Assistant Unavailable)
        
        ### Executive Summary
        **Target:** {scan_data.get('target', 'Unknown')}
        **Risk Level:** {summary.get('risk_level', 'UNKNOWN')} ({summary.get('risk_score', 0)}/100)
        
        ### Findings Overview
        - **Total Issues:** {summary.get('total_findings', 0)}
        - **Critical:** {summary.get('critical', 0)} (Require immediate attention)
        - **High:** {summary.get('high', 0)} (Address within 48 hours)
        - **Medium:** {summary.get('medium', 0)} (Schedule for next patch cycle)
        - **Low:** {summary.get('low', 0)} (Consider in routine maintenance)
        
        ### Network Exposure
        - **Open Ports:** {len(scan_data.get('open_ports', []))}
        - **Services Detected:** {len(scan_data.get('services', []))}
        - **CVEs Identified:** {summary.get('cves_found', 0)}
        
        ### Immediate Concerns
        1. **Critical Vulnerabilities:** {summary.get('critical', 0)} issues need emergency patching
        2. **Open Ports:** Review {len(scan_data.get('open_ports', []))} open ports for necessity
        3. **Service Security:** Check service configurations and versions
        
        ### Basic Recommendations
        **Phase 1 (Now):**
        - Patch critical vulnerabilities immediately
        - Restrict access to vulnerable services
        - Change default credentials
        
        **Phase 2 (This Week):**
        - Apply all security patches
        - Implement firewall rules
        - Enable logging and monitoring
        
        **Phase 3 (This Month):**
        - Conduct security hardening
        - Implement regular scanning
        - Create incident response plan
        
        ---
        *Enable Groq AI Assistant for detailed analysis by setting GROQ_API_KEY in .env file*
        """
    
    def _fallback_response(self, question: str) -> str:
        """Fallback response for questions"""
        return f"""
        ## 🤖 AI Assistant Status: Offline
        
        **Your Question:** {question}
        
        ### To enable AI Assistant:
        1. Get a free API key from [Groq Cloud](https://console.groq.com)
        2. Add `GROQ_API_KEY=your-key-here` to `.env` file
        3. Restart the application
        
        ### Basic Security Guidance:
        - **Patch Management:** Regularly update all software
        - **Access Control:** Implement least privilege principle
        - **Network Security:** Use firewalls and segmentation
        - **Monitoring:** Enable logging and alerting
        - **Backups:** Maintain regular, tested backups
        
        ### For immediate help:
        - [OWASP Top 10](https://owasp.org/www-project-top-ten/)
        - [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
        - [CVE Database](https://cve.mitre.org)
        
        *AI features require an internet connection and API key*
        """
    
    def _fallback_remediation_plan(self, scan_data: Dict) -> str:
        """Fallback remediation plan"""
        summary = scan_data.get('summary', {})
        
        return f"""
        ## 🛠️ BASIC REMEDIATION PLAN
        
        ### Target: {scan_data.get('target', 'Unknown')}
        ### Risk Score: {summary.get('risk_score', 0)}/100 ({summary.get('risk_level', 'UNKNOWN')})
        
        ### 🚨 IMMEDIATE ACTIONS (First 24 Hours)
        
        1. **Emergency Response**
           - Isolate system if critical vulnerabilities exist
           - Apply emergency patches for CVE-XXXX-XXXX vulnerabilities
           - Change all default and weak passwords
        
        2. **Access Control**
           - Restrict network access to vulnerable ports
           - Implement IP whitelisting where possible
           - Disable unnecessary services
        
        3. **Monitoring Setup**
           - Enable firewall logging
           - Set up basic intrusion detection
           - Monitor for suspicious activity
        
        ### 📋 SHORT-TERM REMEDIATION (1 Week)
        
        1. **Patch Management**
           - Apply all available security updates
           - Update {len(scan_data.get('services', []))} detected services
           - Verify patch installation
        
        2. **Configuration Hardening**
           - Harden {len(scan_data.get('open_ports', []))} open ports
           - Remove unnecessary user accounts
           - Disable unused features
        
        3. **Basic Controls**
           - Implement basic firewall rules
           - Enable antivirus/malware protection
           - Configure basic logging
        
        ### 🏗️ LONG-TERM IMPROVEMENTS (1 Month)
        
        1. **Security Architecture**
           - Review network segmentation
           - Implement defense in depth
           - Regular vulnerability scanning
        
        2. **Process Improvement**
           - Establish patch management process
           - Create incident response plan
           - Conduct security awareness training
        
        3. **Compliance & Validation**
           - Regular security assessments
           - Penetration testing
           - Compliance verification
        
        ### ✅ VERIFICATION STEPS
        
        1. **Rescan target after remediation**
        2. **Verify risk score improvement**
        3. **Document all changes made**
        4. **Update security policies**
        
        ---
        *Enable AI Assistant for customized, detailed remediation plans with specific commands and configurations.*
        """
