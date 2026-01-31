🛡️ AI-Powered Security Scanner - Enterprise Edition

This is a Threat Detection tool that use ai for patch vulnerability.
Using nmap module in python this tool is created and in that tool we need NVD API and Groq API for run locally in devices.


A comprehensive, enterprise-grade cybersecurity assessment tool with AI-powered analysis and real-time vulnerability scanning.
✨ Features
🔍 Advanced Security Scanning

    Port Scanning: Detect open ports and services

    Service Detection: Identify running services with versions

    Vulnerability Assessment: Check for common security issues

    CVE Database Integration: Match services against known vulnerabilities

    Web Application Scanning: Basic web vulnerability detection

🤖 AI-Powered Analysis

    Groq AI Integration: Uses Qwen-32B model for intelligent analysis

    Real-time Recommendations: AI-generated remediation plans

    Interactive Assistant: Chat with security AI expert

    Risk Assessment: Intelligent risk scoring and prioritization

    Executive Reports: Professional security assessment reports

🎨 Enterprise UI

    Modern Dark Theme: Professional cybersecurity aesthetic

    Real-time Progress: Live scanning progress with detailed steps

    Responsive Design: Works on desktop, tablet, and mobile

    Interactive Charts: Visual risk assessment and statistics

    Export Options: PDF and JSON report generation

📋 Prerequisites

    Python 3.8+

    pip package manager

    Groq API Key (free at console.groq.com)

    OpenAI API Key (optional, for fallback)

    Network Access (for target scanning)

🚀 Quick Start
1. Clone and Setup
Clone the repository
git clone 
cd Argus

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
2. Configure Environment

Create a .env file in the project root:
# Flask Configuration
SECRET_KEY=your-secret-key-change-in-production
FLASK_ENV=development

# AI Configuration (Required for AI features)
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Scanner Configuration
SCAN_TIMEOUT=30
MAX_PORTS=1000

3. Get Your API Keys
Groq API Key (Required for AI Features):

    Visit console.groq.com

    Sign up for free account

    Generate API key from dashboard

    Add to .env file
   nano .env
   
    #API Keys
    GROQ_API_KEY=YOUR_GROQ_API_KEY
    NVD_API_KEY=YOUR_NVD_API_KEY

    #Security
    SECRET_KEY=your-secret-key-for-flask

    #Application
    DEBUG=True
    PORT=5000
           



Run the Application
python app.py
# Access the Application
<img width="1364" height="655" alt="Screenshot_20260201_014332" src="https://github.com/user-attachments/assets/489c5838-2cf8-41d4-be41-9df267429eb5" />



