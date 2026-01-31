import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # API Keys
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    NVD_API_KEY = os.getenv('NVD_API_KEY', '')
    
    # Scanning Configuration
    MAX_PORTS_TO_SCAN = 1000
    SCAN_TIMEOUT = 5  # seconds
    CONCURRENT_SCANS = 10
    
    # CVE Database
    CVE_UPDATE_INTERVAL = 24  # hours
    MAX_CVES_PER_SERVICE = 5
    
    # AI Settings
    AI_MODEL = "gpt-3.5-turbo"
    AI_TEMPERATURE = 0.7
    AI_MAX_TOKENS = 1000
    
    # Logging
    LOG_LEVEL = "INFO"
    LOG_FILE = "scanner.log"
    
    # Rate Limiting
    MAX_SCANS_PER_HOUR = 10
    MAX_REQUESTS_PER_MINUTE = 60
