from flask import Flask, render_template, request, jsonify, session
from utils.port_scanner import PortScanner
from utils.vulnerability_checker import VulnerabilityChecker
from utils.cve_lookup import CVELookup
from utils.ai_recommender import AIRecommender
from utils.ai_assistant import AIAssistant
import threading
import queue
import json
import uuid
import time
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

# Storage for scan data and results
results_queue = queue.Queue()
scan_data_store = {}
scan_status_store = {}

# Initialize AI components
ai_assistant = AIAssistant()
ai_recommender = AIRecommender()

def scan_target_async(target, scan_id, scan_options):
    """Async scanning function with progress tracking"""
    try:
        # Update status
        scan_status_store[scan_id] = {
            'status': 'running',
            'progress': 0,
            'current_step': 'Initializing',
            'start_time': time.time()
        }
        
        # Initialize components
        scanner = PortScanner()
        vuln_checker = VulnerabilityChecker()
        cve_lookup = CVELookup()
        
        # Step 1: Port Scanning (10%)
        scan_status_store[scan_id]['current_step'] = 'Port Scanning'
        scan_status_store[scan_id]['progress'] = 10
        print(f"[{scan_id}] Scanning {target}...")
        open_ports = scanner.scan_ports(target)
        
        # Step 2: Service Detection (30%)
        scan_status_store[scan_id]['current_step'] = 'Service Detection'
        scan_status_store[scan_id]['progress'] = 30
        services = scanner.detect_services(target, open_ports)
        
        # Step 3: Vulnerability Checking (50%)
        scan_status_store[scan_id]['current_step'] = 'Vulnerability Checking'
        scan_status_store[scan_id]['progress'] = 50
        vulnerabilities = vuln_checker.check_all_vulnerabilities(target, services)
        
        # Step 4: CVE Lookup (70%)
        scan_status_store[scan_id]['current_step'] = 'CVE Database Query'
        scan_status_store[scan_id]['progress'] = 70
        cve_results = {}
        for service in services:
            cves = cve_lookup.search_cves(
                service['name'], 
                service['version']
            )
            cve_results[service['name']] = cves
        
        # Step 5: AI Recommendations (90%)
        scan_status_store[scan_id]['current_step'] = 'AI Analysis'
        scan_status_store[scan_id]['progress'] = 90
        
        all_data = {
            'target': target,
            'open_ports': open_ports,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'cves': cve_results
        }
        
        recommendations = ai_recommender.generate_recommendations(all_data)
        summary = ai_recommender.generate_summary(all_data)
        
        # Generate AI analysis if enabled
        ai_analysis = ""
        if scan_options.get('ai_analysis', True):
            ai_analysis = ai_assistant.analyze_scan_results({
                'target': target,
                'open_ports': open_ports,
                'services': services,
                'vulnerabilities': vulnerabilities,
                'cves': cve_results,
                'summary': summary
            })
        
        # Combine results
        results = {
            'status': 'completed',
            'scan_id': scan_id,
            'target': target,
            'open_ports': open_ports,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'cves': cve_results,
            'recommendations': recommendations,
            'summary': summary,
            'ai_analysis': ai_analysis,
            'scan_options': scan_options,
            'timestamp': datetime.now().isoformat(),
            'scan_duration': time.time() - scan_status_store[scan_id]['start_time']
        }
        
        # Store in scan data store for future AI queries
        scan_data_store[scan_id] = {
            'target': target,
            'open_ports': open_ports,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'cves': cve_results,
            'recommendations': recommendations,
            'summary': summary,
            'timestamp': datetime.now().isoformat()
        }
        
        # Update status to completed
        scan_status_store[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'current_step': 'Completed',
            'results': results
        }
        
        # Put results in queue
        results_queue.put({
            'scan_id': scan_id,
            'results': results
        })
        
    except Exception as e:
        print(f"[{scan_id}] Scan error: {str(e)}")
        scan_status_store[scan_id] = {
            'status': 'error',
            'progress': 0,
            'current_step': 'Error',
            'error': str(e)
        }

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Start a new scan"""
    target = request.form.get('target')
    scan_options = {
        'full_scan': request.form.get('full_scan') == 'on',
        'service_detect': request.form.get('service_detect') == 'on',
        'cve_check': request.form.get('cve_check') == 'on',
        'web_scan': request.form.get('web_scan') == 'on',
        'ai_analysis': request.form.get('ai_analysis') == 'on'
    }
    
    if not target:
        return jsonify({'error': 'No target specified'}), 400
    
    # Generate unique scan ID
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    
    # Store initial status
    scan_status_store[scan_id] = {
        'status': 'queued',
        'progress': 0,
        'current_step': 'Queued',
        'start_time': time.time()
    }
    
    # Start async scan
    thread = threading.Thread(
        target=scan_target_async,
        args=(target, scan_id, scan_options),
        daemon=True
    )
    thread.start()
    
    return jsonify({
        'status': 'scan_started',
        'target': target,
        'scan_id': scan_id,
        'scan_options': scan_options
    })

@app.route('/scan/status/<scan_id>')
def scan_status(scan_id):
    """Get scan status"""
    status = scan_status_store.get(scan_id, {'status': 'not_found'})
    return jsonify(status)

@app.route('/scan/results/<scan_id>')
def scan_results(scan_id):
    """Get scan results"""
    # Check if results are in queue
    try:
        while not results_queue.empty():
            item = results_queue.get_nowait()
            if item['scan_id'] == scan_id:
                return jsonify(item['results'])
    except queue.Empty:
        pass
    
    # Check if scan is completed
    status = scan_status_store.get(scan_id)
    if status and status.get('status') == 'completed':
        return jsonify(status.get('results', {}))
    
    return jsonify({'status': 'scanning'})

# AI Assistant Endpoints
@app.route('/ai/status', methods=['GET'])
def ai_status():
    """Check AI assistant status"""
    return jsonify({
        'available': ai_assistant.client is not None,
        'model': ai_assistant.model if ai_assistant.client else None,
        'provider': 'Groq'
    })

@app.route('/ai/analyze', methods=['POST'])
def ai_analyze():
    """Get AI analysis for scan results"""
    data = request.json
    scan_id = data.get('scan_id')
    
    if not scan_id:
        return jsonify({'error': 'Scan ID required'}), 400
    
    scan_data = scan_data_store.get(scan_id)
    if not scan_data:
        return jsonify({'error': 'Scan data not found'}), 404
    
    analysis = ai_assistant.analyze_scan_results(scan_data)
    
    return jsonify({
        'status': 'success',
        'analysis': analysis,
        'scan_id': scan_id
    })

@app.route('/ai/ask', methods=['POST'])
def ai_ask():
    """Ask AI assistant a question"""
    data = request.json
    question = data.get('question')
    scan_id = data.get('scan_id')
    
    if not question:
        return jsonify({'error': 'Question required'}), 400
    
    context = None
    if scan_id:
        context = scan_data_store.get(scan_id)
    
    answer = ai_assistant.answer_security_question(question, context)
    
    return jsonify({
        'status': 'success',
        'question': question,
        'answer': answer,
        'scan_id': scan_id
    })

@app.route('/ai/remediation', methods=['POST'])
def ai_remediation():
    """Get AI-generated remediation plan"""
    data = request.json
    scan_id = data.get('scan_id')
    specific_issue = data.get('issue')
    
    if not scan_id:
        return jsonify({'error': 'Scan ID required'}), 400
    
    scan_data = scan_data_store.get(scan_id)
    if not scan_data:
        return jsonify({'error': 'Scan data not found'}), 404
    
    plan = ai_assistant.generate_remediation_plan(scan_data, specific_issue)
    
    return jsonify({
        'status': 'success',
        'remediation_plan': plan,
        'scan_id': scan_id
    })

@app.route('/ai/chat', methods=['POST'])
def ai_chat():
    """Interactive chat with AI assistant"""
    data = request.json
    message = data.get('message')
    history = data.get('history', [])
    scan_id = data.get('scan_id')
    
    if not message:
        return jsonify({'error': 'Message required'}), 400
    
    context = None
    if scan_id:
        context = scan_data_store.get(scan_id)
    
    response = ai_assistant.chat(message, history, context)
    
    return jsonify({
        'status': 'success',
        'response': response,
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('utils', exist_ok=True)
    
    # Print startup info
    print("=" * 60)
    print("🔒 AI Cybersecurity Scanner with Groq Assistant")
    print("=" * 60)
    print(f"AI Assistant Status: {'✅ Available' if ai_assistant.client else '❌ Not Available'}")
    if ai_assistant.client:
        print(f"AI Model: {ai_assistant.model}")
    else:
        print("Note: Set GROQ_API_KEY in .env file for AI features")
    print("Server starting on http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
