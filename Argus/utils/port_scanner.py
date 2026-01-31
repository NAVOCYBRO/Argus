import nmap
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017, 6379
        ]
    
    def scan_ports(self, target, ports=None):
        """Scan for open ports"""
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        
        try:
            # Fast scan using nmap
            arguments = '-T4 -F'  # Fast scan
            self.nm.scan(target, arguments=arguments)
            
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    ports = self.nm[target][proto].keys()
                    for port in ports:
                        state = self.nm[target][proto][port]['state']
                        if state == 'open':
                            open_ports.append(port)
            
            # If no ports found, do manual check on common ports
            if not open_ports:
                open_ports = self.manual_port_check(target, ports)
                
        except Exception as e:
            print(f"Nmap scan failed: {e}")
            open_ports = self.manual_port_check(target, ports)
        
        return sorted(open_ports)
    
    def manual_port_check(self, target, ports):
        """Manual TCP port checking"""
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports
    
    def detect_services(self, target, open_ports):
        """Detect services running on open ports"""
        services = []
        
        # Service detection scan
        try:
            self.nm.scan(target, arguments='-sV --version-intensity 5')
            
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    for port in open_ports:
                        if port in self.nm[target][proto]:
                            service_info = self.nm[target][proto][port]
                            services.append({
                                'port': port,
                                'name': service_info.get('name', 'unknown'),
                                'version': service_info.get('version', ''),
                                'product': service_info.get('product', ''),
                                'extrainfo': service_info.get('extrainfo', ''),
                                'cpe': service_info.get('cpe', '')
                            })
        except Exception as e:
            print(f"Service detection failed: {e}")
        
        # Fallback to common port mapping
        if not services:
            port_service_map = {
                21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
                53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
                443: 'https', 445: 'smb', 3306: 'mysql',
                3389: 'rdp', 5432: 'postgresql', 6379: 'redis',
                27017: 'mongodb', 9200: 'elasticsearch'
            }
            
            for port in open_ports:
                service_name = port_service_map.get(port, 'unknown')
                services.append({
                    'port': port,
                    'name': service_name,
                    'version': 'unknown'
                })
        
        return services
