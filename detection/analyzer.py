import math
import time
import json
import os
import threading
from collections import defaultdict
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP

class DNSAnalyzer:
    def __init__(self):
        self.query_history = defaultdict(list)
        self.ip_activity = defaultdict(int)
        
        self.alerts = []
        self.packet_logs = []
        self.is_running = False
        self.max_logs = 1000

    def start_sniffing(self, interface=None):
        if self.is_running:
            return
        self.is_running = True
        t = threading.Thread(target=self._sniff_loop, args=(interface,))
        t.daemon = True
        t.start()

    def stop_sniffing(self):
        self.is_running = False

    def simulate_traffic(self):
        # Background thread to inject simulated malicious and benign traffic
        def _sim():
            domains = [
                ("google.com", 1), ("microsoft.com", 1), ("apple.com", 1),
                ("login-paypal-secure.com", 1), # Suspicious
                ("x8z91jkl.com", 1), # DGA
                ("kjh98sdf9876sdfsdfkjh.dnsentinel.local", 16) # Tunnel
            ]
            import random
            while self.is_running:
                domain, qtype = random.choice(domains)
                self.feed_packet_data("192.168.1.100", "8.8.8.8", domain, qtype)
                
                # simulate a response with spoofing sometimes
                if random.random() < 0.1:
                    self.feed_packet_data("8.8.8.8", "192.168.1.100", "secure-bank.com", is_response=True, rdata_list=["127.0.0.1"])
                
                time.sleep(random.uniform(0.5, 2.0))
        
        t = threading.Thread(target=_sim)
        t.daemon = True
        t.start()

    def _sniff_loop(self, interface):
        try:
            sniff(filter="udp port 53 or udp port 8053", 
                  iface=interface, 
                  prn=self.process_packet, 
                  stop_filter=lambda x: not self.is_running,
                  store=0)
        except Exception as e:
            print(f"Analyzer Sniffing Error: {e}")
            self.is_running = False

    def feed_packet_data(self, src_ip, dst_ip, domain, qtype=1, is_response=False, rdata_list=None):
        if not is_response:
            self.analyze_query(src_ip, dst_ip, domain, qtype)
        else:
            self.analyze_response(src_ip, dst_ip, domain, rdata_list or [])

    def process_packet(self, packet):
        if not packet.haslayer(DNS):
            return
        ip_layer = packet.getlayer(IP)
        if not ip_layer:
            return
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        dns = packet.getlayer(DNS)
        
        if packet.haslayer(DNSQR) and dns.qr == 0:
            qname = dns.qd.qname.decode('utf-8', errors='ignore') if dns.qd else ""
            qname = qname.lower().rstrip('.')
            qtype = dns.qd.qtype
            self.analyze_query(src_ip, dst_ip, qname, qtype)
            
        elif packet.haslayer(DNSRR) and dns.qr == 1:
            qname = dns.qd.qname.decode('utf-8', errors='ignore') if dns.qd else ""
            qname = qname.lower().rstrip('.')
            rdata_list = []
            if dns.ancount > 0:
                for i in range(dns.ancount):
                    rdata = dns.an[i].rdata
                    if isinstance(rdata, bytes):
                        rdata_list.append(rdata.decode('utf-8', errors='ignore'))
                    else:
                        rdata_list.append(str(rdata))
            self.analyze_response(src_ip, dst_ip, qname, rdata_list)

    def extract_features(self, domain):
        parts = domain.split('.')
        subdomain = parts[0] if len(parts) > 2 else ""
        length = len(domain)
        sub_length = len(subdomain)
        entropy = self._shannon_entropy(subdomain if subdomain else domain)
        return length, sub_length, entropy, parts

    def _shannon_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x))/len(data)
            entropy += - p_x*math.log2(p_x)
        return entropy

    def analyze_query(self, src_ip, dst_ip, domain, qtype):
        length, sub_length, entropy, parts = self.extract_features(domain)
        now = time.time()
        
        self.query_history[src_ip].append(now)
        self.query_history[src_ip] = [t for t in self.query_history[src_ip] if now - t < 60]
        query_rate = len(self.query_history[src_ip])
        
        tunnel_score = self.detect_tunnel(sub_length, entropy, qtype)
        dga_score = self.detect_dga(domain, entropy, parts)
        behav_score = 100 if query_rate > 50 else (query_rate * 2)
        susp_score = self.detect_suspicious(domain)
        
        total_risk = (tunnel_score * 0.4) + (dga_score * 0.2) + (behav_score * 0.2) + (susp_score * 0.2)
        total_risk = min(100, round(total_risk, 2))

        log_entry = {
            "timestamp": now,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "domain": domain,
            "type": "Query",
            "entropy": round(entropy, 3),
            "risk_score": total_risk
        }
        self.packet_logs.append(log_entry)
        if len(self.packet_logs) > self.max_logs:
            self.packet_logs.pop(0)
            
        if total_risk > 50:
            self.alerts.append({
                "timestamp": now,
                "domain": domain,
                "src_ip": src_ip,
                "risk_score": total_risk,
                "type": "Malicious Query",
                "details": f"Tunnel: {tunnel_score}, DGA: {dga_score}, Behav: {behav_score}, Susp: {susp_score}"
            })

    def analyze_response(self, src_ip, dst_ip, domain, rdata_list):
        now = time.time()
        spoof_score = 0
        reason = ""
        for rdata in rdata_list:
            if rdata in ["127.0.0.1", "0.0.0.0"] and "local" not in domain:
                spoof_score = 100
                reason = f"Spoofed/Sinkholed IP {rdata} returned"

        if spoof_score > 80:
             self.alerts.append({
                "timestamp": now,
                "domain": domain,
                "src_ip": dst_ip, 
                "risk_score": spoof_score,
                "type": "Spoofing/Sinkhole",
                "details": reason
            })

    def detect_tunnel(self, sub_length, entropy, qtype):
        score = 0
        if sub_length > 30:
            score += 40
        if entropy > 4.2:
            score += 40
        if qtype in [16, 10]:
            score += 20
        return min(100, score)

    def detect_dga(self, domain, entropy, parts):
        score = 0
        main_domain = parts[-2] if len(parts) >= 2 else parts[0]
        if len(main_domain) > 15:
            score += 30
        digits = sum(c.isdigit() for c in main_domain)
        letters = sum(c.isalpha() for c in main_domain)
        if letters > 0 and (digits / (letters + digits)) > 0.3:
            score += 30
        consonants = sum(1 for c in main_domain if c in "bcdfghjklmnpqrstvwxyz")
        vowels = sum(1 for c in main_domain if c in "aeiou")
        if vowels > 0 and (consonants / vowels) > 5:
            score += 20
        if entropy > 3.8:
            score += 20
        return min(100, score)

    def detect_suspicious(self, domain):
        suspicious_keywords = ["login", "bank", "secure", "update", "verify", "account", "paypal", "microsoft", "apple", "google", "free", "admin"]
        score = 0
        for kw in suspicious_keywords:
            if kw in domain and not domain.endswith(f"{kw}.com"):
                score += 50
        if domain.endswith(".co") or domain.endswith(".cm") or domain.endswith(".xyz") or domain.endswith(".top"):
            score += 30
        return min(100, score)
