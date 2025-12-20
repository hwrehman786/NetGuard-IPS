import threading
import time
import subprocess
import socket
import datetime
import sys
import json
import os

# Handle Scapy import gracefully
try:
    from scapy.all import sniff, IP, TCP, UDP, ARP, Raw
except ImportError:
    pass 

# ==========================================
# PART 2: FUNCTIONAL MODULES
# ==========================================

class FirewallManager:
    """Response Module: Interact with Windows Firewall"""
    @staticmethod
    def block_ip(ip_address):
        rule_name = f"HIPS_BLOCK_{ip_address}"
        command = (
            f"netsh advfirewall firewall add rule name=\"{rule_name}\" "
            f"dir=in action=block remoteip={ip_address}"
        )
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL)
            print(f"[FIREWALL] Blocked IP: {ip_address}")
            return True
        except subprocess.CalledProcessError:
            print(f"[ERROR] Failed to block {ip_address}. Run as Admin.")
            return False

    @staticmethod
    def unblock_ip(ip_address):
        rule_name = f"HIPS_BLOCK_{ip_address}"
        command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL)
            print(f"[FIREWALL] Unblocked IP: {ip_address}")
            return True
        except subprocess.CalledProcessError:
            return False

class Logger:
    """Feature 4: Alert System - Log File Entry"""
    @staticmethod
    def log_alert(ip, reason, severity):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{severity.upper()}] IP: {ip} - {reason}\n"
        try:
            with open("hips_alerts.log", "a") as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Logging Error: {e}")

class PacketCaptureThread(threading.Thread):
    """Packet Capture Module: Multithreaded Sniffer"""
    def __init__(self, packet_queue, blocked_ips=None, blocked_lock=None):
        super().__init__()
        self.packet_queue = packet_queue
        self.stop_event = threading.Event()
        self.daemon = True
        # Optional shared set of blocked IPs (DetectionEngine.blocked_ips)
        self.blocked_ips = blocked_ips
        self.blocked_lock = blocked_lock

    def run(self):
        print("[SNIFFER] Started...")
        while not self.stop_event.is_set():
            try:
                # Capture 1 packet at a time. Feature 1: Real-Time Packet Capture
                sniff(count=1, prn=self.process_packet, store=0, timeout=1)
            except Exception as e:
                time.sleep(2)

    def process_packet(self, packet):
        # Feature 1: Extract packets. We accept IP and ARP.
        # Drop packets from IPs that are already blocked (filter early).
        if IP in packet:
            try:
                src_ip = packet[IP].src
                if self.blocked_ips:
                    if self.blocked_lock:
                        with self.blocked_lock:
                            if src_ip in self.blocked_ips:
                                return
                    else:
                        if src_ip in self.blocked_ips:
                            return
            except Exception:
                pass

        if IP in packet or ARP in packet:
            self.packet_queue.put(packet)

    def stop(self):
        self.stop_event.set()


class DetectionEngine(threading.Thread):
    """Detection Engine: Signature Matching & Anomaly Detection"""
    def __init__(self, packet_queue, gui_callback, blacklist_bst, alert_stack, network_graph, analyze_local=False):
        super().__init__()
        self.packet_queue = packet_queue
        self.stop_event = threading.Event()
        self.daemon = True
        self.gui_callback = gui_callback
        self.blacklist = blacklist_bst
        self.alert_stack = alert_stack
        self.network_graph = network_graph
        # Whether to analyze local (self) traffic. When False, local_ip is treated as whitelisted.
        self.analyze_local = analyze_local
        
        # Detection States
        self.packet_counts = {} 
        self.port_map = {} 
        self.syn_track = {} # Feature 2: SYN Flood Detection
        self.blocked_ips = set() 
        self.start_time = time.time()
        
        # Feature 6: ARP Spoofing Prevention Data
        self.arp_table = {} # Stores IP -> MAC mappings
        
        # Feature 7: Whitelist Management
        self.whitelist = set()
        self.local_ip = self.get_local_ip()
        self.whitelist.add(self.local_ip)
        self.whitelist.add("127.0.0.1")
        self.whitelist.add("0.0.0.0")
        
        # Thresholds
        self.THRESHOLD_PPS = 150 # Rate Limiting (Feature 5)
        self.PORT_SCAN_THRESHOLD = 5 # Port Scanning (Feature 2)
        self.SYN_THRESHOLD = 20 # SYN packets per second
        self.dns_cache = {}

        # Thread-safety for blocked IPs
        self.blocked_lock = threading.Lock()

        # Persistence file for blocked IPs
        self._blocked_store = os.path.join(os.path.dirname(__file__), "blocked_ips.json")

        # Load persisted blocked IPs (if any) and attempt to re-apply OS blocks
        try:
            self._load_persisted_blocks()
        except Exception as e:
            print(f"[WARN] Could not load persisted blocks: {e}")

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def get_hostname(self, ip):
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(0.2) 
            hostname = socket.gethostbyaddr(ip)[0]
            if "1e100.net" in hostname:
                hostname = "Google/YouTube Service"
            elif "google" in hostname:
                hostname = "Google Service"
            elif "fbcdn" in hostname:
                hostname = "Facebook/Meta"
            socket.setdefaulttimeout(old_timeout)
        except:
            hostname = ip
        self.dns_cache[ip] = hostname
        return hostname

    def run(self):
        print("[DETECTION] Engine Started...")
        while not self.stop_event.is_set():
            try:
                if not self.packet_queue.empty():
                    pkt = self.packet_queue.get()
                    self.analyze(pkt)
                else:
                    time.sleep(0.1)
            except Exception as e:
                print(f"[DETECTION ERROR] {e}")

    def analyze(self, pkt):
        # Feature 6: ARP Spoofing Prevention (Moved BEFORE IP filtering)
        if ARP in pkt:
            # op=2 means 'is-at' (ARP Reply)
            if pkt[ARP].op == 2:
                ip_src = pkt[ARP].psrc
                mac_src = pkt[ARP].hwsrc
                
                # Check if we have seen this IP before
                if ip_src in self.arp_table:
                    # If the MAC address has changed for the same IP, it's spoofing!
                    if self.arp_table[ip_src] != mac_src:
                        self.trigger_alert(ip_src, "ARP Spoofing Detected (MAC Change)", "High")
                        return
                
                # Update table with current mapping
                self.arp_table[ip_src] = mac_src
            return # Done with ARP

        if IP not in pkt:
            return

        # Extract Core Information
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
        length = len(pkt)
        
        sport = 0
        dport = 0
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        # Filter local traffic visualization (This stops us from seeing non-local traffic in GUI)
        # BUT we already processed ARP above, so we don't miss spoofing.
        if src_ip != self.local_ip and dst_ip != self.local_ip:
            return
            
        # Update Graph
        self.network_graph.add_connection(src_ip, dst_ip)

        # Whitelist Check
        if src_ip in self.whitelist:
            if src_ip == self.local_ip:
                # If configured to analyze local traffic, allow normal analysis to continue.
                if not self.analyze_local:
                    hostname = self.get_hostname(src_ip)
                    self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length, sport, dport))
                    return
            else:
                return

        with self.blocked_lock:
            if src_ip in self.blocked_ips:
                return

        # Reset counters
        current_time = time.time()
        if current_time - self.start_time > 1.0:
            self.packet_counts = {}
            self.port_map = {} 
            self.syn_track = {}
            self.start_time = current_time

        threat_detected = False
        reason = ""
        severity = "Low"

        # 1. Signature Matching
        if Raw in pkt:
            try:
                payload = str(pkt[Raw].load)
                if "password" in payload.lower() or "admin" in payload.lower():
                    threat_detected = True
                    reason = "Suspicious Payload (Keyword Match)"
                    severity = "Medium"
            except:
                pass

        # If analyzing local traffic, also emit a LOCAL_ACTIVITY event with a small payload snippet
        try:
            if self.analyze_local and (src_ip == self.local_ip or dst_ip == self.local_ip) and Raw in pkt:
                raw_bytes = pkt[Raw].load
                try:
                    raw_text = raw_bytes.decode('utf-8', errors='replace')
                except Exception:
                    raw_text = str(raw_bytes)
                snippet = raw_text.replace('\r', ' ').split('\n')[0][:300]
                direction = 'OUT' if src_ip == self.local_ip else 'IN'
                self.gui_callback('LOCAL_ACTIVITY', (direction, src_ip, dst_ip, snippet))
        except Exception:
            pass

        # 2. SYN Flood Detection
        if TCP in pkt and pkt[TCP].flags == 'S': 
            self.syn_track[src_ip] = self.syn_track.get(src_ip, 0) + 1
            if self.syn_track[src_ip] > self.SYN_THRESHOLD:
                threat_detected = True
                reason = "SYN Flood Attack (Flooding)"
                severity = "High"

        # 3. Port Scanning Detection
        if dport > 0:
            if src_ip not in self.port_map:
                self.port_map[src_ip] = set()
            self.port_map[src_ip].add(dport)
            if len(self.port_map[src_ip]) > self.PORT_SCAN_THRESHOLD:
                threat_detected = True
                reason = "Port Scanning Detected (Scanning)"
                severity = "Medium"

        # 4. Rate Limiting / DoS
        self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1
        if self.packet_counts[src_ip] > self.THRESHOLD_PPS:
            threat_detected = True
            reason = "High Traffic Rate (DoS/Flooding)"
            severity = "High"

        # 5. Blacklist Check
        if self.blacklist.search(src_ip):
            threat_detected = True
            reason = "Blacklisted IP (Known Attacker)"
            severity = "High"

        if threat_detected:
            self.trigger_alert(src_ip, reason, severity)
        else:
            hostname = self.get_hostname(src_ip)
            self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length, sport, dport))

    def trigger_alert(self, src_ip, reason, severity):
        # Immediately add to in-memory blocked list so subsequent packets
        # are ignored without waiting for the OS firewall call to finish.
        with self.blocked_lock:
            self.blocked_ips.add(src_ip)
        # Persist the updated blocked set immediately
        try:
            self._save_persisted_blocks()
        except Exception as e:
            print(f"[WARN] Could not persist blocked IPs: {e}")

        hostname = self.get_hostname(src_ip)

        print(f"[ALERT] {severity.upper()}: {src_ip} - {reason}")
        Logger.log_alert(src_ip, reason, severity)

        alert_msg = f"[{severity.upper()}] BLOCKED {src_ip} ({hostname}): {reason}"
        self.alert_stack.push(alert_msg)
        self.gui_callback("ALERT", (src_ip, hostname, reason, severity))

        # Perform the OS-level firewall block asynchronously so we don't
        # delay packet processing (netsh can be slow or require admin).
        def _block_and_retry(ip, attempt=1, max_attempts=5):
            try:
                success = FirewallManager.block_ip(ip)
                if not success and attempt < max_attempts:
                    delay = [5, 15, 30, 60, 120][min(attempt-1, 4)]
                    print(f"[WARN] Firewall block failed for {ip}, retrying in {delay}s (attempt {attempt + 1})")
                    Logger.log_alert(ip, f"Firewall block failed, retrying in {delay}s (attempt {attempt + 1})", "Warning")
                    t = threading.Timer(delay, _block_and_retry, args=(ip, attempt+1, max_attempts))
                    t.daemon = True
                    t.start()
                elif not success:
                    print(f"[ERROR] Firewall block ultimately failed for {ip} after {max_attempts} attempts")
                    Logger.log_alert(ip, f"Firewall block ultimately failed after {max_attempts} attempts", "Error")
            except Exception as e:
                print(f"[ERROR] Blocking thread error for {ip}: {e}")
                Logger.log_alert(ip, f"Blocking thread error: {e}", "Error")

        t = threading.Thread(target=_block_and_retry, args=(src_ip,), daemon=True)
        t.start()

    def _save_persisted_blocks(self):
        try:
            with self.blocked_lock:
                data = list(self.blocked_ips)
            with open(self._blocked_store, 'w') as fh:
                json.dump({'blocked': data}, fh)
        except Exception as e:
            print(f"[WARN] Failed to write blocked_ips file: {e}")
            Logger.log_alert("local", f"Failed to write blocked_ips file: {e}", "Warning")

    def _load_persisted_blocks(self):
        if not os.path.isfile(self._blocked_store):
            return
        try:
            with open(self._blocked_store, 'r') as fh:
                j = json.load(fh)
                items = j.get('blocked', [])
                for ip in items:
                    with self.blocked_lock:
                        if ip not in self.blocked_ips:
                            self.blocked_ips.add(ip)
                            # Try to re-apply OS-level block asynchronously
                            t = threading.Thread(target=FirewallManager.block_ip, args=(ip,), daemon=True)
                            t.start()
        except Exception as e:
            print(f"[WARN] Failed to load blocked_ips file: {e}")
            Logger.log_alert("local", f"Failed to load blocked_ips file: {e}", "Warning")

    def stop(self):
        self.stop_event.set()