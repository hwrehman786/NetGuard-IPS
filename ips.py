import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import time
import subprocess
import random
import sys
import socket
import datetime # For logging timestamps

# Try importing scapy; handle error if missing
try:
    # Added ARP and Raw for new detection features
    from scapy.all import sniff, IP, TCP, UDP, ARP, Raw
except ImportError:
    messagebox.showerror("Missing Dependency", "Scapy is not installed.\nPlease run: pip install scapy")
    sys.exit(1)

# ==========================================
# PART 1: DATA STRUCTURES (From Labs)
# ==========================================

# --- [Lab 7] Queue Implementation ---
packet_queue = queue.Queue()

# --- [Lab 8] Binary Search Tree (BST) ---
class BSTNode:
    def __init__(self, ip):
        self.ip = ip
        self.left = None
        self.right = None

class BlacklistBST:
    def __init__(self):
        self.root = None

    def insert(self, ip):
        if not self.root:
            self.root = BSTNode(ip)
        else:
            self._insert_recursive(self.root, ip)

    def _insert_recursive(self, node, ip):
        if ip < node.ip:
            if node.left is None:
                node.left = BSTNode(ip)
            else:
                self._insert_recursive(node.left, ip)
        elif ip > node.ip:
            if node.right is None:
                node.right = BSTNode(ip)
            else:
                self._insert_recursive(node.right, ip)

    # [Lab 10] Binary Search Algorithm
    def search(self, ip):
        return self._search_recursive(self.root, ip)

    def _search_recursive(self, node, ip):
        if node is None:
            return False
        if ip == node.ip:
            return True
        elif ip < node.ip:
            return self._search_recursive(node.left, ip)
        else:
            return self._search_recursive(node.right, ip)

# --- [Lab 4 & 6] Stack using Singly Linked List ---
class StackNode:
    def __init__(self, data):
        self.data = data
        self.next = None

class AlertStack:
    def __init__(self):
        self.top = None 
        self.size = 0

    def push(self, alert):
        new_node = StackNode(alert)
        new_node.next = self.top
        self.top = new_node
        self.size += 1

    def pop(self):
        if self.is_empty():
            return None
        data = self.top.data
        self.top = self.top.next
        self.size -= 1
        return data

    def is_empty(self):
        return self.top is None

# --- [Lab 9] Graph Data Structure ---
class NetworkGraph:
    def __init__(self):
        self.adj_list = {} 

    def add_connection(self, src, dst):
        if src not in self.adj_list:
            self.adj_list[src] = set()
        self.adj_list[src].add(dst)

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
    def __init__(self):
        super().__init__()
        self.stop_event = threading.Event()
        self.daemon = True

    def run(self):
        print("[SNIFFER] Started...")
        while not self.stop_event.is_set():
            try:
                # Capture 1 packet at a time. Feature 1: Real-Time Packet Capture
                # We do NOT apply filters here to ensure we catch ARP and IP traffic.
                sniff(count=1, prn=self.process_packet, store=0, timeout=1)
            except Exception as e:
                time.sleep(2)

    def process_packet(self, packet):
        # Feature 1: Extract packets. We now accept IP and ARP.
        if IP in packet or ARP in packet:
            packet_queue.put(packet)

    def stop(self):
        self.stop_event.set()

class DetectionEngine(threading.Thread):
    """Detection Engine: Signature Matching & Anomaly Detection"""
    def __init__(self, gui_callback, blacklist_bst, alert_stack, network_graph):
        super().__init__()
        self.stop_event = threading.Event()
        self.daemon = True
        self.gui_callback = gui_callback
        self.blacklist = blacklist_bst
        self.alert_stack = alert_stack
        self.network_graph = network_graph
        
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
                if not packet_queue.empty():
                    pkt = packet_queue.get()
                    self.analyze(pkt)
                else:
                    time.sleep(0.1)
            except Exception as e:
                print(f"[DETECTION ERROR] {e}")

    def analyze(self, pkt):
        # ==========================================
        # Feature 6: ARP Spoofing Prevention
        # ==========================================
        if ARP in pkt:
            # op=2 means 'is-at' (ARP Reply)
            if pkt[ARP].op == 2:
                ip_src = pkt[ARP].psrc
                mac_src = pkt[ARP].hwsrc
                
                # Check mapping
                if ip_src in self.arp_table:
                    if self.arp_table[ip_src] != mac_src:
                        # MAC address changed for the same IP! Possible Spoofing.
                        self.trigger_alert(ip_src, "ARP Spoofing Detected", "High")
                        return
                
                self.arp_table[ip_src] = mac_src
            return # Done with ARP

        if IP not in pkt:
            return

        # ==========================================
        # Extract Core Information (Feature 1)
        # ==========================================
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
        length = len(pkt)
        
        # Extract Ports (Feature 1 continued)
        sport = 0
        dport = 0
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        # Filter local traffic visualization
        if src_ip != self.local_ip and dst_ip != self.local_ip:
            return
            
        # Update Graph
        self.network_graph.add_connection(src_ip, dst_ip)

        # ==========================================
        # Feature 7: Whitelist Check
        # ==========================================
        if src_ip in self.whitelist:
            # Never block whitelisted IPs
            if src_ip == self.local_ip:
                hostname = self.get_hostname(src_ip)
                self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length))
            return

        if src_ip in self.blocked_ips:
            return

        # Reset counters every second
        current_time = time.time()
        if current_time - self.start_time > 1.0:
            self.packet_counts = {}
            self.port_map = {} 
            self.syn_track = {}
            self.start_time = current_time

        # ==========================================
        # Feature 2 & 5: Detection Logic
        # ==========================================
        
        threat_detected = False
        reason = ""
        severity = "Low"

        # 1. Signature Matching (Keyword in Payload)
        # Simple rule matching for unencrypted HTTP/Telnet
        if Raw in pkt:
            try:
                payload = str(pkt[Raw].load)
                if "password" in payload.lower() or "admin" in payload.lower():
                    threat_detected = True
                    reason = "Suspicious Payload (Keyword Match)"
                    severity = "Medium"
            except:
                pass

        # 2. SYN Flood Detection (Feature 2)
        if TCP in pkt and pkt[TCP].flags == 'S': # S = SYN flag
            self.syn_track[src_ip] = self.syn_track.get(src_ip, 0) + 1
            if self.syn_track[src_ip] > self.SYN_THRESHOLD:
                threat_detected = True
                reason = "SYN Flood Attack (Flooding)"
                severity = "High"

        # 3. Port Scanning Detection (Feature 2)
        if dport > 0:
            if src_ip not in self.port_map:
                self.port_map[src_ip] = set()
            self.port_map[src_ip].add(dport)
            if len(self.port_map[src_ip]) > self.PORT_SCAN_THRESHOLD:
                threat_detected = True
                reason = "Port Scanning Detected (Scanning)"
                severity = "Medium"

        # 4. Rate Limiting / DoS (Feature 5)
        self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1
        if self.packet_counts[src_ip] > self.THRESHOLD_PPS:
            threat_detected = True
            reason = "High Traffic Rate (DoS/Flooding)"
            severity = "High"

        # 5. Blacklist Check (Feature 7)
        if self.blacklist.search(src_ip):
            threat_detected = True
            reason = "Blacklisted IP (Known Attacker)"
            severity = "High"

        # ==========================================
        # Feature 3 & 4: Blocking & Alerting
        # ==========================================
        if threat_detected:
            self.trigger_alert(src_ip, reason, severity)
        else:
            hostname = self.get_hostname(src_ip)
            self.gui_callback("TRAFFIC", (src_ip, hostname, dst_ip, proto, length))

    def trigger_alert(self, src_ip, reason, severity):
        # Feature 3: Automatic Blocking
        success = FirewallManager.block_ip(src_ip)
        if success:
            self.blocked_ips.add(src_ip)
            hostname = self.get_hostname(src_ip)
            
            # Feature 4: Alert System (Console + Log File + GUI)
            print(f"[ALERT] {severity.upper()}: {src_ip} - {reason}")
            Logger.log_alert(src_ip, reason, severity)
            
            alert_msg = f"[{severity.upper()}] BLOCKED {src_ip} ({hostname}): {reason}"
            self.alert_stack.push(alert_msg)
            self.gui_callback("ALERT", (src_ip, hostname, reason, severity))

    def stop(self):
        self.stop_event.set()

# ==========================================
# PART 3: VISUALIZATION (GUI)
# ==========================================

class HipsDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("HIPS - Intrusion Prevention System (Data Structures Project)")
        self.root.geometry("1100x750")
        
        # Initialize Labs Logic
        self.blacklist_bst = BlacklistBST()
        self.alert_stack = AlertStack()
        self.network_graph = NetworkGraph()
        
        self.populate_dummy_blacklist()

        # Styles
        style = ttk.Style()
        style.configure("Treeview", font=('Consolas', 10))
        style.configure("TLabel", font=('Arial', 10))

        # --- Layout ---
        control_frame = ttk.LabelFrame(root, text="Controls", padding=10)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        self.btn_start = ttk.Button(control_frame, text="Start System", command=self.start_system)
        self.btn_start.pack(side="left", padx=5)
        
        self.btn_stop = ttk.Button(control_frame, text="Stop System", command=self.stop_system, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        self.btn_sort = ttk.Button(control_frame, text="Sort Traffic (Bubble Sort)", command=self.sort_traffic)
        self.btn_sort.pack(side="left", padx=5)

        self.btn_sim = ttk.Button(control_frame, text="Simulate Attack", command=self.simulate_attack)
        self.btn_sim.pack(side="right", padx=5)

        self.lbl_status = ttk.Label(control_frame, text="Status: Ready (Check 'hips_alerts.log' for history)", foreground="blue")
        self.lbl_status.pack(side="left", padx=20)

        mid_frame = tk.Frame(root)
        mid_frame.pack(fill="both", expand=True, padx=10, pady=5)

        traffic_frame = ttk.LabelFrame(mid_frame, text="Live Traffic (Queue Buffer)", padding=5)
        traffic_frame.pack(side="left", fill="both", expand=True)

        columns = ("Time", "Source", "Destination", "Protocol", "Size")
        self.tree = ttk.Treeview(traffic_frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col)
            width = 150 if col == "Source" else 90
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True)

        map_frame = ttk.LabelFrame(mid_frame, text="Network Map (Graph)", padding=5)
        map_frame.pack(side="right", fill="both", expand=True)
        
        self.canvas = tk.Canvas(map_frame, bg="white", width=400, height=350)
        self.canvas.pack(fill="both", expand=True)
        self.nodes_drawn = {} 

        alert_frame = ttk.LabelFrame(root, text="Security Alerts (Linked List Stack)", padding=10)
        alert_frame.pack(fill="x", padx=10, pady=5)

        self.alert_list = tk.Listbox(alert_frame, height=6, fg="red", font=('Consolas', 10, 'bold'))
        self.alert_list.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.btn_unblock = ttk.Button(alert_frame, text="Unblock IP", command=self.unblock_selected_ip)
        self.btn_unblock.pack(side="right", padx=5)

        self.sniffer = None
        self.detector = None
        self.is_running = False
        self.captured_packets_data = [] 

        self.center_x, self.center_y = 200, 175
        self.draw_node("LocalHost", self.center_x, self.center_y, "blue")

    def populate_dummy_blacklist(self):
        threats = ["192.168.1.100", "10.0.0.5", "172.16.0.25"]
        for ip in threats:
            self.blacklist_bst.insert(ip)

    def sort_traffic(self):
        """Sorts the traffic table by packet size."""
        data = self.captured_packets_data
        n = len(data)
        if n < 2: return

        # Bubble Sort
        for i in range(n):
            for j in range(0, n-i-1):
                if data[j][4] < data[j+1][4]: # Sort Descending
                    data[j], data[j+1] = data[j+1], data[j]
        
        self.tree.delete(*self.tree.get_children())
        for row in data:
            self.tree.insert("", "end", values=row)
        messagebox.showinfo("Sorting", f"Sorted {n} packets using Bubble Sort.")

    def draw_node(self, name, x, y, color="gray"):
        r = 20
        self.canvas.create_oval(x-r, y-r, x+r, y+r, fill=color, outline="black")
        display_name = name
        if len(display_name) > 15:
            display_name = display_name[:12] + "..."
        self.canvas.create_text(x, y, text=display_name, font=("Arial", 8))
        self.nodes_drawn[name] = (x, y) 

    def draw_edge(self, src, dst, color="black"):
        if src in self.nodes_drawn and dst in self.nodes_drawn:
            x1, y1 = self.nodes_drawn[src]
            x2, y2 = self.nodes_drawn[dst]
            self.canvas.create_line(x1, y1, x2, y2, fill=color, arrow=tk.LAST)

    def get_valid_node_position(self):
        min_dist = 50 
        width = int(self.canvas.cget("width"))
        height = int(self.canvas.cget("height"))
        for _ in range(50):
            rx = random.randint(40, width - 40)
            ry = random.randint(40, height - 40)
            dist_center = ((rx - self.center_x)**2 + (ry - self.center_y)**2)**0.5
            if dist_center < min_dist: continue
            overlap = False
            for (nx, ny) in self.nodes_drawn.values():
                dist = ((rx - nx)**2 + (ry - ny)**2)**0.5
                if dist < min_dist:
                    overlap = True
                    break
            if not overlap: return rx, ry
        return random.randint(40, width - 40), random.randint(40, height - 40)
    
    def simulate_attack(self):
        sim_ip = "45.155.205.10"
        sim_host = "Attacker (Russia)"
        sim_reason = "Signature Match: SQL Injection (Simulation)"
        sim_severity = "High"
        
        # Inject directly via GUI update to bypass detection logic for demo
        self.update_gui("ALERT", (sim_ip, sim_host, sim_reason, sim_severity))
        # Log it too
        Logger.log_alert(sim_ip, sim_reason, sim_severity)
        messagebox.showinfo("Simulation", "Simulated Attack Injected!")

    def unblock_selected_ip(self):
        selection = self.alert_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Select an alert first.")
            return
        msg = self.alert_list.get(selection[0])
        try:
            # Format: "[SEVERITY] BLOCKED IP (Host): Reason"
            # Split by spaces. IP is typically the 3rd word.
            parts = msg.split()
            # Example: ["[HIGH]", "BLOCKED", "1.2.3.4", ...]
            ip_to_unblock = parts[2]
            
            if FirewallManager.unblock_ip(ip_to_unblock):
                if self.detector and ip_to_unblock in self.detector.blocked_ips:
                    self.detector.blocked_ips.remove(ip_to_unblock)
                messagebox.showinfo("Success", f"IP {ip_to_unblock} has been unblocked.")
                self.alert_list.delete(selection[0])
        except Exception as e:
            messagebox.showerror("Error", f"Could not unblock: {e}")

    def update_gui(self, type, data):
        self.root.after(0, lambda: self._process_gui_update(type, data))

    def _process_gui_update(self, type, data):
        if not self.is_running: return

        timestamp = time.strftime("%H:%M:%S")

        if type == "TRAFFIC":
            src_ip, src_host, dst, proto, length = data
            
            row_data = (timestamp, src_host, dst, proto, length)
            self.captured_packets_data.append(row_data)
            
            self.tree.insert("", 0, values=row_data)
            if len(self.tree.get_children()) > 50:
                self.tree.delete(self.tree.get_children()[-1])
                if len(self.captured_packets_data) > 50:
                    self.captured_packets_data.pop(0)

            node_key = src_host 
            if node_key not in self.nodes_drawn:
                rx, ry = self.get_valid_node_position()
                self.draw_node(node_key, rx, ry, "green")
                self.draw_edge("LocalHost", node_key)
            
        elif type == "ALERT":
            src, hostname, reason, severity = data
            # Format: [SEVERITY] BLOCKED IP (Host) : Reason
            msg = f"[{severity.upper()}] BLOCKED {src} ({hostname}) : {reason}"
            
            self.alert_list.insert(0, msg)
            
            if hostname in self.nodes_drawn:
                x, y = self.nodes_drawn[hostname]
                self.draw_node(hostname, x, y, "red")
            elif src in self.nodes_drawn: 
                x, y = self.nodes_drawn[src]
                self.draw_node(src, x, y, "red")

    def start_system(self):
        if self.is_running: return
        self.is_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text="Status: SYSTEM ACTIVE - Logging to file", foreground="green")

        self.sniffer = PacketCaptureThread()
        self.detector = DetectionEngine(self.update_gui, self.blacklist_bst, self.alert_stack, self.network_graph)
        
        self.sniffer.start()
        self.detector.start()

    def stop_system(self):
        if not self.is_running: return
        self.is_running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="Status: STOPPED", foreground="red")

        if self.sniffer: self.sniffer.stop()
        if self.detector: self.detector.stop()

if __name__ == "__main__":
    try:
        is_admin = (subprocess.run("net session", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
    except:
        is_admin = False

    if not is_admin:
        print("WARNING: Not running as Administrator. Packet sniffing and Blocking may fail.")
    
    root = tk.Tk()
    app = HipsDashboard(root)
    root.mainloop()