import tkinter as tk
from scapy.all import sniff, IP, TCP
import threading
import datetime

SUSPICIOUS_PORTS = [23, 443, 4444, 5555]

# GUI setup
root = tk.Tk()
root.title("NIDS Alert Dashboard")
root.geometry("600x400")

text_area = tk.Text(root, wrap="word", bg="black", fg="lime", font=("Courier", 10))
text_area.pack(expand=True, fill="both")

def log_alert(alert):
    text_area.insert(tk.END, alert + "\n")
    text_area.see(tk.END)

def detect_intrusion(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        if dst_port in SUSPICIOUS_PORTS:
            alert = f"[ALERT] {datetime.datetime.now()} | {src_ip} → {dst_ip} | Port: {dst_port}"
            log_alert(alert)

def start_sniffing():
    sniff(prn=detect_intrusion, store=False)

# Threading sniff so GUI doesn't freeze
sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
sniff_thread.start()

# Run the GUI
root.mainloop()