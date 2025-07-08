import csv
import tkinter as tk
from scapy.all import sniff, IP, TCP
import threading
import datetime
import winsound

SUSPICIOUS_PORTS = [443, 23, 4444, 5555]

# Global flag to control sniffing
sniffing = False
sniffer_thread = None

# GUI Setup
root = tk.Tk()
root.title("Advanced NIDS by Harshit")
root.geometry("700x500")
root.configure(bg="black")

text_area = tk.Text(root, wrap="word", bg="black", fg="lime", font=("Courier", 10))
text_area.pack(expand=True, fill="both")

# Alert function
def log_alert(alert):
    text_area.insert(tk.END, alert + "\n")
    text_area.see(tk.END)
    winsound.MessageBeep()  # Sound
    text_area.tag_add("alert", "end-2l", "end-1l")
    text_area.tag_config("alert", foreground="red")  # Color alert

    def log_to_csv(src_ip, dst_ip, dst_port, timestamp):
     with open("alerts.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, src_ip, dst_ip, dst_port])


def search_alerts():
    query = search_entry.get().lower()
    text_area.tag_remove("highlight", "1.0", tk.END)

    if query:
        idx = "1.0"
        while True:
            idx = text_area.search(query, idx, nocase=1, stopindex=tk.END)
            if not idx:
                break
            end_idx = f"{idx}+{len(query)}c"
            text_area.tag_add("highlight", idx, end_idx)
            idx = end_idx
        text_area.tag_config("highlight", background="yellow", foreground="black")




# Packet analyzer
def detect_intrusion(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        if dst_port in SUSPICIOUS_PORTS:
            alert = f"[ALERT] {datetime.datetime.now()} | {src_ip} → {dst_ip} | Port: {dst_port}"
            log_alert(alert)

# Sniffing control
def start_sniffing():
    global sniffing, sniffer_thread
    sniffing = True
    sniffer_thread = threading.Thread(target=sniff_packets)
    sniffer_thread.start()

def stop_sniffing():
    global sniffing
    sniffing = False

def sniff_packets():
    sniff(prn=packet_handler, store=False)

def packet_handler(packet):
    if sniffing:
        detect_intrusion(packet)

# Buttons
button_frame = tk.Frame(root, bg="black")
button_frame.pack(pady=10)

start_btn = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white", width=15)
start_btn.pack(side=tk.LEFT, padx=10)

stop_btn = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white", width=15)
stop_btn.pack(side=tk.LEFT, padx=10)

# Start GUI
root.mainloop()

# GUI Setup
root = tk.Tk()
root.title("Advanced NIDS by Harshit")
root.geometry("700x500")
root.configure(bg="black")

# Search bar setup
search_frame = tk.Frame(root, bg="white")
search_frame.pack(fill="x")

search_label = tk.Label(search_frame, text="Search: ", fg="white", bg="red", font=("Courier", 10))
search_label.pack(side="left", padx=5)

search_entry = tk.Entry(search_frame, font=("Courier", 10))
search_entry.pack(side="left", fill="x", expand=True, padx=5)

search_button = tk.Button(search_frame, text="Search", command=lambda: search_alerts(), bg="red", fg="yellowk", font=("Courier", 10))
search_button.pack(side="left", padx=5)

# Main alert display area
text_area = tk.Text(root, wrap="word", bg="white", fg="lime", font=("Courier", 10))
text_area.pack(expand=True, fill="both")