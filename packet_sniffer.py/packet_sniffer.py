from scapy.all import sniff, IP, TCP
import datetime

# ✅ Suspicious ports
SUSPICIOUS_PORTS = [23, 443, 4444, 5555]

# 🚨 Detect suspicious activity
def detect_intrusion(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        print(packet.summary())  # 👈 summary bhi yahi pe print kar rahe

        if dst_port in SUSPICIOUS_PORTS:
            alert = f"[ALERT] Suspicious port access: {src_ip} → {dst_ip} on port {dst_port} at {datetime.datetime.now()}"
            print("\n" + alert)

            with open("alerts.log", "a") as file:
                file.write(alert + "\n")

# 🧠 Sniff and process packets
print("[*] Starting NIDS... Press Ctrl+C to stop")
sniff(prn=detect_intrusion, store=False)