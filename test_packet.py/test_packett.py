from scapy.all import send, IP, TCP

# Send a fake suspicious packet to port 9999 (used for testing)
packet = IP(dst="127.0.0.1")/TCP(dport=9999, sport=12345)
send(packet)

print("Test packet sent to port 9999.")
