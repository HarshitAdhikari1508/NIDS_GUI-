# NIDS_GUI - Network Intrusion Detection System (GUI based)

This is a simple project I made using Python for monitoring network traffic and detecting suspicious activity. It has a basic GUI made with Tkinter, and it logs any potentially harmful packets it detects. The idea was to make a tool that helps understand how intrusion detection works on a basic level.

---

## Features

- Packet sniffing using Scapy
- GUI built with Tkinter
- Logs suspicious packets in a file
- Export to CSV (planned)
- Search and filter alerts (planned)
- Auto-blocking using Windows Firewall (planned)

---

## Project Structure

NIDS_GUI-/
├── packet_sniffer.py/
│ ├── gui_nids.py
│ ├── gui_nids_advanced.py
│ └── packet_sniffer.py
├── test_packet.py/
│ └── test_packett.py
├── alerts.log
└── README.md

## How to Use

Make sure Python is installed.

1. Install dependencies:
```bash
pip install scapy


#Run the GUI file:

bash
Copy
Edit
python packet_sniffer.py/gui_nids.py

Notes
This project is still under development. I’m planning to add more features like automatic IP blocking, search/filter options in the GUI, and maybe even a simple dashboard in future.

Contact
Created by Harshit Adhikari
Email: harshitsinghadhikari9027@gmail.com

Feel free to suggest improvements or report bugs.
