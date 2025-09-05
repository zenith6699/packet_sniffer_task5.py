# 📡 Network Packet Analyzer (Packet Sniffer)

> ⚠️ **DISCLAIMER:**  
> This tool is intended strictly for **educational purposes only**.  
> Unauthorized packet capturing or network monitoring is **illegal**.  
> Use only on networks you own or have explicit permission to monitor.

---

## 📌 Overview

This is a simple **Network Packet Analyzer (Packet Sniffer)** written in Python using only built-in modules. It captures and parses network packets including Ethernet, IPv4, ICMP, TCP, and UDP headers and logs the output to a file.

---

## 🚀 Features

- Real-time packet capture
- Parses Ethernet, IPv4, ICMP, TCP, UDP
- Captures raw data and formats in hex
- Logs output to a timestamped file
- Ethical use consent prompt
- Works on both Windows and Linux

---

## 🧱 Modules Used

- `socket`
- `struct`
- `textwrap`
- `datetime`
- `os`, `sys`, `time`

---

## 💻 How to Run

### 1. Run the script

```bash
sudo python packet_sniffer.py
```

> ⚠️ Must be run with `sudo` or Administrator privileges.

### 2. Provide input when prompted

- Number of packets to capture (default = 100)
- Output log file name (default = packet_log.txt)

---

## 🛑 Stopping the Sniffer

- Press `Ctrl + C` to stop the sniffer at any time.

---

## 📂 Output

Captured packets are saved in a log file like:

```
packet_log.txt
```

Example log entry:

```
[2025-09-05 22:45:01] Packet #1
Ethernet Frame:
  Destination: 00:1A:2B:3C:4D:5E, Source: 11:22:33:44:55:66, Protocol: 8
IPv4 Packet:
  Version: 4, Header Length: 20, TTL: 64
  Protocol: 6, Source: 192.168.1.5, Target: 192.168.1.1
TCP Segment:
  Source Port: 443, Destination Port: 51234
  Flags: {'URG': 0, 'ACK': 1, 'PSH': 1, 'RST': 0, 'SYN': 0, 'FIN': 0}
Data:
  \x48\x65\x6c\x6c\x6f...
```

---

## ✅ Compatibility

- ✅ Python 3.x
- ✅ Windows (Administrator mode)
- ✅ Linux (with `sudo`)
- ❌ macOS (not tested)

---

## 🛡️ Ethical Usage

Before capturing, a consent warning is shown. You must confirm you:

- Understand ethical and legal responsibilities
- Are using this on your own or authorized network
- Accept consequences of misuse

---

## 📖 License

This project is licensed under the **MIT License**.

---

## 🙏 Final Note

> Understand how packets work, how protocols interact, and how network traffic can be analyzed for ethical hacking and cybersecurity research.  
> Never use this tool for malicious purposes. Respect privacy and laws.

---

**Author:** [Your Name]  
**Year:** 2025
