# DoS/DDoS Attack Detector

A beginner-friendly, real-time tool to detect and visualize Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks. Features a modern web dashboard, multi-type attack detection, and a dark/light mode toggle with icon.

---

## 🚀 Features
- **Real-time network traffic monitoring**
- **Comprehensive attack detection:**
  - **DDoS:** Distributed attacks from multiple IPs with high packet rates
  - **DoS:** High-volume attacks from single/few IPs
  - **UDP Flood:** Excessive UDP packet bombardment
  - **ICMP Flood:** Ping of Death and ICMP flooding attacks
  - **Slowloris:** Incomplete TCP handshake attacks
  - **Port Scanning:** Rapid port scan detection from single IPs
  - **Brute Force:** Failed authentication attempt tracking
  - **DNS Amplification:** Abnormal DNS query pattern detection
  - **Advanced SYN Flood:** Sophisticated TCP SYN flood identification
  - **Application Layer Attacks:** HTTP floods and Slowloris variations
  - **Botnet Detection:** Coordinated attack pattern identification
- **Advanced analytics:**
  - Real-time packet analysis with deep inspection
  - Statistical anomaly detection
  - Behavioral pattern recognition
  - Threat intelligence correlation
- **Live dashboard:**
  - Packets per second (color-coded threat levels)
  - Unique IP count and geographic distribution
  - Top offending IPs with threat scores
  - Recent alerts with severity classification
  - Attack type breakdown and statistics
  - Real-time threat map visualization
  - Last update timestamp
  - **Dark/Light mode toggle with icon** (🌙/☀️)
- **Alert system:**
  - Email notifications for critical threats
  - Configurable alert thresholds
  - Multi-level severity classification
- **Beginner-friendly UI with professional-grade detection**
- **Easy setup and usage**

---

## 🛠️ Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Run the app:**
   ```bash
   python app.py
   ```
3. **Open your browser:**
   [http://127.0.0.1:5000](http://127.0.0.1:5000)

> **Note:** On Windows, you may need to run your terminal as Administrator for packet capture.

---

## 📊 Dashboard Overview
- **Packets per second:** Live traffic rate, color-coded for normal/warning/alert.
- **Unique IPs:** Number of unique sources in the last second (helps spot DDoS).
- **Top Offending IPs:** IPs sending the most packets.
- **Recent Alerts:** Shows detected attacks, with DDoS alerts highlighted.
- **Last updated:** Timestamp of the latest stats.
- **Dark/Light Mode:** Click the 🌙/☀️ icon in the top right to toggle between dark and light themes. Your preference is saved automatically.

![{B79BA4BD-0DC8-4702-9E2D-C19A6440B370}](https://github.com/user-attachments/assets/3c1cd4da-9858-4f22-847e-a22a06475d5c)

---

## 🛡️ Detection Logic

### **Core Attack Detection:**
- **DDoS:** High packet rate (>500/sec) AND many unique IPs (>50/sec)
- **DoS:** High packet rate from single/few IPs (>100/sec)
- **UDP Flood:** Excessive UDP packets (>80/sec)
- **ICMP Flood:** Excessive ICMP packets (>50/sec)
- **Slowloris:** Incomplete TCP handshakes (>30 from single IP)

### **Advanced Security Detection:**
- **Port Scanning:** Rapid connection attempts to multiple ports from single IP
- **Brute Force:** Multiple failed authentication attempts within time window
- **DNS Amplification:** Abnormal DNS query patterns and response ratios
- **Advanced SYN Flood:** Sophisticated TCP SYN flood with sequence analysis
- **Application Layer Attacks:** HTTP flood detection and Slowloris variations
- **Botnet Detection:** Coordinated attack patterns from multiple sources

### **Analysis Methods:**
- **Statistical Analysis:** Traffic pattern deviation detection
- **Behavioral Analysis:** IP reputation and activity profiling
- **Temporal Analysis:** Time-based attack pattern recognition
- **Protocol Analysis:** Deep packet inspection for protocol anomalies

All detection thresholds are configurable in `detector/analysis.py` and `detector/advanced_analysis.py`.

---

## 🧪 Testing & Simulation
- To simulate attacks, use tools like `hping3` or custom scripts to generate traffic.
- Example (Linux):
  ```bash
  sudo hping3 -S <target_ip> -p 80 --flood -a <spoofed_ip>
  ```


---

## 📂 Project Structure
```
DOS Attack Detector/
├── app.py                # Main Flask app
├── detector/
│   ├── capture.py        # Packet sniffing & stats
│   ├── analysis.py       # Detection logic
│   └── alerts.py         # Alert storage
├── static/
│   └── style.css         # Dashboard styles
├── templates/
│   └── index.html        # Dashboard UI
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

---

## 🤝 Contributing
Pull requests and suggestions are welcome! For major changes, please open an issue first.

---

## 📜 License
MIT License 
