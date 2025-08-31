# DoS/DDoS Attack Detector

A beginner-friendly, real-time tool to detect and visualize Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks. Features a modern web dashboard, multi-type attack detection, and a dark/light mode toggle with icon.

---

## 🚀 Features
- **Real-time network traffic monitoring**
- **Detects multiple attack types:**
  - DDoS (many IPs, high packet rate)
  - DoS (single IP, high packet rate)
  - UDP Flood
  - ICMP Flood (Ping of Death)
  - Slowloris-style (incomplete TCP handshakes)
- **Live dashboard:**
  - Packets per second (color-coded)
  - Unique IP count
  - Top offending IPs
  - Recent alerts (with DDoS highlight)
  - Last update timestamp
  - **Dark/Light mode toggle with icon** (🌙/☀️)
- **Beginner-friendly UI**
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

<img width="2376" height="1312" alt="image" src="https://github.com/user-attachments/assets/1fa14c4f-c4b2-4bfd-a046-6eb48917212d" />


---

## 🛡️ Detection Logic
- **DDoS:** High packet rate (default >500/sec) AND many unique IPs (default >50/sec)
- **DoS:** High packet rate from a single/few IPs
- **UDP Flood:** Excessive UDP packets
- **ICMP Flood:** Excessive ICMP (ping) packets
- **Slowloris:** Many incomplete TCP handshakes

Thresholds can be tuned in `detector/analysis.py`.

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
