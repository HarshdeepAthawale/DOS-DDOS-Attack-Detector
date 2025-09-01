# 🔧 Packet Capture Fix Guide

## ❌ Problem: Live Packet Capturing Not Working

Your DoS/DDoS detector is currently running with **simulated data** instead of real packet capture. This is a common issue on Windows systems.

## 🎯 Quick Fix (Recommended)

### Option 1: Automatic Fix Script
1. **Right-click** on `fix_packet_capture.bat`
2. Select **"Run as Administrator"**
3. Follow the prompts to install required drivers
4. Restart your computer
5. Run the detector again

### Option 2: Manual Installation
1. **Install Npcap** (recommended): https://npcap.com/
2. **Install WinPcap** (alternative): https://www.winpcap.org/
3. **Restart your computer**
4. **Run Command Prompt as Administrator**
5. Navigate to your project directory
6. Run: `python app.py`

## 🔍 Why This Happens

### Windows Network Limitations
- **No built-in packet capture**: Windows doesn't have native packet capture like Linux
- **Driver requirements**: Need Npcap/WinPcap for low-level network access
- **Permission issues**: Packet capture requires Administrator privileges
- **Firewall blocking**: Windows Firewall may block packet capture

### Scapy Configuration Issues
- **Missing pcap provider**: Scapy can't find packet capture drivers
- **Interface detection**: Can't identify network interfaces properly
- **Permission denied**: Network access requires elevated privileges

## 🛠️ Detailed Troubleshooting

### Step 1: Check Current Status
```bash
# Run the detector and check console output
python app.py
```

Look for these messages:
- ✅ `Real packet capture started successfully!` = Working
- 🔄 `Starting simulated packet capture...` = Not working
- ❌ `Could not start real packet capture` = Needs fixing

### Step 2: Install Packet Capture Drivers

#### Npcap (Recommended)
1. Download from: https://npcap.com/
2. Run installer as Administrator
3. Choose "Install Npcap in WinPcap API-compatible Mode"
4. Restart computer

#### WinPcap (Alternative)
1. Download from: https://www.winpcap.org/
2. Run installer as Administrator
3. Restart computer

### Step 3: Check Python Packages
```bash
pip install scapy flask yagmail
```

### Step 4: Test Packet Capture
```bash
python -c "from scapy.all import sniff; print('Testing...'); sniff(count=1, timeout=3)"
```

### Step 5: Run as Administrator
```bash
# Right-click Command Prompt → Run as Administrator
cd "C:\My Codes\DOS-DDOS-Attack-Detector"
python app.py
```

## 🚨 Common Error Messages & Solutions

### "WARNING: No libpcap provider available"
**Solution**: Install Npcap or WinPcap

### "Sniffing and sending packets is not available at layer 2"
**Solution**: Run as Administrator + install packet capture drivers

### "Permission denied"
**Solution**: Run Command Prompt as Administrator

### "Interface not found"
**Solution**: Check network adapter settings, try different interface

### "Firewall blocking"
**Solution**: Allow Python through Windows Firewall

## 🔧 Advanced Configuration

### Scapy Configuration
```python
from scapy.all import conf

# Try different capture methods
conf.use_pcap = True      # Use pcap (requires Npcap/WinPcap)
conf.use_dnet = True      # Use dnet (alternative)
conf.use_raw_socket = True # Use raw sockets (fallback)
```

### Network Interface Selection
```python
from scapy.all import get_if_list

# List available interfaces
interfaces = get_if_list()
print(f"Available: {interfaces}")

# Use specific interface
sniff(iface="Ethernet", prn=packet_callback)
```

## 📱 Alternative Solutions

### 1. Use Wireshark
- Install Wireshark (includes Npcap)
- Use Wireshark for packet analysis
- Run detector with simulated data

### 2. Use Linux Subsystem
- Install WSL2 on Windows
- Run detector in Linux environment
- Better packet capture support

### 3. Use Virtual Machine
- Install Linux VM
- Run detector in VM
- Full packet capture capabilities

## ✅ Verification

After fixing, you should see:
```
✅ Real packet capture started successfully!
✅ Real Packet Capture Active
```

Instead of:
```
🔄 Starting simulated packet capture...
🔄 Simulated Data (No Real Capture)
```

## 🆘 Still Having Issues?

### Check These:
1. **Administrator rights**: Must run as Administrator
2. **Driver installation**: Npcap/WinPcap properly installed
3. **Firewall settings**: Allow Python through firewall
4. **Antivirus**: Disable temporarily to test
5. **Network adapter**: Check adapter settings
6. **Windows version**: Some older versions have issues

### Get Help:
1. Run the fix script: `fix_packet_capture.bat`
2. Check console output for specific errors
3. Verify all dependencies are installed
4. Try running on different network interface

## 🎉 Success Indicators

When packet capture is working:
- Dashboard shows "✅ Real Packet Capture Active"
- Real network traffic appears in statistics
- No more simulated data generation
- Console shows successful capture messages

---

**Remember**: Packet capture on Windows requires Administrator privileges and proper drivers. The fix script handles most common issues automatically!
