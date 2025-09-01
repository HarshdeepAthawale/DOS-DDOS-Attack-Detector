#!/usr/bin/env python3
"""
Packet Capture Fix Script for Windows
This script helps resolve packet capture issues on Windows systems.
"""

import os
import sys
import subprocess
import platform
import ctypes
import urllib.request
import zipfile
import tempfile
import shutil

def is_admin():
    """Check if running as administrator"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def download_file(url, filename):
    """Download a file from URL"""
    try:
        print(f"Downloading {filename}...")
        urllib.request.urlretrieve(url, filename)
        return True
    except Exception as e:
        print(f"Failed to download {filename}: {e}")
        return False

def install_npcap():
    """Install Npcap for packet capture"""
    print("Installing Npcap...")
    
    # Download Npcap installer
    npcap_url = "https://npcap.com/dist/npcap-1.79.exe"
    installer_path = "npcap-installer.exe"
    
    if download_file(npcap_url, installer_path):
        try:
            # Run installer silently
            print("Running Npcap installer...")
            subprocess.run([installer_path, "/S"], check=True)
            print("✅ Npcap installed successfully!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Npcap installation failed: {e}")
            return False
        finally:
            # Clean up installer
            if os.path.exists(installer_path):
                os.remove(installer_path)
    return False

def install_winpcap():
    """Install WinPcap as fallback"""
    print("Installing WinPcap...")
    
    # Download WinPcap installer
    winpcap_url = "https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe"
    installer_path = "winpcap-installer.exe"
    
    if download_file(winpcap_url, installer_path):
        try:
            # Run installer silently
            print("Running WinPcap installer...")
            subprocess.run([installer_path, "/S"], check=True)
            print("✅ WinPcap installed successfully!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ WinPcap installation failed: {e}")
            return False
        finally:
            # Clean up installer
            if os.path.exists(installer_path):
                os.remove(installer_path)
    return False

def check_python_packages():
    """Check and install required Python packages"""
    print("Checking Python packages...")
    
    required_packages = ['scapy', 'flask', 'yagmail']
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} is already installed")
        except ImportError:
            print(f"Installing {package}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"✅ {package} installed successfully")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install {package}: {e}")
                return False
    return True

def test_packet_capture():
    """Test if packet capture is working"""
    print("Testing packet capture...")
    
    try:
        from scapy.all import sniff, conf
        
        # Try to configure Scapy for Windows
        if platform.system() == "Windows":
            try:
                conf.use_pcap = True
                print("✅ Configured Scapy to use pcap")
            except:
                print("⚠️ Could not configure pcap, trying alternative methods...")
        
        # Try to capture a single packet
        print("Attempting to capture a packet...")
        result = sniff(count=1, timeout=3, store=0)
        
        if result:
            print("✅ Packet capture is working!")
            return True
        else:
            print("⚠️ No packets captured in timeout period")
            return False
            
    except Exception as e:
        print(f"❌ Packet capture test failed: {e}")
        return False

def create_batch_file():
    """Create a batch file to run the detector as administrator"""
    batch_content = """@echo off
echo Starting DoS/DDoS Attack Detector as Administrator...
echo.
echo If packet capture still doesn't work:
echo 1. Make sure Npcap or WinPcap is installed
echo 2. Check Windows Firewall settings
echo 3. Try running this batch file as Administrator
echo.
python app.py
pause
"""
    
    with open("run_detector.bat", "w") as f:
        f.write(batch_content)
    
    print("✅ Created run_detector.bat file")

def main():
    """Main function"""
    print("=" * 60)
    print("DoS/DDoS Attack Detector - Packet Capture Fix")
    print("=" * 60)
    print()
    
    # Check if running as administrator
    if not is_admin():
        print("❌ This script must be run as Administrator!")
        print("Please right-click on Command Prompt and select 'Run as Administrator'")
        print("Then navigate to this directory and run this script again.")
        input("Press Enter to exit...")
        return
    
    print("✅ Running as Administrator")
    print()
    
    # Check system
    print(f"Operating System: {platform.system()} {platform.release()}")
    print(f"Python Version: {sys.version}")
    print()
    
    # Install packet capture drivers
    print("Step 1: Installing packet capture drivers...")
    if not install_npcap():
        print("Npcap installation failed, trying WinPcap...")
        if not install_winpcap():
            print("❌ Both Npcap and WinPcap installation failed!")
            print("Please manually install one of them:")
            print("- Npcap: https://npcap.com/")
            print("- WinPcap: https://www.winpcap.org/")
            input("Press Enter to continue...")
    
    print()
    
    # Check Python packages
    print("Step 2: Checking Python packages...")
    if not check_python_packages():
        print("❌ Failed to install required Python packages!")
        input("Press Enter to exit...")
        return
    
    print()
    
    # Test packet capture
    print("Step 3: Testing packet capture...")
    if test_packet_capture():
        print("🎉 Packet capture is working! You can now run the detector.")
    else:
        print("⚠️ Packet capture test failed. This might be due to:")
        print("1. Firewall blocking packet capture")
        print("2. Antivirus software interference")
        print("3. Network adapter issues")
        print("4. Missing or incompatible packet capture drivers")
    
    print()
    
    # Create batch file
    print("Step 4: Creating convenience files...")
    create_batch_file()
    
    print()
    print("=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    print()
    print("To start the detector:")
    print("1. Run: python app.py")
    print("2. Or double-click: run_detector.bat")
    print()
    print("If you still have issues:")
    print("1. Restart your computer after installing drivers")
    print("2. Check Windows Firewall settings")
    print("3. Try running as Administrator")
    print("4. Check antivirus software settings")
    print()
    
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
