## **🦈 Wireshark: The Ultimate Network Analysis Tool**  

Wireshark is a **network protocol analyzer** that captures and inspects network traffic. It is widely used in **cybersecurity, forensics, and CTF challenges** to analyze packets, detect vulnerabilities, and extract hidden data.  

---

# **📌 Table of Contents**  
- [📖 What is Wireshark?](#-what-is-wireshark)  
- [🎯 What Can Wireshark Do?](#-what-can-wireshark-do)  
- [🛠️ Installing Wireshark](#️-installing-wireshark)  
- [⚡ Basic Wireshark Usage](#-basic-wireshark-usage)  
- [🔍 Filtering Traffic in Wireshark](#-filtering-traffic-in-wireshark)  
- [🚀 Wireshark in CTF Challenges](#-wireshark-in-ctf-challenges)  
- [🛡️ Detecting Attacks & Malicious Traffic](#️-detecting-attacks--malicious-traffic)  
- [📂 Extracting Data from Network Traffic](#-extracting-data-from-network-traffic)  
- [📚 Further Learning & Resources](#-further-learning--resources)  

---

# **📖 What is Wireshark?**  

Wireshark is a **packet sniffer and network protocol analyzer** that captures and analyzes network traffic in real-time. It helps **inspect, filter, and reconstruct network packets** for security analysis and forensic investigations.  

📝 **Uses of Wireshark:**  
✅ Debugging network issues  
✅ Capturing and analyzing malicious traffic  
✅ Extracting data from network packets  
✅ Reverse engineering malware communications  
✅ Investigating security breaches and CTF challenges  

---

# **🎯 What Can Wireshark Do?**  

Wireshark provides **deep packet inspection** and allows you to:  

1. **Capture Network Traffic** – Monitor all incoming and outgoing network packets.  
2. **Analyze Protocols** – Inspect **TCP, UDP, HTTP, FTP, DNS, ARP, TLS, SSH**, and other protocols.  
3. **Extract Sensitive Data** – Recover **passwords, files, chat messages, and API keys**.  
4. **Detect Network Attacks** – Identify **MITM attacks, DNS poisoning, and ARP spoofing**.  
5. **Reconstruct Files & Streams** – Extract **images, documents, or entire conversations** from packets.  

---

# **🛠️ Installing Wireshark**  

### 🔵 **On Windows**  
1. Download Wireshark from [**Wireshark.org**](https://www.wireshark.org/download.html).  
2. Run the installer and select **Npcap** (for packet capturing).  

### 🍏 **On macOS**  
```bash
brew install wireshark
```

### 🐧 **On Linux**  
```bash
sudo apt update && sudo apt install wireshark -y
```
🔹 To allow non-root users to capture packets:  
```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark $USER
```

---

# **⚡ Basic Wireshark Usage**  

### 📡 **Starting a Capture**  
1. Open Wireshark.  
2. Select a network interface (Wi-Fi, Ethernet, etc.).  
3. Click **Start Capture**.  
4. Stop the capture when enough packets are collected.  

### 🔍 **Inspecting Packets**  
- Click on a packet to view its details.  
- Expand layers to analyze **Ethernet, IP, TCP, HTTP, etc.**  
- Right-click → **Follow TCP Stream** to reconstruct conversations.  

---

# **🔍 Filtering Traffic in Wireshark**  

### 🎯 **Common Filters**  
| Filter | Description |
|--------|-------------|
| `ip.addr == 192.168.1.1` | Show packets related to a specific IP |
| `http` | Show only HTTP traffic |
| `tcp.port == 80` | Show packets on port 80 (HTTP) |
| `dns` | Show only DNS queries and responses |
| `ftp` | Display FTP login sessions and file transfers |
| `tcp contains "password"` | Find packets containing the word "password" |

### 🔥 **Advanced Filters**  
| Filter | Description |
|--------|-------------|
| `!(arp or icmp or dns)` | Hide unnecessary traffic |
| `frame contains "flag"` | Search for flags in CTF challenges |
| `tls && !tcp.port == 443` | Identify encrypted traffic on non-standard ports |

---

# **🚀 Wireshark in CTF Challenges**  

Wireshark is **heavily used in CTF competitions** for **forensics and network challenges**.  

### **What Can Be Done in Wireshark? (CTF & Real-World Use Cases)**  
Wireshark allows you to **capture, filter, analyze, and extract** data from network traffic. In CTFs, challenges often involve **forensic analysis of network packets**, where you need to find **hidden flags, passwords, or malicious activity** inside a `.pcap` file.  

---

## 🔥 **Types of Wireshark Challenges in CTFs**  

### 🕵️ **1️⃣ Finding Credentials (Usernames & Passwords)**  
👉 Many CTF challenges provide a **.pcap file** containing login credentials sent over an **unencrypted** protocol like:  
- **HTTP (basic authentication, login forms in plaintext)**  
- **FTP (unencrypted file transfers with username/passwords)**  
- **Telnet (command-line sessions without encryption)**  

📌 **Example Challenge:**  
A `.pcap` file contains an **FTP login session**. Your task is to extract the username and password used to access the FTP server.  

📌 **Wireshark Trick:**  
- Use filter: `ftp` to show FTP traffic.  
- Follow the **TCP stream** to see login credentials.  

---

### 🔗 **2️⃣ Following Conversations (Reconstructing Messages & Commands)**  
👉 Sometimes, a CTF challenge involves **tracking an entire conversation** between two parties, such as:  
- **Chat messages in HTTP, IRC, or custom protocols**  
- **Commands executed in a Telnet or SSH session**  
- **Data sent from a botnet or malware infection**  

📌 **Example Challenge:**  
A `.pcap` file contains a **hacker's conversation** with a backdoor. Find out what commands were sent and what data was stolen.  

📌 **Wireshark Trick:**  
- Use `Follow TCP Stream` to see entire conversations.  
- Use filter: `tcp contains "password"` to find sensitive data.  

---

### 📂 **3️⃣ Extracting Files from Network Traffic**  
👉 Some challenges involve **file transfers**, where a file was downloaded over HTTP, FTP, SMB, or TFTP. Your job is to **recover the file** from the captured packets.  

📌 **Example Challenge:**  
A `.pcap` file contains an **image file transferred over HTTP**. Extract the image and check if there is hidden steganography inside it.  

📌 **Wireshark Trick:**  
- Use `File > Export Objects > HTTP` to extract files.  
- Check for `.zip`, `.png`, `.jpg`, `.pdf`, or other file types.  

---

### 🌐 **4️⃣ Analyzing Malicious Traffic (Malware & Phishing)**  
👉 Some challenges simulate a **malware infection** or a **phishing attack**, and you need to identify what happened.  
- **Find the attacker's IP address.**  
- **Check what malware was downloaded.**  
- **See if data was exfiltrated (stolen) from a victim's computer.**  

📌 **Example Challenge:**  
A `.pcap` file contains suspicious activity on a company network. Your task is to **identify the hacker's IP address and the malware they sent**.  

📌 **Wireshark Trick:**  
- Filter by suspect traffic: `ip.addr == 192.168.1.100`  
- Look at **DNS queries** (`dns`) to see if malware contacted a command-and-control (C2) server.  
- Check `http` or `ftp` for malware downloads.  

---

### 🎭 **5️⃣ Detecting Man-in-the-Middle (MITM) Attacks**  
👉 Some CTF challenges involve detecting **MITM attacks** like:  
- **ARP Spoofing** (attacker intercepts network traffic)  
- **SSL Stripping** (HTTPS → HTTP downgrade)  
- **Fake DNS Responses** (phishing attempts)  

📌 **Example Challenge:**  
A `.pcap` file contains suspicious HTTPS traffic. Find out if someone **intercepted and modified the data**.  

📌 **Wireshark Trick:**  
- Use filter: `arp` – Look for duplicate ARP responses (sign of ARP spoofing).  
- Use filter: `tls` – Check for sudden **HTTPS downgrades to HTTP** (SSL stripping attack).  

---

### 🎯 **6️⃣ Decoding Encoded or Compressed Data**  
👉 Sometimes, CTF challenges involve **hidden messages inside network packets**. The data might be:  
- **Base64 encoded**  
- **Hex or binary encoded**  
- **Compressed with gzip, zlib, or other formats**  

📌 **Example Challenge:**  
A `.pcap` file contains an encoded flag. Decode it to find the flag.  

📌 **Wireshark Trick:**  
- Use `Follow TCP Stream` and look for **Base64** or hex data.  
- Export raw data and use Python to decode it (`base64.b64decode(data)`).  

---

## 💡 **How to Get Better at Wireshark?**  
### 🔹 Practice with Real `.pcap` Files:  
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)  
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)  
- [PicoCTF Forensics Challenges](https://picoctf.org/)  

### 🔹 Learn from Wireshark Tutorials:  
- [Wireshark 101 (YouTube)](https://www.youtube.com/results?search_query=Wireshark+tutorial)  
- [TryHackMe: Wireshark Room](https://tryhackme.com/)  

---

## 🏆 **Want a Real Challenge?**  
---

# **🛡️ Detecting Attacks & Malicious Traffic**  

### **🔴 1. Man-in-the-Middle (MITM) Attacks**  
- Attackers intercept network traffic using **ARP spoofing** or **SSL stripping**.  
- 🛠️ Detect with:  
  ```plaintext
  arp | dns
  ```

### **🔴 2. DNS Spoofing & Phishing**  
- Attackers redirect victims to malicious websites.  
- 🛠️ Detect with:  
  ```plaintext
  dns && ip.src != expected_server_ip
  ```

### **🔴 3. Malware Communication**  
- Detect **malware downloads** or **data exfiltration**.  
- 🛠️ Detect with:  
  ```plaintext
  http contains "malware"
  ```

---

# **📂 Extracting Data from Network Traffic**  

### 🖼️ **Recovering Files (Images, PDFs, ZIPs, etc.)**  
1. Open `.pcap` file.  
2. **File > Export Objects > HTTP/FTP**.  
3. Save extracted files for further analysis.  

### 📜 **Finding Hidden Data in TCP Streams**  
- 🔍 Use: `Follow TCP Stream` to check for **Base64 encoded or hex-encoded data**.  
- 🛠️ Decode using Python:  
  ```python
  import base64
  print(base64.b64decode("encoded_data"))
  ```

---

# **📚 Further Learning & Resources**  

### ✅ **Practice with Real Capture Files**  
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)  
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)  
- [PicoCTF Forensics Challenges](https://picoctf.org/)  

### 📖 **Learn More About Wireshark**  
- [Wireshark Official Documentation](https://www.wireshark.org/docs/)  
- [TryHackMe Wireshark Room](https://tryhackme.com/)  

---

🔥 **Keep practicing! Wireshark is one of the most powerful tools in cybersecurity, and mastering it will make you a strong CTF player and network analyst.** 🚀
