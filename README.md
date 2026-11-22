# NetSecure - Real-Time Wireshark Telemetry & Security Lab (Exercise 12)

A clean, light-themed network packet monitoring and security analysis system built from scratch to satisfy **Exercise 12** of Information Security.

---

## 🌟 Key Features

1. **Strictly Real Hardware Identity (No Fake Data)**:
   - **Machine A**: Automatically binds to your laptop's real IP (`192.168.1.6`) and physical MAC (`1c:ce:51:32:87:5e`) on `Wi-Fi`.
   - **Machine B**: Resolves the target host's real MAC dynamically from the Windows ARP cache (`arp -a` / `Get-NetNeighbor`).

2. **Live HTTP Password Sniffing Reflected in Desktop Wireshark**:
   - The server binds to `0.0.0.0:5000` (`http://192.168.1.6:5000`).
   - When you submit a password on the website, the packet traverses the physical `Wi-Fi` interface.
   - **Your actual desktop Wireshark app captures the plain text password in real time**!
   - Contrasted with **HTTPS (TLS 1.3 / AES-256-GCM)** where credentials turn into opaque ciphertext.

3. **Wireshark-Style 3-Pane Interface**:
   - **Top Pane**: Packet list (`No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`).
   - **Middle Pane**: OSI layer tree (`Frame`, `Ethernet II`, `IPv4`, `TCP/UDP/ICMP`, `HTTP`).
   - **Bottom Pane**: Memory-dump Hex & ASCII byte inspector.

4. **Exercise 12 Six Fields Answered**:
   - Source IP (`192.168.1.6`)
   - Destination IP (`192.168.1.1` or target)
   - Network Layer Protocol (`IPv4 / ICMP`)
   - Source MAC Address (`1c:ce:51:32:87:5e`)
   - Destination MAC Address (`70:b6:4f:1e:04:f1`)
   - ICMP Packet Type Code & Meaning (`Type 8 Code 0 Echo Request` & `Type 0 Code 0 Echo Reply`).

5. **Multi-Protocol Realization**:
   - Dedicated inspection for **HTTP, HTTPS, DNS, ARP, and FTP**.

---

## 🚀 How to Run

### Method 1: One-Click Run
Double-click **`start.bat`** in this folder!

### Method 2: Command Line
Open a terminal in this folder and run:
```powershell
python -m uvicorn backend.app:app --host 0.0.0.0 --port 5000 --reload
```
Open your browser at **`http://192.168.1.6:5000`** (or `http://localhost:5000`).

---

## 🔍 How to Test in Desktop Wireshark (Step-by-Step)

1. Open **Wireshark** on your laptop and start capturing on **Wi-Fi**.
2. In the Wireshark filter bar at the top, type:
   ```text
   http.request.method == "POST"
   ```
   *(and press Enter)*
3. In your browser at `http://192.168.1.6:5000`, type any username and password and click **Submit Credentials via HTTP**.
4. Look at **Wireshark**: A green row `POST /login HTTP/1.1` appears immediately!
5. In Wireshark, **right-click that row** → **Follow** → **TCP Stream**:
   You will see your password in plain, bright red text!
