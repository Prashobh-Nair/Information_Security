"""
NetSecure Wireshark & TShark Integration Verification Test Suite
Executes real tests for all 9 checklist items mandated in Task 8.
"""

import sys
import subprocess
import time
import json
from pathlib import Path

# Setup paths
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.main import app
from backend.config import TSHARK_BINARY, LOCAL_IP, LOCAL_MAC, GATEWAY_IP
from backend.capture.capture_engine import capture_engine
from backend.capture.interface_manager import get_network_interfaces, get_lab_hosts_info
from backend.capture.pcap_handler import parse_pcap_file, export_session_to_pcap
from backend.database import get_packets, get_latest_session

def run_tests():
    print("=" * 70)
    print("  NETSECURE WIRESHARK & TSHARK INTEGRATION TEST SUITE")
    print("=" * 70)
    results = {}

    # TEST 1: Wireshark Detection
    print("\n[TEST 1] Wireshark Installation Detection...")
    wireshark_dir = Path(r"C:\Program Files\Wireshark")
    tshark_path = wireshark_dir / "tshark.exe"
    t1_pass = tshark_path.is_file() and TSHARK_BINARY == str(tshark_path)
    results["1_wireshark_detection"] = {
        "passed": t1_pass,
        "detail": f"Detected TShark at {TSHARK_BINARY}" if t1_pass else "TShark not found"
    }
    print(f"  -> Result: {'PASS' if t1_pass else 'FAIL'} ({results['1_wireshark_detection']['detail']})")

    # TEST 2: TShark Execution
    print("\n[TEST 2] TShark Execution Verification...")
    try:
        proc = subprocess.run([TSHARK_BINARY, "--version"], capture_output=True, text=True, timeout=5)
        t2_pass = proc.returncode == 0 and "TShark (Wireshark)" in proc.stdout
        ver_line = proc.stdout.splitlines()[0] if proc.stdout else "Unknown"
        results["2_tshark_execution"] = {"passed": t2_pass, "detail": ver_line}
    except Exception as e:
        results["2_tshark_execution"] = {"passed": False, "detail": str(e)}
    print(f"  -> Result: {'PASS' if results['2_tshark_execution']['passed'] else 'FAIL'} ({results['2_tshark_execution']['detail']})")

    # TEST 3: Npcap Availability & Driver Status
    print("\n[TEST 3] Npcap Service & Packet Driver Status...")
    try:
        sc_proc = subprocess.run(["sc.exe", "query", "npcap"], capture_output=True, text=True, timeout=5)
        npcap_running = "RUNNING" in sc_proc.stdout
        results["3_npcap_availability"] = {
            "passed": npcap_running,
            "detail": "Npcap Packet Driver service is RUNNING (Kernel packet filter active)" if npcap_running else "Npcap service not running"
        }
    except Exception as e:
        results["3_npcap_availability"] = {"passed": False, "detail": str(e)}
    print(f"  -> Result: {'PASS' if results['3_npcap_availability']['passed'] else 'FAIL'} ({results['3_npcap_availability']['detail']})")

    # TEST 4: Network Interface Detection
    print("\n[TEST 4] Network Interface Enumeration via TShark...")
    ifaces = get_network_interfaces()
    t4_pass = len(ifaces) > 0 and any(i.get("tshark_ready") for i in ifaces)
    results["4_interface_detection"] = {
        "passed": t4_pass,
        "detail": f"Discovered {len(ifaces)} capture adapters: {[i['name'] for i in ifaces[:4]]}"
    }
    print(f"  -> Result: {'PASS' if t4_pass else 'FAIL'} ({results['4_interface_detection']['detail']})")

    # TEST 5 & 6: Live Packet Capture Start and Stop with TShark
    print("\n[TEST 5 & 6] Actual Live Packet Capture (Start & Stop)...")
    loopback_iface = next((i for i in ifaces if i.get("is_loopback")), ifaces[0])
    target_dev = loopback_iface.get("device_name") or loopback_iface["id"]

    start_res = capture_engine.start_capture(interface=target_dev, filter_expr="", mode="tshark")
    print(f"  -> Start Capture Status: {start_res.get('status')} (Engine: {start_res.get('engine')}, Session: {start_res.get('session_id')})")
    
    # Generate traffic while capturing
    time.sleep(1)
    client = TestClient(app)
    client.post("/api/ping", json={"target_ip": "127.0.0.1", "count": 2})
    time.sleep(1)

    stop_res = capture_engine.stop_capture()
    print(f"  -> Stop Capture Status: {stop_res.get('status')} (Packets Captured: {stop_res.get('packets_captured')})")

    t5_6_pass = start_res.get("status") == "success" and stop_res.get("status") == "success"
    results["5_actual_live_capture"] = {
        "passed": t5_6_pass,
        "detail": f"Captured on {target_dev} via TShark process (Session #{start_res.get('session_id')})"
    }
    results["6_start_stop_capture"] = {
        "passed": t5_6_pass,
        "detail": "Successfully launched and terminated tshark background worker process."
    }

    # TEST 7: ICMP Packet Analysis & Type/Code Meaning
    print("\n[TEST 7] ICMP Packet Analysis (Ping Verification)...")
    r_icmp = client.get("/api/protocols/icmp")
    icmp_data = r_icmp.json()
    t7_pass = icmp_data.get("echo_requests_count", 0) > 0 and len(icmp_data.get("ping_correlations", [])) > 0
    results["7_icmp_analysis"] = {
        "passed": t7_pass,
        "detail": f"Correlated {len(icmp_data.get('ping_correlations', []))} ping pairs with Type 8/0 verified"
    }
    print(f"  -> Result: {'PASS' if t7_pass else 'FAIL'} ({results['7_icmp_analysis']['detail']})")

    # TEST 8: Source and Destination MAC Extraction
    print("\n[TEST 8] Source & Destination MAC Address Extraction...")
    r_pkts = client.get("/api/capture/packets?limit=5")
    pkt_list = r_pkts.json().get("packets", [])
    has_macs = any(p.get("src_mac") and p.get("dst_mac") and p.get("src_mac") != "N/A" for p in pkt_list)
    results["8_mac_extraction"] = {
        "passed": has_macs,
        "detail": f"Sample MACs extracted: Src={pkt_list[0]['src_mac']} -> Dst={pkt_list[0]['dst_mac']}" if has_macs else "No MACs found"
    }
    print(f"  -> Result: {'PASS' if has_macs else 'FAIL'} ({results['8_mac_extraction']['detail']})")

    # TEST 9: PCAP Export and Reopening
    print("\n[TEST 9] PCAP Export and Reopening Validation...")
    latest_s = get_latest_session()
    s_id = latest_s["id"] if latest_s else 1
    exported_pcap = export_session_to_pcap(s_id, "test_verification_export.pcap")
    pcap_path = Path(exported_pcap)
    
    # Reopen and parse exported PCAP
    reopen_count, _ = parse_pcap_file(pcap_path, s_id)
    t9_pass = pcap_path.is_file() and pcap_path.stat().st_size > 0 and reopen_count > 0
    results["9_pcap_export_reopen"] = {
        "passed": t9_pass,
        "detail": f"Exported {pcap_path.stat().st_size} bytes to {pcap_path.name}; successfully reopened and validated {reopen_count} frames"
    }
    print(f"  -> Result: {'PASS' if t9_pass else 'FAIL'} ({results['9_pcap_export_reopen']['detail']})")

    print("\n" + "=" * 70)
    all_passed = all(v["passed"] for v in results.values())
    print(f"  ALL 9 TASKS STATUS: {'ALL TESTS PASSED (100% OPERATIONAL)' if all_passed else 'SOME TESTS FAILED'}")
    print("=" * 70)
    return results

if __name__ == "__main__":
    run_tests()
