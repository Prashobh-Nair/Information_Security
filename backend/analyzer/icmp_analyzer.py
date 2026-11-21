"""
NetSecure ICMP Analyzer
Provides deep lookup, explanations, RFC classifications, and ping round-trip correlation for ICMP packets.
Directly fulfills Lab Exercise 12 Requirement #6:
"Identify source IP, destination IP, network layer protocols, source MAC, destination MAC, and ICMP packet type, code, and meaning."
"""

from typing import Dict, Any, Tuple

# Comprehensive ICMP Types & Codes Dictionary (RFC 792, RFC 1122, RFC 1812)
ICMP_LOOKUP = {
    0: {
        "name": "Echo Reply",
        "description": "Standard ICMP response to an Echo Request (Ping). Sent by Machine B when responding to Machine A.",
        "codes": {
            0: "Echo Reply (Standard ping response from target host)"
        }
    },
    3: {
        "name": "Destination Unreachable",
        "description": "The destination network, host, port, or protocol is inaccessible from the sending router/host.",
        "codes": {
            0: "Net Unreachable (Routing table has no path to network)",
            1: "Host Unreachable (Target host does not respond or ARP failed)",
            2: "Protocol Unreachable (Transport protocol not supported on destination)",
            3: "Port Unreachable (Target UDP/TCP port is not listening)",
            4: "Fragmentation Needed and DF (Don't Fragment) flag was set",
            5: "Source Route Failed",
            6: "Destination Network Unknown",
            7: "Destination Host Unknown",
            8: "Source Host Isolated",
            9: "Communication with Destination Network is Administratively Prohibited",
            10: "Communication with Destination Host is Administratively Prohibited (Firewall blocked)",
            11: "Destination Network Unreachable for Type of Service",
            12: "Destination Host Unreachable for Type of Service",
            13: "Communication Administratively Prohibited by Filter",
            14: "Host Precedence Violation",
            15: "Precedence Cutoff in Effect"
        }
    },
    4: {
        "name": "Source Quench (Deprecated)",
        "description": "Flow control request to slow down transmission rate.",
        "codes": {
            0: "Source Quench"
        }
    },
    5: {
        "name": "Redirect Message",
        "description": "Informs a sending host to use another gateway/router that is on a shorter route.",
        "codes": {
            0: "Redirect Datagram for the Network",
            1: "Redirect Datagram for the Host",
            2: "Redirect Datagram for the Type of Service and Network",
            3: "Redirect Datagram for the Type of Service and Host"
        }
    },
    8: {
        "name": "Echo Request",
        "description": "Ping request datagram. Sent by Machine A to verify if Machine B is reachable on the Ethernet LAN.",
        "codes": {
            0: "Echo Request (Standard ping request probe)"
        }
    },
    9: {
        "name": "Router Advertisement",
        "description": "Router discovery advertisement sent to hosts.",
        "codes": {
            0: "Normal router advertisement"
        }
    },
    10: {
        "name": "Router Solicitation",
        "description": "Host discovery query for local routers.",
        "codes": {
            0: "Router discovery query"
        }
    },
    11: {
        "name": "Time Exceeded (TTL Expired)",
        "description": "TTL reached zero in transit, or fragment reassembly time exceeded. Crucial for Traceroute mechanics.",
        "codes": {
            0: "Time to Live (TTL) Exceeded in Transit (Traceroute hop response)",
            1: "Fragment Reassembly Time Exceeded"
        }
    },
    12: {
        "name": "Parameter Problem",
        "description": "An error occurred in the IP header processing.",
        "codes": {
            0: "Pointer indicates the error in IP header",
            1: "Missing a Required Option",
            2: "Bad Length"
        }
    },
    13: {
        "name": "Timestamp Request",
        "description": "Query used for clock synchronization and measuring network latency.",
        "codes": {
            0: "Timestamp Request"
        }
    },
    14: {
        "name": "Timestamp Reply",
        "description": "Response containing timestamp values for latency calculations.",
        "codes": {
            0: "Timestamp Reply"
        }
    }
}

def analyze_icmp(icmp_type: int | None, icmp_code: int | None) -> Dict[str, Any]:
    if icmp_type is None:
        return {
            "type": None,
            "code": None,
            "type_name": "N/A",
            "meaning": "Not an ICMP packet",
            "description": "",
            "is_echo_request": False,
            "is_echo_reply": False,
            "academic_explanation": ""
        }
    
    code = icmp_code if icmp_code is not None else 0
    type_info = ICMP_LOOKUP.get(icmp_type)
    
    if type_info:
        type_name = type_info["name"]
        description = type_info["description"]
        code_meaning = type_info["codes"].get(code, f"Code {code} (Specific sub-condition)")
    else:
        type_name = f"ICMP Type {icmp_type}"
        description = "Unassigned or experimental ICMP type"
        code_meaning = f"Code {code}"

    meaning = f"Type {icmp_type}, Code {code}: {code_meaning}"
    is_echo_request = (icmp_type == 8 and code == 0)
    is_echo_reply = (icmp_type == 0 and code == 0)

    # Academic explanation specific to Lab Exercise 12
    if is_echo_request:
        explanation = (
            "Machine A transmits an ICMP Echo Request (Type 8, Code 0) encapsulated within an IP packet "
            "(Protocol 1) across the Ethernet LAN to Machine B's IP address. It contains an identifier and "
            "sequence number used to match the corresponding reply."
        )
    elif is_echo_reply:
        explanation = (
            "Machine B receives the Echo Request and immediately generates an ICMP Echo Reply (Type 0, Code 0). "
            "Machine B swaps the Source and Destination IP & MAC addresses, preserving the identifier and sequence "
            "number so Machine A can measure Round Trip Time (RTT)."
        )
    elif icmp_type == 3:
        explanation = (
            f"Machine was unable to deliver packet to target host or port: {code_meaning}. "
            "Frequently generated when a service is not listening on the specified port or firewall drops probe."
        )
    elif icmp_type == 11:
        explanation = (
            "The IP Packet Time-To-Live (TTL) decremented to 0 at an intermediate hop. "
            "Used by diagnostic tools like traceroute/tracert to map Layer 3 topology."
        )
    else:
        explanation = f"Standard ICMP diagnostic message: {description}"

    return {
        "type": icmp_type,
        "code": code,
        "type_name": type_name,
        "meaning": meaning,
        "description": description,
        "is_echo_request": is_echo_request,
        "is_echo_reply": is_echo_reply,
        "academic_explanation": explanation
    }
