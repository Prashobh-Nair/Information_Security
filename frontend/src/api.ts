/**
 * NetSecure REST API & WebSocket Client with Standalone Cloud & GitHub Pages Fallbacks
 */

const API_BASE = '/api';

export interface SystemStatus {
  status: string;
  tshark_installed: boolean;
  tshark_path: string;
  capture_active: boolean;
  active_interface: string | null;
  engine_mode: string;
  team_info: {
    project_name: string;
    course: string;
    lab_exercise: string;
    team_members: Array<{ name: string; role: string }>;
  };
}

export interface NetworkInterface {
  id: string;
  name: string;
  description: string;
  mac: string;
  ipv4: string;
  status: string;
  speed: string;
  is_up: boolean;
  is_loopback: boolean;
}

export interface LabHosts {
  machine_a: { name: string; ip: string; mac: string; interface: string; role: string };
  machine_b: { name: string; ip: string; mac: string; interface: string; role: string };
  network: { topology: string; subnet: string; lab_exercise: string };
}

export interface PacketItem {
  id?: number;
  packet_num: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_mac: string;
  dst_mac: string;
  protocol: string;
  length: number;
  info: string;
  l4_proto: string;
  src_port: number | null;
  dst_port: number | null;
  icmp_type: number | null;
  icmp_code: number | null;
  icmp_meaning: string;
  payload_hex: string;
  payload_ascii: string;
  details?: any;
}

export interface PingResult {
  target_ip: string;
  status: string;
  packets_sent: number;
  packets_received: number;
  packets_lost: number;
  packet_loss_pct: number;
  min_rtt_ms: number;
  avg_rtt_ms: number;
  max_rtt_ms: number;
  jitter_ms: number;
  raw_output: string;
  timestamp: string;
}

export interface DashboardStats {
  total_packets: number;
  total_bytes: number;
  counts: Record<string, number>;
  protocol_distribution: Array<{ name: string; value: number; percentage: number; color: string }>;
  traffic_timeline: Array<any>;
  top_talkers: Array<{ conversation: string; packet_count: number; share_pct: number }>;
  security_summary: {
    credential_leaks: number;
    unencrypted_http: number;
    total_alerts: number;
  };
}

// Fallback Mock Data for Standalone Cloud / GitHub Pages hosting
const MOCK_SYSTEM_STATUS: SystemStatus = {
  status: 'online',
  tshark_installed: true,
  tshark_path: 'C:\\Program Files\\Wireshark\\tshark.exe',
  capture_active: false,
  active_interface: 'Wi-Fi [4]',
  engine_mode: 'tshark',
  team_info: {
    project_name: 'NetSecure Enterprise',
    course: 'Information Security (Semester 5)',
    lab_exercise: 'Lab Exercise 12: LAN Traffic & Password Sniffing Analysis',
    team_members: [
      { name: 'Student Lead', role: 'Machine A Operator (Traffic Capture & Analysis)' },
      { name: 'Team Member 2', role: 'Machine B Operator (Target Host Administration & Ping)' },
      { name: 'Team Member 3', role: 'HTTP vs HTTPS Password Sniffing Demonstration' },
      { name: 'Team Member 4', role: 'Protocol Dissection (ICMP, ARP, DNS, FTP) & Documentation' }
    ]
  }
};

const MOCK_LAB_HOSTS: LabHosts = {
  machine_a: { name: 'Lab Machine A', ip: '192.168.1.6', mac: '1c:ce:51:32:87:5e', interface: 'Wi-Fi', role: 'Sender / Examiner Host' },
  machine_b: { name: 'Lab Machine B', ip: '192.168.1.1', mac: '00:0c:29:4d:5e:6f', interface: 'GigabitEthernet0', role: 'Target / Receiver Host' },
  network: { topology: 'Ethernet LAN (IEEE 802.3)', subnet: '255.255.255.0 (/24)', lab_exercise: 'Lab #12' }
};

const MOCK_INTERFACES: NetworkInterface[] = [
  { id: '1', name: 'Wi-Fi [4]', description: 'Intel Wi-Fi 6 AX201 160MHz', mac: '1c:ce:51:32:87:5e', ipv4: '192.168.1.6', status: 'Active (Up)', speed: '1.2 Gbps', is_up: true, is_loopback: false },
  { id: '2', name: 'Npcap Loopback Adapter [7]', description: 'Npcap Loopback Adapter for Localhost Interception', mac: '00:00:00:00:00:00', ipv4: '127.0.0.1', status: 'Active (Up)', speed: '10 Gbps', is_up: true, is_loopback: true },
  { id: '3', name: 'Local Area Connection* 10 [1]', description: 'Microsoft Wi-Fi Direct Virtual Adapter', mac: '1e:ce:51:32:87:5e', ipv4: 'N/A', status: 'Disconnected', speed: 'N/A', is_up: false, is_loopback: false }
];

const MOCK_PACKETS: PacketItem[] = [
  {
    packet_num: 1, timestamp: '14:25:01.102', src_ip: '192.168.1.6', dst_ip: '192.168.1.1',
    src_mac: '1c:ce:51:32:87:5e', dst_mac: '00:0c:29:4d:5e:6f', protocol: 'ICMP', length: 74,
    info: 'Echo (ping) request  id=0x0001, seq=1/256, ttl=128',
    l4_proto: 'ICMP', src_port: null, dst_port: null, icmp_type: 8, icmp_code: 0, icmp_meaning: 'Echo Request (Ping Probe)',
    payload_hex: '00 0c 29 4d 5e 6f 1c ce 51 32 87 5e 08 00 45 00 00 3c 1a 2b 00 00 80 01 7c 3b c0 a8 01 06 c0 a8 01 01 08 00 4d 5a 00 01 00 01 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69',
    payload_ascii: '..)M^o..Q2..E..<.+..|;....MZ..abcdefghijklmnopqrstuvwabcdfghi',
    details: {
      ethernet: { src_mac: '1c:ce:51:32:87:5e', dst_mac: '00:0c:29:4d:5e:6f', ether_type: 'IPv4 (0x0800)' },
      network: { protocol: 'IPv4', src_ip: '192.168.1.6', dst_ip: '192.168.1.1', ttl: 128, checksum: '0x7c3b', total_length: 60 },
      transport: { type: 8, code: 0, sequence_number: 1, identifier: 1, meaning: 'Echo Request (Ping)', academic_explanation: "Machine A generates an ICMP Echo Request (Type 8, Code 0) to verify Machine B's network layer reachability." }
    }
  },
  {
    packet_num: 2, timestamp: '14:25:01.104', src_ip: '192.168.1.1', dst_ip: '192.168.1.6',
    src_mac: '00:0c:29:4d:5e:6f', dst_mac: '1c:ce:51:32:87:5e', protocol: 'ICMP', length: 74,
    info: 'Echo (ping) reply    id=0x0001, seq=1/256, ttl=64 (reply in 1.84ms)',
    l4_proto: 'ICMP', src_port: null, dst_port: null, icmp_type: 0, icmp_code: 0, icmp_meaning: 'Echo Reply (Ping Response)',
    payload_hex: '1c ce 51 32 87 5e 00 0c 29 4d 5e 6f 08 00 45 00 00 3c 2b 3c 00 00 40 01 3c 2b c0 a8 01 01 c0 a8 01 06 00 00 55 5a 00 01 00 01 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69',
    payload_ascii: '..Q2..MZ..E..<+<..@.<+....UZ..abcdefghijklmnopqrstuvwabcdfghi',
    details: {
      ethernet: { src_mac: '00:0c:29:4d:5e:6f', dst_mac: '1c:ce:51:32:87:5e', ether_type: 'IPv4 (0x0800)' },
      network: { protocol: 'IPv4', src_ip: '192.168.1.1', dst_ip: '192.168.1.6', ttl: 64, checksum: '0x3c2b', total_length: 60 },
      transport: { type: 0, code: 0, sequence_number: 1, identifier: 1, meaning: 'Echo Reply (Ping Response)', academic_explanation: 'Machine B replies with ICMP Echo Reply (Type 0, Code 0), proving bidirectional connectivity.' }
    }
  },
  {
    packet_num: 3, timestamp: '14:25:02.312', src_ip: '192.168.1.6', dst_ip: '192.168.1.1',
    src_mac: '1c:ce:51:32:87:5e', dst_mac: '00:0c:29:4d:5e:6f', protocol: 'HTTP', length: 248,
    info: 'POST /api/dummy/login HTTP/1.1 (application/x-www-form-urlencoded) [CLEARTEXT CREDENTIALS LEAKED]',
    l4_proto: 'TCP', src_port: 52140, dst_port: 80, icmp_type: null, icmp_code: null, icmp_meaning: '',
    payload_hex: '50 4f 53 54 20 2f 61 70 69 2f 64 75 6d 6d 79 2f 6c 6f 67 69 6e 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 31 39 32 2e 31 36 38 2e 31 2e 31 0d 0a 0d 0a 75 73 65 72 6e 61 6d 65 3d 73 74 75 64 65 6e 74 5f 61 6c 65 78 26 70 61 73 73 77 6f 72 64 3d 53 65 63 72 33 74 4c 61 62 50 40 73 73 77 30 72 64 21',
    payload_ascii: 'POST /api/dummy/login HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\nusername=student_alex&password=Secr3tLabP@ssw0rd!',
    details: {
      ethernet: { src_mac: '1c:ce:51:32:87:5e', dst_mac: '00:0c:29:4d:5e:6f', ether_type: 'IPv4 (0x0800)' },
      network: { protocol: 'IPv4', src_ip: '192.168.1.6', dst_ip: '192.168.1.1', ttl: 128 },
      transport: { src_port: 52140, dst_port: 80, flags: 'PSH, ACK' },
      application: { protocol: 'HTTP', method: 'POST', uri: '/api/dummy/login', is_encrypted: false, body: 'username=student_alex&password=Secr3tLabP@ssw0rd!' },
      security: { has_credentials: true, leak_type: 'Cleartext HTTP Form Submission' }
    }
  },
  {
    packet_num: 4, timestamp: '14:25:03.119', src_ip: '192.168.1.6', dst_ip: '192.168.1.1',
    src_mac: '1c:ce:51:32:87:5e', dst_mac: '00:0c:29:4d:5e:6f', protocol: 'HTTPS', length: 1440,
    info: 'TLSv1.3 Application Data (Encrypted Ciphertext Block)',
    l4_proto: 'TCP', src_port: 52144, dst_port: 443, icmp_type: null, icmp_code: null, icmp_meaning: '',
    payload_hex: '17 03 03 05 a0 a8 b1 99 e4 f2 10 32 c8 b7 e2 a0 91 f5 dc 84 9b 72 fa de ee 21 a8 99 c7 2b 44 8a c9 e1 a2',
    payload_ascii: '...........2...........!...+D....',
    details: {
      ethernet: { src_mac: '1c:ce:51:32:87:5e', dst_mac: '00:0c:29:4d:5e:6f', ether_type: 'IPv4 (0x0800)' },
      network: { protocol: 'IPv4', src_ip: '192.168.1.6', dst_ip: '192.168.1.1', ttl: 128 },
      transport: { src_port: 52144, dst_port: 443, flags: 'ACK' },
      application: { protocol: 'HTTPS', is_encrypted: true, record_type: 'Application Data (0x17)', tls_version: 'TLS 1.3' }
    }
  }
];

const MOCK_STATS: DashboardStats = {
  total_packets: 46,
  total_bytes: 18450,
  counts: { TCP: 18, UDP: 8, ICMP: 12, HTTP: 3, HTTPS: 3, DNS: 2, ARP: 2, FTP: 2 },
  protocol_distribution: [
    { name: 'ICMP', value: 12, percentage: 26.1, color: '#16856A' },
    { name: 'TCP', value: 18, percentage: 39.1, color: '#1D4ED8' },
    { name: 'HTTP', value: 3, percentage: 6.5, color: '#C18A35' },
    { name: 'HTTPS', value: 3, percentage: 6.5, color: '#0284C7' },
    { name: 'FTP', value: 2, percentage: 4.3, color: '#C64747' },
    { name: 'DNS', value: 4, percentage: 8.7, color: '#7C3AED' },
    { name: 'ARP', value: 4, percentage: 8.7, color: '#DB2777' }
  ],
  traffic_timeline: [
    { time: '14:25:00', packets: 4, icmp: 2, http: 0, https: 1 },
    { time: '14:25:05', packets: 14, icmp: 4, http: 2, https: 0 },
    { time: '14:25:10', packets: 18, icmp: 4, http: 1, https: 2 },
    { time: '14:25:15', packets: 10, icmp: 2, http: 0, https: 0 }
  ],
  top_talkers: [
    { conversation: '192.168.1.6 ⇄ 192.168.1.1', packet_count: 36, share_pct: 78.3 },
    { conversation: '192.168.1.6 ⇄ 8.8.8.8', packet_count: 10, share_pct: 21.7 }
  ],
  security_summary: { credential_leaks: 1, unencrypted_http: 3, total_alerts: 1 }
};

export async function getSystemStatus(): Promise<SystemStatus> {
  try {
    const res = await fetch(`${API_BASE}/system/status`);
    if (res.ok) return await res.json();
  } catch (_) {}
  return MOCK_SYSTEM_STATUS;
}

export async function getInterfaces(): Promise<{ interfaces: NetworkInterface[]; tshark_installed: boolean }> {
  try {
    const res = await fetch(`${API_BASE}/system/interfaces`);
    if (res.ok) return await res.json();
  } catch (_) {}
  return { interfaces: MOCK_INTERFACES, tshark_installed: true };
}

export async function getLabHosts(): Promise<LabHosts> {
  try {
    const res = await fetch(`${API_BASE}/system/lab-hosts`);
    if (res.ok) return await res.json();
  } catch (_) {}
  return MOCK_LAB_HOSTS;
}

export async function saveLabSettings(data: any): Promise<any> {
  try {
    const res = await fetch(`${API_BASE}/system/lab-settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (res.ok) return await res.json();
  } catch (_) {}
  return { status: 'success', message: 'Config updated.' };
}

export async function executePing(target_ip: string, count: number = 4, timeout_sec: number = 2): Promise<PingResult> {
  try {
    const res = await fetch(`${API_BASE}/ping`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_ip, count, timeout_sec })
    });
    if (res.ok) return await res.json();
  } catch (_) {}

  // Fallback realistic ping simulation for cloud/GitHub Pages
  return {
    target_ip,
    status: 'SUCCESS',
    packets_sent: count,
    packets_received: count,
    packets_lost: 0,
    packet_loss_pct: 0,
    min_rtt_ms: 1.2,
    avg_rtt_ms: 2.1,
    max_rtt_ms: 3.4,
    jitter_ms: 0.8,
    raw_output: `Pinging ${target_ip} with 32 bytes of data:\nReply from ${target_ip}: bytes=32 time=1.84ms TTL=64\nReply from ${target_ip}: bytes=32 time=2.10ms TTL=64\nReply from ${target_ip}: bytes=32 time=1.95ms TTL=64\nReply from ${target_ip}: bytes=32 time=2.51ms TTL=64\n\nPing statistics for ${target_ip}:\n    Packets: Sent = ${count}, Received = ${count}, Lost = 0 (0% loss),\nApproximate round trip times in milli-seconds:\n    Minimum = 1.2ms, Maximum = 3.4ms, Average = 2.1ms`,
    timestamp: new Date().toLocaleTimeString()
  };
}

export async function getPingLogs(): Promise<{ logs: PingResult[] }> {
  try {
    const res = await fetch(`${API_BASE}/ping/logs`);
    if (res.ok) return await res.json();
  } catch (_) {}
  return { logs: [] };
}

export async function startCapture(interface_name: string, filter_expr: string = '', mode: string = 'auto', confirm_authorized: boolean = true) {
  try {
    const res = await fetch(`${API_BASE}/capture/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: interface_name, filter_expr, mode, confirm_authorized })
    });
    if (res.ok) return await res.json();
  } catch (_) {}
  return { status: 'success', message: 'Capture active.' };
}

export async function stopCapture() {
  try {
    const res = await fetch(`${API_BASE}/capture/stop`, { method: 'POST' });
    if (res.ok) return await res.json();
  } catch (_) {}
  return { status: 'success', message: 'Capture stopped.' };
}

export async function getCaptureStatus() {
  try {
    const res = await fetch(`${API_BASE}/capture/status`);
    if (res.ok) return await res.json();
  } catch (_) {}
  return { is_running: false };
}

export async function getPackets(params: { session_id?: number; protocol?: string; search?: string; limit?: number; offset?: number } = {}) {
  try {
    const query = new URLSearchParams();
    if (params.session_id) query.set('session_id', params.session_id.toString());
    if (params.protocol) query.set('protocol', params.protocol);
    if (params.search) query.set('search', params.search);
    if (params.limit) query.set('limit', params.limit.toString());
    if (params.offset) query.set('offset', params.offset.toString());
    
    const res = await fetch(`${API_BASE}/capture/packets?${query.toString()}`);
    if (res.ok) return await res.json();
  } catch (_) {}
  return { packets: MOCK_PACKETS, total_count: MOCK_PACKETS.length };
}

export async function getPacketById(id: number): Promise<PacketItem> {
  try {
    const res = await fetch(`${API_BASE}/capture/packets/${id}`);
    if (res.ok) return await res.json();
  } catch (_) {}
  return MOCK_PACKETS[0];
}

export async function uploadPcap(file: File) {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/capture/upload`, {
      method: 'POST',
      body: formData
    });
    if (res.ok) return await res.json();
  } catch (_) {}
  return { status: 'success', packet_count: 26 };
}

export async function loadSamplePcap() {
  try {
    const res = await fetch(`${API_BASE}/capture/load-sample`, { method: 'POST' });
    if (res.ok) return await res.json();
  } catch (_) {}
  return { status: 'success', message: 'Sample loaded.' };
}

export async function getDashboardStats(sessionId?: number): Promise<DashboardStats> {
  try {
    const url = sessionId ? `${API_BASE}/stats?session_id=${sessionId}` : `${API_BASE}/stats`;
    const res = await fetch(url);
    if (res.ok) return await res.json();
  } catch (_) {}
  return MOCK_STATS;
}

export async function getIcmpAnalysis(sessionId?: number) {
  try {
    const url = sessionId ? `${API_BASE}/protocols/icmp?session_id=${sessionId}` : `${API_BASE}/protocols/icmp`;
    const res = await fetch(url);
    if (res.ok) return await res.json();
  } catch (_) {}
  return {
    lab_verdict: "Confirmed: Bidirectional ICMP Echo exchange verified between Machine A (192.168.1.6) and Machine B (192.168.1.1). Type 8 requests matched with Type 0 replies.",
    echo_requests_count: 6,
    echo_replies_count: 6,
    total_icmp_packets: 12,
    ping_correlations: [
      { request_num: 1, request_time: '14:25:01.102', reply_num: 2, source_host: '192.168.1.6', target_host: '192.168.1.1', type_code_summary: 'Type 8, Code 0 ⇄ Type 0, Code 0', status: 'Correlated (1.84ms)' }
    ]
  };
}

export async function getArpAnalysis(sessionId?: number) {
  try {
    const url = sessionId ? `${API_BASE}/protocols/arp?session_id=${sessionId}` : `${API_BASE}/protocols/arp`;
    const res = await fetch(url);
    if (res.ok) return await res.json();
  } catch (_) {}
  return {
    academic_note: "ARP resolves network layer IPv4 addresses to data link hardware MAC addresses.",
    resolved_ip_mac_table: [
      { ip: '192.168.1.6', mac: '1c:ce:51:32:87:5e' },
      { ip: '192.168.1.1', mac: '00:0c:29:4d:5e:6f' }
    ],
    arp_transactions: [
      { packet_num: 5, operation: 'ARP Request (Who has 192.168.1.1?)', sender_ip: '192.168.1.6', sender_mac: '1c:ce:51:32:87:5e', target_ip: '192.168.1.1', target_mac: '00:00:00:00:00:00' }
    ]
  };
}

export async function getDnsAnalysis(sessionId?: number) {
  try {
    const url = sessionId ? `${API_BASE}/protocols/dns?session_id=${sessionId}` : `${API_BASE}/protocols/dns`;
    const res = await fetch(url);
    if (res.ok) return await res.json();
  } catch (_) {}
  return {
    academic_note: "DNS translates human-readable hostnames to IP addresses over UDP port 53.",
    domain_resolution_map: [
      { domain: 'lab.university.local', addresses: ['192.168.1.1'] },
      { domain: 'gateway.netsecure', addresses: ['192.168.1.1'] }
    ],
    dns_records: [
      { packet_num: 7, is_response: false, query_type: 'A', query_name: 'lab.university.local', client_ip: '192.168.1.6', server_ip: '8.8.8.8', answers: [] },
      { packet_num: 8, is_response: true, query_type: 'A', query_name: 'lab.university.local', client_ip: '8.8.8.8', server_ip: '192.168.1.6', answers: ['192.168.1.1'] }
    ]
  };
}

export async function getHttpAnalysis(sessionId?: number) {
  try {
    const url = sessionId ? `${API_BASE}/protocols/http?session_id=${sessionId}` : `${API_BASE}/protocols/http`;
    const res = await fetch(url);
    if (res.ok) return await res.json();
  } catch (_) {}
  return {
    security_verdict: "VULNERABILITY CONFIRMED: Plaintext HTTP POST request intercepted on port 80. Credentials transmitted without encryption (CWE-319).",
    leaked_credentials: [
      { packet_num: 3, username: 'student_alex', password: 'Secr3tLabP@ssw0rd!', evidence: 'username=student_alex&password=Secr3tLabP@ssw0rd!' }
    ],
    http_transactions: [
      { packet_num: 3, method: 'POST', uri: '/api/dummy/login', src_ip: '192.168.1.6', dst_ip: '192.168.1.1', body: 'username=student_alex&password=Secr3tLabP@ssw0rd!' }
    ]
  };
}

export async function getHttpsAnalysis(sessionId?: number) {
  try {
    const url = sessionId ? `${API_BASE}/protocols/https?session_id=${sessionId}` : `${API_BASE}/protocols/https`;
    const res = await fetch(url);
    if (res.ok) return await res.json();
  } catch (_) {}
  return {
    security_verdict: "SECURE CONFIRMED: All application data packets encapsulated in TLS 1.3 records (0x17). Credentials protected against passive sniffing.",
    total_https_packets: 14,
    handshake_packets_count: 4,
    encrypted_app_data_count: 10,
    observed_sni_hosts: ['portal.university.local', 'netsecure.local']
  };
}

export async function getFtpAnalysis(sessionId?: number) {
  try {
    const url = sessionId ? `${API_BASE}/protocols/ftp?session_id=${sessionId}` : `${API_BASE}/protocols/ftp`;
    const res = await fetch(url);
    if (res.ok) return await res.json();
  } catch (_) {}
  return {
    security_verdict: "FTP authentication commands are transmitted in cleartext on TCP port 21 without encryption.",
    commands: [
      { packet_num: 11, src_ip: '192.168.1.6', dst_ip: '192.168.1.1', command: 'USER lab_student' },
      { packet_num: 12, src_ip: '192.168.1.6', dst_ip: '192.168.1.1', command: 'PASS FtpSecret2026!' }
    ]
  };
}

export async function getSecurityAlerts() {
  try {
    const res = await fetch(`${API_BASE}/alerts`);
    if (res.ok) return await res.json();
  } catch (_) {}
  return { alerts: [] };
}

export async function submitDummyLogin(data: { username: string; password: string; protocol: string; source_ip?: string; target_ip?: string }) {
  try {
    const res = await fetch(`${API_BASE}/dummy/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (res.ok) return await res.json();
  } catch (_) {}

  // Fallback realistic simulation for cloud / GitHub Pages
  const isHttp = data.protocol === 'HTTP';
  return {
    status: 'success',
    protocol: data.protocol,
    password_exposed: isHttp,
    security_status: isHttp ? 'UNENCRYPTED VULNERABILITY (LEAKED)' : 'SECURE ENCRYPTED (TLS 1.3)',
    exposed_password: isHttp ? data.password : '•••••••••••••••• (Encrypted in Ciphertext Block)',
    wire_payload: isHttp 
      ? `username=${encodeURIComponent(data.username)}&password=${encodeURIComponent(data.password)}`
      : '17 03 03 05 a0 a8 b1 99 e4 f2 10 32 c8 b7 e2 a0 91 f5 dc 84 9b 72 (Opaque Ciphertext)',
    steps: [
      { step: 1, title: 'Form Input', detail: `User enters username "${data.username}" and password on login portal`, actor: 'Client Browser' },
      { step: 2, title: 'Wire Transmission', detail: isHttp ? 'Sent over unencrypted TCP Port 80 in cleartext ASCII' : 'Sealed inside TLS 1.3 session with AES-256-GCM cipher keys', actor: 'Network Interface' },
      { step: 3, title: 'Packet Capture', detail: 'TShark / Wireshark records the raw frame on Ethernet LAN adapter', actor: 'Wire Tap / Sniffer' },
      { step: 4, title: 'Payload Dissection', detail: isHttp ? 'Dissector reads HTTP POST request body directly' : 'Dissector encounters opaque TLS Application Data record (0x17)', actor: 'Dissector' },
      { step: 5, title: 'Security Outcome', detail: isHttp ? `Plaintext password "${data.password}" extracted without decryption!` : 'Password remains completely private. Sniffer only sees ciphertext.', highlight: true, actor: 'Auditor' }
    ]
  };
}

export async function getDummyHistory() {
  try {
    const res = await fetch(`${API_BASE}/dummy/history`);
    if (res.ok) return await res.json();
  } catch (_) {}
  return { history: [] };
}

export function getPdfReportUrl(sessionId?: number) {
  return sessionId ? `${API_BASE}/reports/pdf?session_id=${sessionId}` : `${API_BASE}/reports/pdf`;
}

export function getCsvReportUrl(sessionId?: number) {
  return sessionId ? `${API_BASE}/reports/csv?session_id=${sessionId}` : `${API_BASE}/reports/csv`;
}

export function getPcapExportUrl(sessionId?: number) {
  return sessionId ? `${API_BASE}/capture/export-pcap?session_id=${sessionId}` : `${API_BASE}/capture/export-pcap`;
}
