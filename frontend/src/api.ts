/**
 * NetSecure REST API & WebSocket Client
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

export async function getSystemStatus(): Promise<SystemStatus> {
  const res = await fetch(`${API_BASE}/system/status`);
  if (!res.ok) throw new Error('Failed to fetch system status');
  return res.json();
}

export async function getInterfaces(): Promise<{ interfaces: NetworkInterface[]; tshark_installed: boolean }> {
  const res = await fetch(`${API_BASE}/system/interfaces`);
  if (!res.ok) throw new Error('Failed to fetch network interfaces');
  return res.json();
}

export async function getLabHosts(): Promise<LabHosts> {
  const res = await fetch(`${API_BASE}/system/lab-hosts`);
  if (!res.ok) throw new Error('Failed to fetch lab host info');
  return res.json();
}

export async function saveLabSettings(data: any): Promise<any> {
  const res = await fetch(`${API_BASE}/system/lab-settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function executePing(target_ip: string, count: number = 4, timeout_sec: number = 2): Promise<PingResult> {
  const res = await fetch(`${API_BASE}/ping`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_ip, count, timeout_sec })
  });
  if (!res.ok) throw new Error('Ping execution failed');
  return res.json();
}

export async function getPingLogs(): Promise<{ logs: PingResult[] }> {
  const res = await fetch(`${API_BASE}/ping/logs`);
  return res.json();
}

export async function startCapture(interface_name: string, filter_expr: string = '', mode: string = 'auto', confirm_authorized: boolean = true) {
  const res = await fetch(`${API_BASE}/capture/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ interface: interface_name, filter_expr, mode, confirm_authorized })
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to start capture');
  }
  return res.json();
}

export async function stopCapture() {
  const res = await fetch(`${API_BASE}/capture/stop`, { method: 'POST' });
  return res.json();
}

export async function getCaptureStatus() {
  const res = await fetch(`${API_BASE}/capture/status`);
  return res.json();
}

export async function getPackets(params: { session_id?: number; protocol?: string; search?: string; limit?: number; offset?: number } = {}) {
  const query = new URLSearchParams();
  if (params.session_id) query.set('session_id', params.session_id.toString());
  if (params.protocol) query.set('protocol', params.protocol);
  if (params.search) query.set('search', params.search);
  if (params.limit) query.set('limit', params.limit.toString());
  if (params.offset) query.set('offset', params.offset.toString());
  
  const res = await fetch(`${API_BASE}/capture/packets?${query.toString()}`);
  return res.json();
}

export async function getPacketById(id: number): Promise<PacketItem> {
  const res = await fetch(`${API_BASE}/capture/packets/${id}`);
  if (!res.ok) throw new Error('Packet not found');
  return res.json();
}

export async function uploadPcap(file: File) {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/capture/upload`, {
    method: 'POST',
    body: formData
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Upload failed');
  }
  return res.json();
}

export async function loadSamplePcap() {
  const res = await fetch(`${API_BASE}/capture/load-sample`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to load sample PCAP');
  return res.json();
}

export async function getDashboardStats(sessionId?: number): Promise<DashboardStats> {
  const url = sessionId ? `${API_BASE}/stats?session_id=${sessionId}` : `${API_BASE}/stats`;
  const res = await fetch(url);
  return res.json();
}

export async function getIcmpAnalysis(sessionId?: number) {
  const url = sessionId ? `${API_BASE}/protocols/icmp?session_id=${sessionId}` : `${API_BASE}/protocols/icmp`;
  const res = await fetch(url);
  return res.json();
}

export async function getArpAnalysis(sessionId?: number) {
  const url = sessionId ? `${API_BASE}/protocols/arp?session_id=${sessionId}` : `${API_BASE}/protocols/arp`;
  const res = await fetch(url);
  return res.json();
}

export async function getDnsAnalysis(sessionId?: number) {
  const url = sessionId ? `${API_BASE}/protocols/dns?session_id=${sessionId}` : `${API_BASE}/protocols/dns`;
  const res = await fetch(url);
  return res.json();
}

export async function getHttpAnalysis(sessionId?: number) {
  const url = sessionId ? `${API_BASE}/protocols/http?session_id=${sessionId}` : `${API_BASE}/protocols/http`;
  const res = await fetch(url);
  return res.json();
}

export async function getHttpsAnalysis(sessionId?: number) {
  const url = sessionId ? `${API_BASE}/protocols/https?session_id=${sessionId}` : `${API_BASE}/protocols/https`;
  const res = await fetch(url);
  return res.json();
}

export async function getFtpAnalysis(sessionId?: number) {
  const url = sessionId ? `${API_BASE}/protocols/ftp?session_id=${sessionId}` : `${API_BASE}/protocols/ftp`;
  const res = await fetch(url);
  return res.json();
}

export async function getSecurityAlerts() {
  const res = await fetch(`${API_BASE}/alerts`);
  return res.json();
}

export async function submitDummyLogin(data: { username: string; password: string; protocol: string; source_ip?: string; target_ip?: string }) {
  const res = await fetch(`${API_BASE}/dummy/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

export async function getDummyHistory() {
  const res = await fetch(`${API_BASE}/dummy/history`);
  return res.json();
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
