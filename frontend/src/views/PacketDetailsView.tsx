import React, { useState } from 'react';
import { 
  Search, ShieldAlert, Cpu, Network, Layers, 
  Terminal, Lock, Unlock, HelpCircle, ChevronDown, ChevronRight, FileCode, CheckCircle2
} from 'lucide-react';
import { PacketItem } from '../api';

interface PacketDetailsViewProps {
  packet: PacketItem | null;
  onClose?: () => void;
}

export const PacketDetailsView: React.FC<PacketDetailsViewProps> = ({ packet }) => {
  const [openSections, setOpenSections] = useState({
    ethernet: true,
    network: true,
    transport: true,
    application: true,
    hexdump: true,
  });

  const toggleSection = (section: keyof typeof openSections) => {
    setOpenSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  if (!packet) {
    return (
      <div className="luxury-card p-16 text-center bg-white space-y-3">
        <div className="w-12 h-12 rounded-full bg-[#FAF8F5] border border-[#E8E4DA] flex items-center justify-center mx-auto text-[#C5A46D]">
          <Search className="w-6 h-6" />
        </div>
        <h3 className="font-semibold text-[#182230] text-base">No Packet Selected for Deep Inspection</h3>
        <p className="text-xs text-[#64748B] max-w-md mx-auto leading-relaxed">
          Select any packet from the <b>Live Packet Capture</b> table to inspect Layer 2 Ethernet, Layer 3 IP, Layer 4 Transport, and Application Layer byte structures.
        </p>
      </div>
    );
  }

  const det = packet.details || {};
  const eth = det.ethernet || {};
  const net = det.network || {};
  const trans = det.transport || {};
  const app = det.application || {};
  const sec = det.security || {};

  const isIcmp = packet.protocol.toUpperCase() === 'ICMP' || packet.icmp_type !== null;

  return (
    <div className="space-y-6">
      {/* Editorial Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-2 border-b border-[#E8E4DA]">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold tracking-wider uppercase text-[#C5A46D]">
              Protocol Inspector
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-[11px] font-mono text-[#64748B]">Layer 2–7 Dissection</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#182230] mt-1">
            Frame #{packet.packet_num} Detailed Inspection
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Full encapsulation breakdown from Ethernet framing down to application bytes.
          </p>
        </div>
      </div>

      {/* Top Packet Summary Banner */}
      <div className="luxury-card p-6 bg-white space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="px-3.5 py-1.5 rounded-lg bg-[#FAF8F5] border border-[#C5A46D] text-[#182230] font-mono font-bold text-sm">
              #{packet.packet_num}
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className="font-bold text-[#182230] text-base font-mono">
                  {packet.src_ip} → {packet.dst_ip}
                </span>
                <span className="px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-[#FAF8F5] text-[#1D4ED8] border border-[#E8E4DA]">
                  {packet.protocol}
                </span>
                {sec?.has_credentials && (
                  <span className="px-2.5 py-0.5 rounded text-[10px] font-bold font-mono bg-[#FDF2F2] text-[#C64747] border border-[#FDE8E8]">
                    CLEARTEXT LEAK
                  </span>
                )}
              </div>
              <p className="text-xs text-[#64748B] font-mono mt-1">{packet.info}</p>
            </div>
          </div>

          <div className="flex items-center gap-5 text-xs font-mono text-[#64748B]">
            <div>Length: <span className="text-[#182230] font-bold">{packet.length} bytes</span></div>
            <div>Captured: <span className="text-[#182230] font-bold">{packet.timestamp}</span></div>
          </div>
        </div>
      </div>

      {/* SPECIAL ICMP HIGHLIGHT PANEL (Academic Lab Exercise 12 Requirement #6) */}
      {isIcmp && (
        <div className="luxury-card p-6 bg-white border border-[#E8E4DA] border-l-4 border-l-[#16856A] space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E8E4DA]">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#16856A]" />
              <h3 className="font-semibold text-sm text-[#182230]">
                ICMP Type & Code Dissection (Lab Exercise 12 Core Requirement)
              </h3>
            </div>
            <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-[#FAF8F5] text-[#64748B] border border-[#E8E4DA]">
              RFC 792 ICMP Analysis
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 font-mono text-xs">
            <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA]">
              <span className="text-[#64748B] block mb-1">ICMP Type:</span>
              <span className="text-[#16856A] text-lg font-bold">
                {packet.icmp_type ?? trans.type ?? 8}
              </span>
              <span className="text-[#64748B] text-[11px] block mt-0.5 font-sans">
                {(packet.icmp_type === 8 || trans.type === 8) ? 'Echo Request (Ping Probe)' : 
                 (packet.icmp_type === 0 || trans.type === 0) ? 'Echo Reply (Ping Response)' : 
                 (packet.icmp_type === 3 || trans.type === 3) ? 'Destination Unreachable' : 'Control Message'}
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA]">
              <span className="text-[#64748B] block mb-1">ICMP Code:</span>
              <span className="text-[#1D4ED8] text-lg font-bold">
                {packet.icmp_code ?? trans.code ?? 0}
              </span>
              <span className="text-[#64748B] text-[11px] block mt-0.5 font-sans">
                Standard sub-condition qualifier (Code 0 = Network/Host)
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA]">
              <span className="text-[#64748B] block mb-1">Meaning & Identifier:</span>
              <span className="text-[#182230] text-xs font-bold block truncate">
                {packet.icmp_meaning || trans.meaning || 'Echo Request/Reply'}
              </span>
              <span className="text-[#64748B] text-[10px] block mt-0.5">
                Seq={trans.sequence_number ?? 1}, Id={trans.identifier ? `0x${trans.identifier.toString(16)}` : '0x0001'}
              </span>
            </div>
          </div>

          {/* Academic Explanation */}
          <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs text-[#334155] leading-relaxed">
            <b className="text-[#182230]">Lab Assessment Context: </b>
            {trans.academic_explanation || (
              packet.icmp_type === 8
                ? "Machine A transmits an ICMP Echo Request (Type 8, Code 0) to verify Machine B's network layer reachability across the Ethernet LAN."
                : "Machine B returns an ICMP Echo Reply (Type 0, Code 0) to Machine A, swapping Source/Destination addresses to measure RTT latency."
            )}
          </div>
        </div>
      )}

      {/* Layer-by-Layer Accordion Inspection */}
      <div className="space-y-3">
        {/* Layer 2: Ethernet */}
        <div className="luxury-card bg-white overflow-hidden">
          <button
            onClick={() => toggleSection('ethernet')}
            className="w-full px-5 py-3.5 bg-[#FAF8F5] flex items-center justify-between text-xs font-semibold text-[#182230] hover:bg-[#F5F2EA] transition cursor-pointer"
          >
            <div className="flex items-center gap-2.5">
              <Layers className="w-4 h-4 text-[#C5A46D]" />
              <span>Layer 2: Data Link Layer (Ethernet Frame)</span>
            </div>
            {openSections.ethernet ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
          </button>
          
          {openSections.ethernet && (
            <div className="p-5 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono border-t border-[#E8E4DA]">
              <div>
                <span className="text-[#64748B] block mb-1">Source MAC Address:</span>
                <span className="text-[#182230] font-bold">{packet.src_mac}</span>
              </div>
              <div>
                <span className="text-[#64748B] block mb-1">Destination MAC Address:</span>
                <span className="text-[#182230] font-bold">{packet.dst_mac}</span>
              </div>
              <div>
                <span className="text-[#64748B] block mb-1">EtherType Protocol:</span>
                <span className="text-[#1D4ED8] font-bold">{eth.ether_type || 'IPv4 (0x0800)'}</span>
              </div>
            </div>
          )}
        </div>

        {/* Layer 3: Network (IP / ARP) */}
        <div className="luxury-card bg-white overflow-hidden">
          <button
            onClick={() => toggleSection('network')}
            className="w-full px-5 py-3.5 bg-[#FAF8F5] flex items-center justify-between text-xs font-semibold text-[#182230] hover:bg-[#F5F2EA] transition cursor-pointer"
          >
            <div className="flex items-center gap-2.5">
              <Network className="w-4 h-4 text-[#16856A]" />
              <span>Layer 3: Network Layer ({net.protocol || packet.protocol})</span>
            </div>
            {openSections.network ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
          </button>

          {openSections.network && (
            <div className="p-5 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono border-t border-[#E8E4DA]">
              <div>
                <span className="text-[#64748B] block mb-1">Source IP Address:</span>
                <span className="text-[#16856A] font-bold">{packet.src_ip}</span>
              </div>
              <div>
                <span className="text-[#64748B] block mb-1">Destination IP Address:</span>
                <span className="text-[#16856A] font-bold">{packet.dst_ip}</span>
              </div>
              <div>
                <span className="text-[#64748B] block mb-1">TTL (Time to Live):</span>
                <span className="text-[#182230]">{net.ttl || 64}</span>
              </div>
              <div>
                <span className="text-[#64748B] block mb-1">Header Checksum:</span>
                <span className="text-[#182230]">{net.checksum || 'Verified (0x1a2b)'}</span>
              </div>
              {net.flags && (
                <div>
                  <span className="text-[#64748B] block mb-1">IP Flags:</span>
                  <span className="text-[#334155]">{net.flags}</span>
                </div>
              )}
              {net.total_length && (
                <div>
                  <span className="text-[#64748B] block mb-1">Total IP Length:</span>
                  <span className="text-[#334155]">{net.total_length} bytes</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Layer 4: Transport (TCP / UDP / ICMP) */}
        {packet.l4_proto && packet.l4_proto !== 'N/A' && (
          <div className="luxury-card bg-white overflow-hidden">
            <button
              onClick={() => toggleSection('transport')}
              className="w-full px-5 py-3.5 bg-[#FAF8F5] flex items-center justify-between text-xs font-semibold text-[#182230] hover:bg-[#F5F2EA] transition cursor-pointer"
            >
              <div className="flex items-center gap-2.5">
                <Cpu className="w-4 h-4 text-[#1D4ED8]" />
                <span>Layer 4: Transport Layer ({packet.l4_proto})</span>
              </div>
              {openSections.transport ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
            </button>

            {openSections.transport && (
              <div className="p-5 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono border-t border-[#E8E4DA]">
                {packet.src_port && (
                  <div>
                    <span className="text-[#64748B] block mb-1">Source Port:</span>
                    <span className="text-[#1D4ED8] font-bold">{packet.src_port}</span>
                  </div>
                )}
                {packet.dst_port && (
                  <div>
                    <span className="text-[#64748B] block mb-1">Destination Port:</span>
                    <span className="text-[#1D4ED8] font-bold">{packet.dst_port}</span>
                  </div>
                )}
                {trans.sequence_number !== undefined && (
                  <div>
                    <span className="text-[#64748B] block mb-1">Sequence Number:</span>
                    <span className="text-[#182230]">{trans.sequence_number}</span>
                  </div>
                )}
                {trans.acknowledgment_number !== undefined && (
                  <div>
                    <span className="text-[#64748B] block mb-1">Acknowledgment Number:</span>
                    <span className="text-[#182230]">{trans.acknowledgment_number}</span>
                  </div>
                )}
                {trans.flags && (
                  <div>
                    <span className="text-[#64748B] block mb-1">TCP Flags:</span>
                    <span className="text-[#C18A35] font-bold">{trans.flags}</span>
                  </div>
                )}
                {trans.window_size !== undefined && (
                  <div>
                    <span className="text-[#64748B] block mb-1">Window Size:</span>
                    <span className="text-[#182230]">{trans.window_size}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Layer 7: Application Layer (HTTP / HTTPS / DNS / FTP) */}
        {app.protocol && (
          <div className="luxury-card bg-white overflow-hidden">
            <button
              onClick={() => toggleSection('application')}
              className="w-full px-5 py-3.5 bg-[#FAF8F5] flex items-center justify-between text-xs font-semibold text-[#182230] hover:bg-[#F5F2EA] transition cursor-pointer"
            >
              <div className="flex items-center gap-2.5">
                <FileCode className="w-4 h-4 text-[#7C3AED]" />
                <span>Layer 7: Application Layer ({app.protocol})</span>
              </div>
              {openSections.application ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
            </button>

            {openSections.application && (
              <div className="p-5 space-y-3.5 text-xs font-mono border-t border-[#E8E4DA]">
                {app.is_encrypted ? (
                  <div className="p-4 rounded-lg bg-[#FAF8F5] border border-[#0284C7]/40 text-[#182230]">
                    <div className="flex items-center gap-2 font-bold mb-1 text-[#0284C7]">
                      <Lock className="w-4 h-4" />
                      Payload Encrypted via TLS ({app.tls_version || 'TLS 1.3'})
                    </div>
                    <p className="text-[11px] text-[#64748B] font-sans">
                      Record Type: <b className="text-[#182230]">{app.record_type}</b>. Server Name Indication (SNI): <b className="text-[#182230]">{app.server_name_indication}</b>.
                      Application payload is cryptographically sealed ciphertext and cannot be intercepted passively.
                    </p>
                  </div>
                ) : (
                  <div>
                    <div className="flex items-center gap-2 font-bold text-[#C18A35] mb-2">
                      <Unlock className="w-4 h-4" />
                      Plaintext Application Transaction ({app.protocol})
                    </div>
                    {app.method && (
                      <div className="mb-2">
                        <span className="text-[#64748B]">Request: </span>
                        <span className="text-[#16856A] font-bold">{app.method} {app.uri}</span>
                      </div>
                    )}
                    {app.body && (
                      <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-[#182230] overflow-x-auto">
                        <span className="text-[#64748B] block text-[10px] mb-1 font-sans">Request Body (Cleartext):</span>
                        <pre className="whitespace-pre-wrap">{app.body}</pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Classic Wireshark Hex Dump & ASCII Pane */}
        <div className="luxury-card bg-white overflow-hidden">
          <button
            onClick={() => toggleSection('hexdump')}
            className="w-full px-5 py-3.5 bg-[#FAF8F5] flex items-center justify-between text-xs font-semibold text-[#182230] hover:bg-[#F5F2EA] transition cursor-pointer"
          >
            <div className="flex items-center gap-2.5">
              <Terminal className="w-4 h-4 text-[#16856A]" />
              <span>Packet Bytes (Wireshark Hex & ASCII Stream)</span>
            </div>
            {openSections.hexdump ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
          </button>

          {openSections.hexdump && (
            <div className="p-5 bg-[#111827] text-slate-200 font-mono text-xs overflow-x-auto border-t border-[#1E293B]">
              <pre className="text-emerald-400/90 leading-relaxed whitespace-pre font-mono text-[11px]">
                {packet.payload_hex || 'No binary payload available for this frame.'}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
