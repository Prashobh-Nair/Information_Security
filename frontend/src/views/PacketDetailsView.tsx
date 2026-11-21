import React, { useState } from 'react';
import { 
  Search, Cpu, Network, Layers, 
  Terminal, Lock, Unlock, ChevronDown, ChevronRight, FileCode
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
      <div className="p-16 text-center bg-white rounded-xl border border-[#E2E8F0] shadow-xs space-y-2">
        <Search className="w-8 h-8 text-[#94A3B8] mx-auto opacity-50" />
        <h3 className="font-semibold text-[#0F172A] text-sm">No Packet Selected</h3>
        <p className="text-xs text-[#64748B] max-w-sm mx-auto">
          Select any packet from the <b>Live Packet Capture</b> table to inspect Layer 2–7 headers and raw bytes.
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
    <div className="space-y-5">
      {/* Top Banner */}
      <div className="p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="px-3 py-1 rounded-lg bg-[#EFF6FF] border border-[#BFDBFE] text-[#2563EB] font-mono font-bold text-sm">
              #{packet.packet_num}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-[#0F172A] text-sm font-mono">
                  {packet.src_ip} → {packet.dst_ip}
                </span>
                <span className="px-2 py-0.2 rounded text-[10px] font-bold font-mono bg-[#F1F5F9] text-[#2563EB]">
                  {packet.protocol}
                </span>
                {sec?.has_credentials && (
                  <span className="px-2 py-0.2 rounded text-[10px] font-bold font-mono bg-[#FEF2F2] text-[#DC2626] border border-[#FECACA]">
                    LEAK
                  </span>
                )}
              </div>
              <p className="text-xs text-[#64748B] font-mono mt-0.5">{packet.info}</p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono text-[#64748B]">
            <div>Length: <span className="text-[#0F172A] font-semibold">{packet.length} bytes</span></div>
            <div>Time: <span className="text-[#0F172A] font-semibold">{packet.timestamp}</span></div>
          </div>
        </div>
      </div>

      {/* ICMP Panel */}
      {isIcmp && (
        <div className="p-5 rounded-xl bg-white border border-[#E2E8F0] border-l-4 border-l-[#059669] shadow-xs space-y-3">
          <h3 className="font-semibold text-xs text-[#0F172A]">
            ICMP Packet Dissection (Type & Code)
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
            <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
              <span className="text-[#64748B] block mb-1">ICMP Type:</span>
              <span className="text-[#059669] text-base font-bold">
                {packet.icmp_type ?? trans.type ?? 8}
              </span>
              <span className="text-[#64748B] text-[10px] block mt-0.5 font-sans">
                {(packet.icmp_type === 8 || trans.type === 8) ? 'Echo Request (Ping)' : 'Echo Reply (Ping Response)'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
              <span className="text-[#64748B] block mb-1">ICMP Code:</span>
              <span className="text-[#2563EB] text-base font-bold">
                {packet.icmp_code ?? trans.code ?? 0}
              </span>
              <span className="text-[#64748B] text-[10px] block mt-0.5 font-sans">
                Code 0 (Standard Condition)
              </span>
            </div>

            <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
              <span className="text-[#64748B] block mb-1">Meaning:</span>
              <span className="text-[#0F172A] text-xs font-bold block truncate">
                {packet.icmp_meaning || trans.meaning || 'Echo Request/Reply'}
              </span>
              <span className="text-[#64748B] text-[10px] block mt-0.5">
                Seq={trans.sequence_number ?? 1}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Accordions */}
      <div className="space-y-2.5">
        {/* Layer 2 */}
        <div className="rounded-xl border border-[#E2E8F0] bg-white overflow-hidden shadow-xs">
          <button
            onClick={() => toggleSection('ethernet')}
            className="w-full px-4 py-3 bg-[#F8FAFC] flex items-center justify-between text-xs font-semibold text-[#0F172A] hover:bg-[#F1F5F9] cursor-pointer"
          >
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#2563EB]" />
              <span>Layer 2: Data Link Layer (Ethernet II)</span>
            </div>
            {openSections.ethernet ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
          </button>
          
          {openSections.ethernet && (
            <div className="p-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono border-t border-[#E2E8F0]">
              <div>
                <span className="text-[#64748B] block">Source MAC:</span>
                <span className="text-[#0F172A] font-semibold">{packet.src_mac}</span>
              </div>
              <div>
                <span className="text-[#64748B] block">Destination MAC:</span>
                <span className="text-[#0F172A] font-semibold">{packet.dst_mac}</span>
              </div>
              <div>
                <span className="text-[#64748B] block">EtherType:</span>
                <span className="text-[#2563EB] font-semibold">{eth.ether_type || 'IPv4 (0x0800)'}</span>
              </div>
            </div>
          )}
        </div>

        {/* Layer 3 */}
        <div className="rounded-xl border border-[#E2E8F0] bg-white overflow-hidden shadow-xs">
          <button
            onClick={() => toggleSection('network')}
            className="w-full px-4 py-3 bg-[#F8FAFC] flex items-center justify-between text-xs font-semibold text-[#0F172A] hover:bg-[#F1F5F9] cursor-pointer"
          >
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-[#059669]" />
              <span>Layer 3: Network Layer ({net.protocol || packet.protocol})</span>
            </div>
            {openSections.network ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
          </button>

          {openSections.network && (
            <div className="p-4 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono border-t border-[#E2E8F0]">
              <div>
                <span className="text-[#64748B] block">Source IP:</span>
                <span className="text-[#059669] font-semibold">{packet.src_ip}</span>
              </div>
              <div>
                <span className="text-[#64748B] block">Destination IP:</span>
                <span className="text-[#059669] font-semibold">{packet.dst_ip}</span>
              </div>
              <div>
                <span className="text-[#64748B] block">TTL:</span>
                <span className="text-[#0F172A]">{net.ttl || 64}</span>
              </div>
              <div>
                <span className="text-[#64748B] block">Checksum:</span>
                <span className="text-[#0F172A]">{net.checksum || '0x1a2b'}</span>
              </div>
            </div>
          )}
        </div>

        {/* Layer 4 */}
        {packet.l4_proto && packet.l4_proto !== 'N/A' && (
          <div className="rounded-xl border border-[#E2E8F0] bg-white overflow-hidden shadow-xs">
            <button
              onClick={() => toggleSection('transport')}
              className="w-full px-4 py-3 bg-[#F8FAFC] flex items-center justify-between text-xs font-semibold text-[#0F172A] hover:bg-[#F1F5F9] cursor-pointer"
            >
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-[#2563EB]" />
                <span>Layer 4: Transport Layer ({packet.l4_proto})</span>
              </div>
              {openSections.transport ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
            </button>

            {openSections.transport && (
              <div className="p-4 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono border-t border-[#E2E8F0]">
                {packet.src_port && (
                  <div>
                    <span className="text-[#64748B] block">Source Port:</span>
                    <span className="text-[#2563EB] font-semibold">{packet.src_port}</span>
                  </div>
                )}
                {packet.dst_port && (
                  <div>
                    <span className="text-[#64748B] block">Destination Port:</span>
                    <span className="text-[#2563EB] font-semibold">{packet.dst_port}</span>
                  </div>
                )}
                {trans.flags && (
                  <div>
                    <span className="text-[#64748B] block">Flags:</span>
                    <span className="text-[#D97706] font-semibold">{trans.flags}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Layer 7 */}
        {app.protocol && (
          <div className="rounded-xl border border-[#E2E8F0] bg-white overflow-hidden shadow-xs">
            <button
              onClick={() => toggleSection('application')}
              className="w-full px-4 py-3 bg-[#F8FAFC] flex items-center justify-between text-xs font-semibold text-[#0F172A] hover:bg-[#F1F5F9] cursor-pointer"
            >
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#7C3AED]" />
                <span>Layer 7: Application Layer ({app.protocol})</span>
              </div>
              {openSections.application ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
            </button>

            {openSections.application && (
              <div className="p-4 space-y-2 text-xs font-mono border-t border-[#E2E8F0]">
                {app.is_encrypted ? (
                  <div className="p-3 rounded-lg bg-[#F0F9FF] border border-[#BAE6FD] text-[#0369A1]">
                    <div className="flex items-center gap-1.5 font-bold mb-1">
                      <Lock className="w-3.5 h-3.5" />
                      Payload Encrypted via TLS ({app.tls_version || 'TLS 1.3'})
                    </div>
                    <p className="text-[11px] text-[#475569] font-sans">
                      Application payload is ciphertext and cannot be intercepted passively.
                    </p>
                  </div>
                ) : (
                  <div>
                    <div className="flex items-center gap-1.5 font-bold text-[#D97706] mb-1.5">
                      <Unlock className="w-3.5 h-3.5" />
                      Plaintext Application Transaction ({app.protocol})
                    </div>
                    {app.body && (
                      <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-[#0F172A] overflow-x-auto">
                        <pre className="whitespace-pre-wrap">{app.body}</pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Hex Dump */}
        <div className="rounded-xl border border-[#E2E8F0] bg-white overflow-hidden shadow-xs">
          <button
            onClick={() => toggleSection('hexdump')}
            className="w-full px-4 py-3 bg-[#F8FAFC] flex items-center justify-between text-xs font-semibold text-[#0F172A] hover:bg-[#F1F5F9] cursor-pointer"
          >
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#059669]" />
              <span>Packet Bytes (Wireshark Hex & ASCII)</span>
            </div>
            {openSections.hexdump ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
          </button>

          {openSections.hexdump && (
            <div className="p-4 bg-[#0F172A] text-emerald-400 font-mono text-xs overflow-x-auto border-t border-[#E2E8F0]">
              <pre className="leading-relaxed whitespace-pre font-mono text-[11px]">
                {packet.payload_hex || 'No binary payload available.'}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
