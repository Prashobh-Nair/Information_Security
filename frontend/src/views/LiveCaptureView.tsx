import React, { useState, useRef } from 'react';
import { 
  Radio, Play, Square, Filter, Search, Upload, Download, 
  CheckCircle2, Shield
} from 'lucide-react';
import { 
  PacketItem, NetworkInterface, startCapture, stopCapture, 
  uploadPcap, getPcapExportUrl 
} from '../api';

interface LiveCaptureViewProps {
  packets: PacketItem[];
  interfaces: NetworkInterface[];
  isCapturing: boolean;
  selectedPacket: PacketItem | null;
  onSelectPacket: (pkt: PacketItem) => void;
  onRefresh: () => void;
  selectedProtocol: string;
  onProtocolChange: (proto: string) => void;
}

export const LiveCaptureView: React.FC<LiveCaptureViewProps> = ({
  packets,
  interfaces,
  isCapturing,
  selectedPacket,
  onSelectPacket,
  onRefresh,
  selectedProtocol,
  onProtocolChange
}) => {
  const [selectedIface, setSelectedIface] = useState<string>('');
  const [bpfFilter, setBpfFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState<string>(selectedProtocol || 'ALL');
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    if (selectedProtocol) {
      setActiveFilter(selectedProtocol);
    }
  }, [selectedProtocol]);

  React.useEffect(() => {
    if (interfaces.length > 0 && !selectedIface) {
      const active = interfaces.find(i => i.is_up && !i.is_loopback && i.ipv4 !== 'N/A') || interfaces.find(i => i.is_loopback) || interfaces[0];
      setSelectedIface((active as any)?.device_name || active.name);
    }
  }, [interfaces, selectedIface]);

  const protocolFilters = ['ALL', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'ARP', 'FTP', 'TCP', 'UDP'];

  const filteredPackets = packets.filter(p => {
    if (activeFilter && activeFilter.toUpperCase() !== 'ALL') {
      const filter = activeFilter.toUpperCase();
      const proto = (p.protocol || '').toUpperCase();
      const l4 = (p.l4_proto || '').toUpperCase();

      let matches = false;
      if (filter === 'ICMP') {
        matches = proto === 'ICMP' || l4 === 'ICMP';
      } else if (filter === 'UDP') {
        matches = proto === 'UDP' || l4 === 'UDP' || proto === 'DNS';
      } else if (filter === 'TCP') {
        matches = proto === 'TCP' || l4 === 'TCP' || ['HTTP', 'HTTPS', 'FTP'].includes(proto);
      } else if (filter === 'HTTP') {
        matches = proto === 'HTTP' || (p.src_port === 80 || p.dst_port === 80);
      } else if (filter === 'HTTPS') {
        matches = proto === 'HTTPS' || proto.startsWith('TLS') || (p.src_port === 443 || p.dst_port === 443);
      } else if (filter === 'DNS') {
        matches = proto === 'DNS' || (p.src_port === 53 || p.dst_port === 53);
      } else if (filter === 'ARP') {
        matches = proto === 'ARP';
      } else if (filter === 'FTP') {
        matches = proto === 'FTP' || (p.src_port === 21 || p.dst_port === 21);
      } else {
        matches = proto === filter || l4 === filter;
      }

      if (!matches) return false;
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const inSrc = (p.src_ip || '').toLowerCase().includes(q);
      const inDst = (p.dst_ip || '').toLowerCase().includes(q);
      const inInfo = (p.info || '').toLowerCase().includes(q);
      const inMac = (p.src_mac || '').toLowerCase().includes(q) || (p.dst_mac || '').toLowerCase().includes(q);
      const inProto = (p.protocol || '').toLowerCase().includes(q);
      return inSrc || inDst || inInfo || inMac || inProto;
    }
    return true;
  });

  const handleProtocolClick = (proto: string) => {
    setActiveFilter(proto);
    onProtocolChange(proto);
  };

  const handleStartClick = () => {
    setShowAuthModal(true);
  };

  const handleConfirmStart = async () => {
    try {
      setShowAuthModal(false);
      await startCapture(selectedIface, bpfFilter, 'auto', true);
      onRefresh();
    } catch (err: any) {
      alert(err.message || 'Capture start failed');
    }
  };

  const handleStopClick = async () => {
    try {
      await stopCapture();
      onRefresh();
    } catch (err) {
      console.error(err);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      setIsUploading(true);
      setUploadStatus('Uploading & parsing PCAP trace...');
      const res = await uploadPcap(file);
      setUploadStatus(`Loaded ${res.packet_count} frames from ${file.name}`);
      onRefresh();
    } catch (err: any) {
      setUploadStatus(`Error: ${err.message}`);
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const getProtocolBadge = (proto: string) => {
    switch (proto.toUpperCase()) {
      case 'ICMP': return 'bg-[#ECFDF5] text-[#059669] border-[#A7F3D0]';
      case 'HTTP': return 'bg-[#FFFBEB] text-[#D97706] border-[#FDE68A]';
      case 'HTTPS': return 'bg-[#F0F9FF] text-[#0284C7] border-[#BAE6FD]';
      case 'DNS': return 'bg-[#F5F3FF] text-[#7C3AED] border-[#DDD6FE]';
      case 'ARP': return 'bg-[#FDF2F8] text-[#DB2777] border-[#FBCFE8]';
      case 'FTP': return 'bg-[#FEF2F2] text-[#DC2626] border-[#FECACA]';
      case 'TCP': return 'bg-[#EFF6FF] text-[#2563EB] border-[#BFDBFE]';
      case 'UDP': return 'bg-[#EEF2FF] text-[#4F46E5] border-[#C7D2FE]';
      default: return 'bg-[#F1F5F9] text-[#64748B] border-[#E2E8F0]';
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#E2E8F0]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#0F172A]">
            Live Packet Capture
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Capture, inspect, and filter network packets in real time.
          </p>
        </div>

        <div>
          {isCapturing ? (
            <button
              onClick={handleStopClick}
              className="px-4 py-1.5 rounded-lg bg-[#DC2626] hover:bg-[#B91C1C] text-white text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              Stop Capture
            </button>
          ) : (
            <button
              onClick={handleStartClick}
              className="px-4 py-1.5 rounded-lg bg-[#059669] hover:bg-[#047857] text-white text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              Start Live Capture
            </button>
          )}
        </div>
      </div>

      {/* Control Bar */}
      <div className="p-4 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-medium text-[#64748B]">Interface:</span>
              <select
                value={selectedIface}
                onChange={(e) => setSelectedIface(e.target.value)}
                disabled={isCapturing}
                className="px-2.5 py-1.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono text-[#0F172A] focus:outline-none focus:border-[#2563EB] max-w-xs"
              >
                {interfaces.map((iface, i) => (
                  <option key={i} value={(iface as any).device_name || iface.name}>
                    {iface.name} {iface.ipv4 !== 'N/A' ? `(${iface.ipv4})` : ''}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-xs font-medium text-[#64748B]">BPF:</span>
              <input
                type="text"
                value={bpfFilter}
                onChange={(e) => setBpfFilter(e.target.value)}
                disabled={isCapturing}
                placeholder="e.g. icmp or port 80"
                className="px-2.5 py-1.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono text-[#0F172A] placeholder-slate-400 focus:outline-none focus:border-[#2563EB] w-44"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".pcap,.pcapng,.cap"
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={isUploading}
              className="px-3 py-1.5 rounded-lg bg-white hover:bg-[#F8FAFC] text-[#475569] text-xs font-medium border border-[#E2E8F0] flex items-center gap-1 transition cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5 text-[#64748B]" />
              {isUploading ? 'Parsing...' : 'Upload PCAP'}
            </button>

            <a
              href={getPcapExportUrl()}
              download="netsecure_capture.pcap"
              className="px-3 py-1.5 rounded-lg bg-white hover:bg-[#F8FAFC] text-[#475569] text-xs font-medium border border-[#E2E8F0] flex items-center gap-1 transition"
            >
              <Download className="w-3.5 h-3.5 text-[#2563EB]" />
              Export PCAP
            </a>
          </div>
        </div>

        {uploadStatus && (
          <div className="p-2.5 rounded-lg bg-[#EFF6FF] border border-[#BFDBFE] text-xs text-[#1E40AF] flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#2563EB]" />
              {uploadStatus}
            </span>
            <button onClick={() => setUploadStatus(null)} className="text-slate-400 hover:text-[#0F172A]">✕</button>
          </div>
        )}

        {/* Filter Pills & Search */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#F1F5F9]">
          <div className="flex items-center gap-1 overflow-x-auto">
            <span className="text-[11px] text-[#94A3B8] mr-1">Filter:</span>
            {protocolFilters.map((proto) => {
              const isActive = (activeFilter || 'ALL').toUpperCase() === proto.toUpperCase();
              return (
                <button
                  key={proto}
                  onClick={() => handleProtocolClick(proto)}
                  className={`px-2.5 py-0.5 rounded text-xs font-mono transition cursor-pointer ${
                    isActive
                      ? 'bg-[#2563EB] text-white font-medium'
                      : 'bg-[#F8FAFC] text-[#64748B] border border-[#E2E8F0] hover:bg-white'
                  }`}
                >
                  {proto}
                </button>
              );
            })}
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter IP, MAC, Info..."
              className="pl-7 pr-3 py-1 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs text-[#0F172A] focus:outline-none focus:border-[#2563EB] w-56"
            />
          </div>
        </div>
      </div>

      {/* Packet Table */}
      <div className="p-0 rounded-xl bg-white border border-[#E2E8F0] shadow-xs overflow-hidden">
        <div className="overflow-x-auto max-h-[500px]">
          <table className="w-full text-xs text-left">
            <thead className="bg-[#F8FAFC] text-[#64748B] uppercase font-semibold text-[10px] tracking-wider sticky top-0 z-10 border-b border-[#E2E8F0]">
              <tr>
                <th className="py-2.5 px-3 w-14 text-center">No.</th>
                <th className="py-2.5 px-3 w-24">Timestamp</th>
                <th className="py-2.5 px-3 w-32">Source IP</th>
                <th className="py-2.5 px-3 w-32">Destination IP</th>
                <th className="py-2.5 px-3 w-20">Protocol</th>
                <th className="py-2.5 px-3 w-16">Length</th>
                <th className="py-2.5 px-3">Packet Info</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#F1F5F9] font-mono text-[#0F172A]">
              {filteredPackets.length > 0 ? (
                filteredPackets.map((pkt, idx) => {
                  const isSelected = selectedPacket?.packet_num === pkt.packet_num || selectedPacket?.id === pkt.id;
                  const hasVuln = pkt.details?.security?.has_credentials;
                  return (
                    <tr
                      key={`${pkt.id || pkt.packet_num || idx}-${idx}`}
                      onClick={() => onSelectPacket(pkt)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-[#EFF6FF] border-l-2 border-l-[#2563EB]'
                          : hasVuln
                          ? 'bg-[#FEF2F2] hover:bg-[#FEE2E2]'
                          : 'hover:bg-[#F8FAFC]'
                      }`}
                    >
                      <td className="py-2 px-3 text-center text-[#94A3B8] font-semibold">{idx + 1}</td>
                      <td className="py-2 px-3 text-[#64748B]">{pkt.timestamp}</td>
                      <td className="py-2 px-3 text-[#2563EB] font-medium">{pkt.src_ip}</td>
                      <td className="py-2 px-3 text-[#0F172A] font-medium">{pkt.dst_ip}</td>
                      <td className="py-2 px-3">
                        <span className={`px-2 py-0.2 rounded text-[10px] font-semibold border ${getProtocolBadge(pkt.protocol)}`}>
                          {pkt.protocol}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-[#64748B]">{pkt.length} B</td>
                      <td className="py-2 px-3 text-[#475569] truncate max-w-md">
                        {hasVuln && (
                          <span className="mr-1.5 px-1.5 py-0.2 rounded bg-[#FEF2F2] text-[#DC2626] text-[9px] font-bold border border-[#FECACA]">
                            LEAK
                          </span>
                        )}
                        <span>{pkt.info}</span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[#94A3B8]">
                    No packets matching filter
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="p-3 bg-[#F8FAFC] border-t border-[#E2E8F0] flex items-center justify-between text-[11px] text-[#64748B]">
          <span>Showing <b>{filteredPackets.length}</b> of {packets.length} packets</span>
          <span>Click any row to inspect Layer 2–7 dissection</span>
        </div>
      </div>

      {/* Modal */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-[#E2E8F0] rounded-xl max-w-sm w-full p-5 shadow-xl text-[#0F172A] space-y-3">
            <h3 className="font-semibold text-sm">Start Live Packet Capture</h3>
            <p className="text-xs text-[#64748B] leading-relaxed">
              Capture promiscuous traffic on adapter <b className="text-[#0F172A]">{selectedIface}</b>.
            </p>
            <div className="flex justify-end gap-2 pt-1">
              <button
                onClick={() => setShowAuthModal(false)}
                className="px-3 py-1.5 rounded-lg bg-white border border-[#E2E8F0] text-xs"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmStart}
                className="px-4 py-1.5 rounded-lg bg-[#059669] text-white text-xs font-medium"
              >
                Start Capture
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
