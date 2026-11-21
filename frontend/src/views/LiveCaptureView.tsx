import React, { useState, useRef } from 'react';
import { 
  Radio, Play, Square, Filter, Search, Upload, Download, 
  RefreshCw, CheckCircle2, AlertCircle, FileUp, Sparkles, Shield, X
} from 'lucide-react';
import { 
  PacketItem, NetworkInterface, startCapture, stopCapture, 
  uploadPcap, loadSamplePcap, getPcapExportUrl 
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
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    if (interfaces.length > 0 && !selectedIface) {
      const active = interfaces.find(i => i.is_up && !i.is_loopback && i.ipv4 !== 'N/A') || interfaces.find(i => i.is_loopback) || interfaces[0];
      setSelectedIface((active as any)?.device_name || active.name);
    }
  }, [interfaces, selectedIface]);

  const protocolFilters = ['ALL', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'ARP', 'FTP', 'TCP', 'UDP'];

  const filteredPackets = packets.filter(p => {
    if (selectedProtocol !== 'ALL' && p.protocol.toUpperCase() !== selectedProtocol.toUpperCase()) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const inSrc = p.src_ip.toLowerCase().includes(q);
      const inDst = p.dst_ip.toLowerCase().includes(q);
      const inInfo = p.info.toLowerCase().includes(q);
      const inMac = p.src_mac.toLowerCase().includes(q) || p.dst_mac.toLowerCase().includes(q);
      return inSrc || inDst || inInfo || inMac;
    }
    return true;
  });

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
      case 'ICMP': return 'bg-[#F0FDF4] text-[#16856A] border-[#DCFCE7]';
      case 'HTTP': return 'bg-[#FFFBEB] text-[#C18A35] border-[#FEF3C7]';
      case 'HTTPS': return 'bg-[#F0F9FF] text-[#0284C7] border-[#E0F2FE]';
      case 'DNS': return 'bg-[#F5F3FF] text-[#7C3AED] border-[#EDE9FE]';
      case 'ARP': return 'bg-[#FDF2F8] text-[#DB2777] border-[#FCE7F3]';
      case 'FTP': return 'bg-[#FEF2F2] text-[#C64747] border-[#FEE2E2]';
      case 'TCP': return 'bg-[#EFF6FF] text-[#1D4ED8] border-[#DBEAFE]';
      case 'UDP': return 'bg-[#EEF2FF] text-[#4F46E5] border-[#E0E7FF]';
      default: return 'bg-[#FAF8F5] text-[#64748B] border-[#E8E4DA]';
    }
  };

  return (
    <div className="space-y-6">
      {/* Editorial Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-2 border-b border-[#E8E4DA]">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold tracking-wider uppercase text-[#C5A46D]">
              Packet Dissection
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-[11px] font-mono text-[#64748B]">TShark Capture Instrument</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#182230] mt-1">
            Live Packet Capture & Telemetry
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Continuous packet streaming across physical and loopback network adapters.
          </p>
        </div>

        {/* Start / Stop Capture Trigger */}
        <div className="flex items-center gap-3">
          {isCapturing ? (
            <button
              onClick={handleStopClick}
              className="px-5 py-2.5 rounded-lg bg-[#C64747] hover:bg-[#B91C1C] text-white text-xs font-semibold flex items-center gap-2 shadow-sm transition cursor-pointer"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              Stop Capture
            </button>
          ) : (
            <button
              onClick={handleStartClick}
              className="px-5 py-2.5 rounded-lg bg-[#16856A] hover:bg-[#13735B] text-white text-xs font-semibold flex items-center gap-2 shadow-sm transition cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              Start Live Capture
            </button>
          )}
        </div>
      </div>

      {/* Capture Control & Filter Bar */}
      <div className="luxury-card p-5 bg-white space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3.5">
            {/* Interface Selector */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-[#182230]">Interface:</span>
              <select
                value={selectedIface}
                onChange={(e) => setSelectedIface(e.target.value)}
                disabled={isCapturing}
                className="px-3 py-2 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs font-mono text-[#182230] focus:outline-none focus:border-[#C5A46D] max-w-xs"
              >
                {interfaces.map((iface, i) => (
                  <option key={i} value={(iface as any).device_name || iface.name}>
                    {iface.name} {iface.ipv4 !== 'N/A' ? `(${iface.ipv4})` : ''}
                  </option>
                ))}
              </select>
            </div>

            {/* BPF Filter Input */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-[#182230]">BPF:</span>
              <input
                type="text"
                value={bpfFilter}
                onChange={(e) => setBpfFilter(e.target.value)}
                disabled={isCapturing}
                placeholder="e.g. icmp or port 80"
                className="px-3 py-2 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs font-mono text-[#182230] placeholder-slate-400 focus:outline-none focus:border-[#C5A46D] w-48"
              />
            </div>
          </div>

          {/* PCAP Operations */}
          <div className="flex items-center gap-2.5">
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
              className="px-3.5 py-2 rounded-lg bg-white hover:bg-[#FAF8F5] text-[#182230] text-xs font-medium border border-[#E8E4DA] flex items-center gap-1.5 shadow-sm transition hover:border-[#D5CEBE] cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5 text-[#182230]" />
              {isUploading ? 'Parsing...' : 'Upload PCAP'}
            </button>

            <a
              href={getPcapExportUrl()}
              download="netsecure_capture.pcap"
              className="px-3.5 py-2 rounded-lg bg-white hover:bg-[#FAF8F5] text-[#182230] text-xs font-medium border border-[#E8E4DA] flex items-center gap-1.5 shadow-sm transition hover:border-[#D5CEBE]"
            >
              <Download className="w-3.5 h-3.5 text-[#1D4ED8]" />
              Export PCAP
            </a>
          </div>
        </div>

        {uploadStatus && (
          <div className="px-4 py-2.5 rounded-lg bg-[#FAF8F5] border border-[#C5A46D]/60 text-xs font-mono text-[#182230] flex items-center justify-between">
            <span className="flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#16856A]" />
              {uploadStatus}
            </span>
            <button onClick={() => setUploadStatus(null)} className="text-slate-400 hover:text-[#182230]">✕</button>
          </div>
        )}

        {/* Filter Pills & Live Search Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-[#E8E4DA]">
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
            <span className="text-[11px] font-semibold text-[#64748B] mr-1">Filter:</span>
            {protocolFilters.map((proto) => {
              const isActive = selectedProtocol.toUpperCase() === proto.toUpperCase();
              return (
                <button
                  key={proto}
                  onClick={() => onProtocolChange(proto)}
                  className={`px-3 py-1 rounded-md text-xs font-mono transition cursor-pointer ${
                    isActive
                      ? 'bg-[#182230] text-white font-semibold shadow-xs'
                      : 'bg-[#FAF8F5] text-[#64748B] border border-[#E8E4DA] hover:text-[#182230] hover:bg-white'
                  }`}
                >
                  {proto}
                </button>
              );
            })}
          </div>

          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter IP, MAC, Info..."
              className="pl-8 pr-3 py-1.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs text-[#182230] placeholder-slate-400 focus:outline-none focus:border-[#C5A46D] w-60"
            />
          </div>
        </div>
      </div>

      {/* Real-time Packet Table */}
      <div className="luxury-card bg-white overflow-hidden space-y-0">
        <div className="overflow-x-auto max-h-[520px]">
          <table className="w-full text-xs text-left">
            <thead className="luxury-table-header text-[#64748B] uppercase font-semibold text-[10px] tracking-wider sticky top-0 z-10">
              <tr>
                <th className="py-3 px-4 w-16 text-center">No.</th>
                <th className="py-3 px-4 w-28">Timestamp</th>
                <th className="py-3 px-4 w-36">Source IP</th>
                <th className="py-3 px-4 w-36">Destination IP</th>
                <th className="py-3 px-4 w-24">Protocol</th>
                <th className="py-3 px-4 w-20">Length</th>
                <th className="py-3 px-4">Packet Description & Layer Info</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#F1F5F9] font-mono text-[#182230]">
              {filteredPackets.length > 0 ? (
                filteredPackets.map((pkt) => {
                  const isSelected = selectedPacket?.packet_num === pkt.packet_num;
                  const hasVuln = pkt.details?.security?.has_credentials;
                  return (
                    <tr
                      key={pkt.packet_num}
                      onClick={() => onSelectPacket(pkt)}
                      className={`cursor-pointer transition-colors select-none ${
                        isSelected
                          ? 'bg-[#FAF8F5] border-l-4 border-l-[#C5A46D]'
                          : hasVuln
                          ? 'bg-[#FDF2F2]/60 hover:bg-[#FDF2F2]'
                          : 'hover:bg-[#FAF8F5]'
                      }`}
                    >
                      <td className="py-2.5 px-4 text-center text-[#64748B] font-semibold">{pkt.packet_num}</td>
                      <td className="py-2.5 px-4 text-[#64748B]">{pkt.timestamp}</td>
                      <td className="py-2.5 px-4 text-[#1D4ED8] font-semibold">{pkt.src_ip}</td>
                      <td className="py-2.5 px-4 text-[#182230] font-semibold">{pkt.dst_ip}</td>
                      <td className="py-2.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getProtocolBadge(pkt.protocol)}`}>
                          {pkt.protocol}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-[#64748B]">{pkt.length} B</td>
                      <td className="py-2.5 px-4 text-[#334155] truncate max-w-md">
                        {(pkt as any).source_type === 'live_tshark' && (
                          <span className="mr-2 px-1.5 py-0.5 rounded bg-[#F0FDF4] text-[#16856A] text-[9px] font-bold border border-[#DCFCE7]">
                            LIVE
                          </span>
                        )}
                        {hasVuln && (
                          <span className="mr-2 px-1.5 py-0.5 rounded bg-[#FDF2F2] text-[#C64747] text-[9px] font-bold border border-[#FDE8E8]">
                            CLEARTEXT LEAK
                          </span>
                        )}
                        <span>{pkt.info}</span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[#64748B] font-sans">
                    <Radio className="w-8 h-8 mx-auto mb-2 opacity-30 text-[#C5A46D]" />
                    <p className="text-sm font-semibold text-[#182230]">No packets matching current filter</p>
                    <p className="text-xs text-[#64748B] mt-0.5">Start live capture or load baseline PCAP</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Footer Summary Strip */}
        <div className="p-4 bg-[#FAF8F5] border-t border-[#E8E4DA] flex flex-wrap items-center justify-between gap-3 text-xs text-[#64748B]">
          <div className="flex items-center gap-3">
            <span>Showing <b className="text-[#182230]">{filteredPackets.length}</b> of {packets.length} packets</span>
            <span className="text-slate-300">|</span>
            <span className="text-[11px]">
              Engine: <b className="text-[#16856A]">TShark 4.6.10 / Npcap</b>
            </span>
          </div>
          <div className="text-[11px] text-[#C5A46D] font-medium">
            Select any row to inspect complete Layer 2–7 dissection
          </div>
        </div>
      </div>

      {/* Permission / Authorization Modal */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 bg-[#111827]/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white border border-[#E8E4DA] rounded-xl max-w-md w-full p-6 shadow-2xl text-[#182230] space-y-4 animate-in fade-in duration-200">
            <div className="flex items-center gap-3 pb-3 border-b border-[#E8E4DA]">
              <div className="w-10 h-10 rounded-lg bg-[#FAF8F5] border border-[#C5A46D]/40 flex items-center justify-center text-[#C5A46D]">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-semibold text-base text-[#182230]">Authorize Live Packet Capture</h3>
                <p className="text-xs text-[#64748B]">Lab Compliance & Packet Filter Authorization</p>
              </div>
            </div>

            <p className="text-xs text-[#475569] leading-relaxed">
              You are about to start promiscuous packet capture on adapter <b className="text-[#182230] font-mono">{selectedIface}</b>. 
              Under academic lab rules, packet sniffing must be conducted on authorized educational lab hardware (Machine A and Machine B).
            </p>

            <div className="p-3.5 bg-[#FAF8F5] rounded-lg border border-[#E8E4DA] text-xs text-[#64748B] space-y-1 font-mono">
              <div>✓ Selected Interface: <span className="text-[#182230]">{selectedIface}</span></div>
              <div>✓ BPF Filter: <span className="text-[#182230]">{bpfFilter || 'None (Promiscuous)'}</span></div>
              <div>✓ Engine: <span className="text-[#16856A] font-semibold">TShark & Npcap Kernel Driver</span></div>
            </div>

            <div className="flex justify-end gap-2.5 pt-2">
              <button
                onClick={() => setShowAuthModal(false)}
                className="px-4 py-2 rounded-lg bg-white hover:bg-[#FAF8F5] text-[#182230] text-xs font-medium border border-[#E8E4DA] transition cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmStart}
                className="px-4 py-2 rounded-lg bg-[#182230] hover:bg-[#111827] text-white text-xs font-semibold shadow-sm transition cursor-pointer"
              >
                Authorize & Start
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
