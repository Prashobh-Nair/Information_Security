import React, { useState } from 'react';
import { 
  Shield, Activity, Wifi, Download, FileText, 
  HelpCircle, AlertTriangle, CheckCircle2, Server, Terminal, X, ArrowUpRight
} from 'lucide-react';
import { SystemStatus, getPdfReportUrl, loadSamplePcap } from '../api';

interface NavbarProps {
  systemStatus: SystemStatus | null;
  wsConnected: boolean;
  onNavigate: (view: string) => void;
  onRefresh: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ systemStatus, wsConnected, onNavigate, onRefresh }) => {
  const [showTsharkHelp, setShowTsharkHelp] = useState(false);
  const [loadingSample, setLoadingSample] = useState(false);

  const handleLoadSample = async () => {
    try {
      setLoadingSample(true);
      await loadSamplePcap();
      onRefresh();
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingSample(false);
    }
  };

  return (
    <>
      <header className="h-16 border-b border-[#E8E4DA] bg-white/95 backdrop-blur sticky top-0 z-40 px-8 flex items-center justify-between text-[#182230]">
        {/* Left: View Breadcrumbs / Context */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-sm tracking-tight text-[#182230]">
              Network Telemetry Console
            </span>
            <span className="text-slate-300">/</span>
            <span className="text-xs font-medium text-[#64748B]">
              Ethernet LAN Security Lab
            </span>
          </div>
        </div>

        {/* Status Indicators & Quick Actions */}
        <div className="flex items-center gap-3.5">
          {/* WebSocket Pulse */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FAF8F5] border border-[#E8E4DA] text-xs font-sans">
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-[#16856A]' : 'bg-[#C18A35]'}`} />
            <span className="text-xs font-medium text-[#182230]">
              {wsConnected ? 'Live Socket Connected' : 'Connecting Socket'}
            </span>
          </div>

          {/* TShark Engine Status */}
          <button 
            type="button"
            onClick={() => setShowTsharkHelp(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-white border border-[#E8E4DA] hover:border-[#C5A46D] hover:bg-[#FAF8F5] transition text-xs shadow-sm cursor-pointer"
            title="Inspect Wireshark & TShark installation telemetry"
          >
            <Terminal className="w-3.5 h-3.5 text-[#182230]" strokeWidth={2} />
            <span className="text-[#64748B] font-medium">Capture Engine:</span>
            {systemStatus?.tshark_installed ? (
              <span className="text-[#16856A] font-semibold flex items-center gap-1">
                TShark Verified <CheckCircle2 className="w-3.5 h-3.5" />
              </span>
            ) : (
              <span className="text-[#1D4ED8] font-semibold flex items-center gap-1">
                Dual Engine Active <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
              </span>
            )}
          </button>

          {/* Load Sample Capture */}
          <button
            type="button"
            onClick={handleLoadSample}
            disabled={loadingSample}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-white hover:bg-[#FAF8F5] text-[#182230] text-xs font-medium border border-[#E8E4DA] shadow-sm transition hover:border-[#D5CEBE] disabled:opacity-50 cursor-pointer"
          >
            <Activity className="w-3.5 h-3.5 text-[#C5A46D]" />
            {loadingSample ? 'Parsing Frames...' : 'Load Baseline PCAP'}
          </button>

          {/* Export PDF Report */}
          <a
            href={getPdfReportUrl()}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-[#1D4ED8] hover:bg-[#1E40AF] text-white text-xs font-semibold shadow-sm transition"
          >
            <Download className="w-3.5 h-3.5" />
            Export Audit Report
          </a>
        </div>
      </header>

      {/* TShark / Wireshark Installation Info Modal */}
      {showTsharkHelp && (
        <div className="fixed inset-0 z-50 bg-[#111827]/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white border border-[#E8E4DA] rounded-xl max-w-xl w-full p-6 shadow-2xl text-[#182230] space-y-5 animate-in fade-in duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-[#E8E4DA]">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-[#FAF8F5] border border-[#C5A46D]/40 flex items-center justify-center">
                  <Terminal className="w-4 h-4 text-[#C5A46D]" />
                </div>
                <div>
                  <h3 className="font-semibold text-base text-[#182230]">TShark & Npcap Telemetry</h3>
                  <p className="text-xs text-[#64748B]">Kernel Packet Filtering & Real-Time Engine</p>
                </div>
              </div>
              <button 
                onClick={() => setShowTsharkHelp(false)}
                className="text-slate-400 hover:text-[#182230] p-1 rounded-md transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3.5 text-xs">
              <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-[#182230]">TShark Binary Location:</span>
                  <span className="font-mono text-[11px] text-[#16856A] font-semibold">Detected</span>
                </div>
                <p className="font-mono text-[11px] text-[#475569] break-all">
                  {systemStatus?.tshark_path || 'C:\\Program Files\\Wireshark\\tshark.exe'}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA]">
                  <span className="text-[#64748B] block text-[11px] mb-1">Npcap Driver</span>
                  <span className="font-semibold text-[#16856A] flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Operational
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA]">
                  <span className="text-[#64748B] block text-[11px] mb-1">Active Status</span>
                  <span className="font-semibold text-[#182230]">
                    {systemStatus?.capture_active ? 'Capturing Frames' : 'Ready (Idle)'}
                  </span>
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-slate-600 space-y-2">
                <h4 className="font-semibold text-[#182230] text-xs">How Live Capture Operates:</h4>
                <ul className="list-disc pl-4 space-y-1 text-[11px] leading-relaxed">
                  <li>Runs asynchronous <code className="bg-white px-1 py-0.5 rounded border border-[#E8E4DA] font-mono text-black">tshark -i &lt;interface&gt; -l -T ek</code>.</li>
                  <li>Extracts multi-layer frames (Ethernet MAC, IPv4, TCP/UDP, ICMP Type/Code).</li>
                  <li>Real-time frames stream straight to the dashboard via WebSockets.</li>
                </ul>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowTsharkHelp(false)}
                className="px-4 py-2 rounded-lg bg-[#182230] hover:bg-[#111827] text-white text-xs font-medium transition"
              >
                Close Telemetry
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
