import React, { useState } from 'react';
import { 
  Shield, Activity, Download, CheckCircle2, 
  Terminal, X, HelpCircle
} from 'lucide-react';
import { SystemStatus, getPdfReportUrl, loadSamplePcap } from '../api';

interface NavbarProps {
  systemStatus: SystemStatus | null;
  wsConnected: boolean;
  isCloudPreview?: boolean;
  onNavigate: (view: string) => void;
  onRefresh: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ 
  systemStatus, 
  wsConnected, 
  isCloudPreview = false,
  onNavigate, 
  onRefresh 
}) => {
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
      <header className="h-16 border-b border-[#E2E8F0] bg-white sticky top-0 z-40 px-6 flex items-center justify-between text-[#0F172A]">
        {/* Left Context */}
        <div className="flex items-center gap-2">
          <span className="font-semibold text-sm text-[#0F172A]">
            Network Monitoring & Security Analysis
          </span>
          <span className="text-slate-300">/</span>
          <span className="text-xs text-[#64748B]">
            Ethernet LAN Lab
          </span>
        </div>

        {/* Status Indicators & Actions */}
        <div className="flex items-center gap-3">
          {/* Connection Status Indicator */}
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-[#F8FAFC] border border-[#E2E8F0] text-xs">
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-[#059669]' : 'bg-[#D97706]'}`} />
            <span className="text-xs font-medium text-[#475569]">
              {isCloudPreview 
                ? 'Cloud Interactive' 
                : wsConnected 
                ? 'WebSocket Active' 
                : 'Connecting'}
            </span>
          </div>

          {/* Engine Status */}
          <button 
            type="button"
            onClick={() => setShowTsharkHelp(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-[#E2E8F0] hover:bg-[#F8FAFC] text-xs transition cursor-pointer text-[#475569]"
            title="Inspect TShark & Capture status"
          >
            <Terminal className="w-3.5 h-3.5 text-[#64748B]" />
            <span className="text-[#64748B]">Engine:</span>
            <span className="text-[#059669] font-medium flex items-center gap-1">
              TShark <CheckCircle2 className="w-3 h-3" />
            </span>
          </button>

          {/* Load Sample PCAP */}
          <button
            type="button"
            onClick={handleLoadSample}
            disabled={loadingSample}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-[#F8FAFC] text-[#475569] text-xs font-medium border border-[#E2E8F0] transition disabled:opacity-50 cursor-pointer"
          >
            <Activity className="w-3.5 h-3.5 text-[#2563EB]" />
            {loadingSample ? 'Loading...' : 'Load Sample PCAP'}
          </button>

          {/* Export Report */}
          <a
            href={getPdfReportUrl()}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-xs font-medium shadow-xs transition"
          >
            <Download className="w-3.5 h-3.5" />
            Export Report
          </a>
        </div>
      </header>

      {/* Info Modal */}
      {showTsharkHelp && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-[#E2E8F0] rounded-xl max-w-md w-full p-6 shadow-xl text-[#0F172A] space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#E2E8F0]">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#2563EB]" />
                <h3 className="font-semibold text-sm text-[#0F172A]">TShark & Capture Telemetry</h3>
              </div>
              <button 
                onClick={() => setShowTsharkHelp(false)}
                className="text-slate-400 hover:text-[#0F172A] p-1 rounded-md"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs text-[#475569]">
              <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] space-y-1">
                <div className="flex justify-between font-semibold text-[#0F172A]">
                  <span>Engine Binary:</span>
                  <span className="text-[#059669]">Detected</span>
                </div>
                <p className="font-mono text-[11px] text-[#64748B] break-all">
                  {systemStatus?.tshark_path || 'C:\\Program Files\\Wireshark\\tshark.exe'}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] space-y-1">
                <div className="flex justify-between font-semibold text-[#0F172A]">
                  <span>Npcap Packet Driver:</span>
                  <span className="text-[#059669]">Operational</span>
                </div>
                <p className="text-[11px] text-[#64748B]">
                  Captures raw frames from Machine A and Machine B across Ethernet LAN.
                </p>
              </div>
            </div>

            <div className="flex justify-end pt-1">
              <button
                onClick={() => setShowTsharkHelp(false)}
                className="px-4 py-1.5 rounded-lg bg-[#0F172A] text-white text-xs font-medium cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
