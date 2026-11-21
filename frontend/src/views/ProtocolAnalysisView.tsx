import React, { useState, useEffect } from 'react';
import { 
  Layers, Activity, Network, Globe, Lock, 
  Unlock, FolderArchive, ArrowRight, ShieldAlert, CheckCircle2 
} from 'lucide-react';
import { 
  getIcmpAnalysis, getArpAnalysis, getDnsAnalysis, 
  getHttpAnalysis, getHttpsAnalysis, getFtpAnalysis 
} from '../api';

interface ProtocolAnalysisViewProps {
  onSelectPacketForInspect?: (packetNum: number) => void;
}

export const ProtocolAnalysisView: React.FC<ProtocolAnalysisViewProps> = () => {
  const [activeTab, setActiveTab] = useState<'ICMP' | 'ARP' | 'DNS' | 'HTTP' | 'HTTPS' | 'FTP'>('ICMP');
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchProtocolData(activeTab);
  }, [activeTab]);

  const fetchProtocolData = async (tab: string) => {
    setLoading(true);
    try {
      let res;
      if (tab === 'ICMP') res = await getIcmpAnalysis();
      else if (tab === 'ARP') res = await getArpAnalysis();
      else if (tab === 'DNS') res = await getDnsAnalysis();
      else if (tab === 'HTTP') res = await getHttpAnalysis();
      else if (tab === 'HTTPS') res = await getHttpsAnalysis();
      else if (tab === 'FTP') res = await getFtpAnalysis();
      setData(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'ICMP', label: 'ICMP', icon: Activity },
    { id: 'ARP', label: 'ARP', icon: Network },
    { id: 'DNS', label: 'DNS', icon: Globe },
    { id: 'HTTP', label: 'HTTP', icon: Unlock },
    { id: 'HTTPS', label: 'HTTPS', icon: Lock },
    { id: 'FTP', label: 'FTP', icon: FolderArchive },
  ];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#E2E8F0]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#0F172A]">
            Protocol Analysis Suite
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Dedicated dissectors verifying ICMP, ARP, DNS, HTTP, HTTPS, and FTP.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-[#E2E8F0] pb-2">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer ${
                isActive
                  ? 'bg-[#2563EB] text-white shadow-xs'
                  : 'bg-white text-[#64748B] border border-[#E2E8F0] hover:bg-[#F8FAFC]'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {loading ? (
        <div className="p-8 text-center text-xs text-[#64748B] bg-white rounded-xl border border-[#E2E8F0]">
          Loading {activeTab} data...
        </div>
      ) : (
        <div className="space-y-5">
          {/* ICMP */}
          {activeTab === 'ICMP' && data && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-white border border-[#E2E8F0] border-l-4 border-l-[#059669] flex items-start gap-3 shadow-xs">
                <CheckCircle2 className="w-4 h-4 text-[#059669] shrink-0 mt-0.5" />
                <p className="text-xs text-[#0F172A] leading-relaxed">
                  {data.lab_verdict}
                </p>
              </div>

              <div className="p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-3">
                <h3 className="font-semibold text-xs text-[#0F172A]">Bidirectional Ping Correlation</h3>
                <div className="overflow-x-auto border border-[#E2E8F0] rounded-lg">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-[#F8FAFC] text-[#64748B] uppercase font-semibold text-[10px] tracking-wider border-b border-[#E2E8F0]">
                      <tr>
                        <th className="py-2.5 px-3">Req #</th>
                        <th className="py-2.5 px-3">Reply #</th>
                        <th className="py-2.5 px-3">Sender (A)</th>
                        <th className="py-2.5 px-3">Target (B)</th>
                        <th className="py-2.5 px-3">Exchange</th>
                        <th className="py-2.5 px-3 text-right">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#F1F5F9] font-mono text-[#0F172A]">
                      {data.ping_correlations?.map((pair: any, i: number) => (
                        <tr key={i} className="hover:bg-[#F8FAFC]">
                          <td className="py-2 px-3 text-[#059669] font-bold">#{pair.request_num}</td>
                          <td className="py-2 px-3 text-[#2563EB] font-bold">#{pair.reply_num}</td>
                          <td className="py-2 px-3 text-[#0F172A]">{pair.source_host}</td>
                          <td className="py-2 px-3 text-[#0F172A]">{pair.target_host}</td>
                          <td className="py-2 px-3 text-[#7C3AED]">{pair.type_code_summary}</td>
                          <td className="py-2 px-3 text-right">
                            <span className="px-2 py-0.2 rounded bg-[#ECFDF5] text-[#059669] text-[10px] font-semibold">
                              {pair.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ARP */}
          {activeTab === 'ARP' && data && (
            <div className="p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-3">
              <h3 className="font-semibold text-xs text-[#0F172A]">Resolved IP-to-MAC Binding</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {data.resolved_ip_mac_table?.map((item: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] flex items-center justify-between font-mono text-xs">
                    <div>
                      <span className="text-[10px] text-[#64748B] block">IP:</span>
                      <span className="text-[#2563EB] font-bold">{item.ip}</span>
                    </div>
                    <ArrowRight className="w-3.5 h-3.5 text-[#94A3B8]" />
                    <div className="text-right">
                      <span className="text-[10px] text-[#64748B] block">MAC:</span>
                      <span className="text-[#059669] font-bold">{item.mac}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* DNS */}
          {activeTab === 'DNS' && data && (
            <div className="p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-3">
              <h3 className="font-semibold text-xs text-[#0F172A]">Domain Name Lookups</h3>
              <div className="space-y-2 font-mono text-xs">
                {data.domain_resolution_map?.map((item: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] flex items-center justify-between">
                    <span className="text-[#7C3AED] font-bold">{item.domain}</span>
                    <span className="text-[#059669]">{item.addresses.join(', ')}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* HTTP */}
          {activeTab === 'HTTP' && data && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-white border border-[#E2E8F0] border-l-4 border-l-[#DC2626] shadow-xs flex items-start gap-3">
                <ShieldAlert className="w-4 h-4 text-[#DC2626] shrink-0 mt-0.5" />
                <p className="text-xs text-[#0F172A] leading-relaxed">
                  {data.security_verdict}
                </p>
              </div>

              {data.leaked_credentials?.map((leak: any, i: number) => (
                <div key={i} className="p-4 rounded-xl bg-[#FEF2F2] border border-[#FECACA] text-xs font-mono space-y-1.5">
                  <div className="text-[#DC2626] font-semibold">Captured Cleartext Credentials (Packet #{leak.packet_num})</div>
                  <div>Username: <b className="text-[#0F172A]">{leak.username}</b></div>
                  <div>Password: <b className="text-[#DC2626] bg-white px-2 py-0.5 rounded border border-[#FECACA]">{leak.password}</b></div>
                </div>
              ))}
            </div>
          )}

          {/* HTTPS */}
          {activeTab === 'HTTPS' && data && (
            <div className="p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-3">
              <div className="flex items-center gap-2 text-[#0284C7] text-xs font-semibold">
                <Lock className="w-4 h-4" />
                <span>{data.security_verdict}</span>
              </div>
              <p className="text-xs text-[#64748B]">All payload bytes sealed within TLS Application Data records.</p>
            </div>
          )}

          {/* FTP */}
          {activeTab === 'FTP' && data && (
            <div className="p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-3">
              <h3 className="font-semibold text-xs text-[#0F172A]">Captured FTP Commands (Port 21)</h3>
              <div className="overflow-x-auto border border-[#E2E8F0] rounded-lg">
                <table className="w-full text-xs text-left font-mono">
                  <thead className="bg-[#F8FAFC] text-[#64748B] text-[10px] border-b border-[#E2E8F0]">
                    <tr>
                      <th className="py-2.5 px-3">Pkt #</th>
                      <th className="py-2.5 px-3">Command</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#F1F5F9] text-[#0F172A]">
                    {data.commands?.map((cmd: any, i: number) => (
                      <tr key={i} className="hover:bg-[#F8FAFC]">
                        <td className="py-2 px-3 text-[#64748B]">#{cmd.packet_num}</td>
                        <td className="py-2 px-3 font-semibold">{cmd.command}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
