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
    { id: 'ICMP', label: 'ICMP (Ping Analysis)', icon: Activity, badge: 'Type 8/0' },
    { id: 'ARP', label: 'ARP (Address Resolution)', icon: Network, badge: 'IP⇄MAC' },
    { id: 'DNS', label: 'DNS (Domain Queries)', icon: Globe, badge: 'Port 53' },
    { id: 'HTTP', label: 'HTTP (Cleartext Web)', icon: Unlock, badge: 'Port 80' },
    { id: 'HTTPS', label: 'HTTPS (TLS Encryption)', icon: Lock, badge: 'TLS 1.3' },
    { id: 'FTP', label: 'FTP (File Transfer)', icon: FolderArchive, badge: 'Port 21' },
  ];

  return (
    <div className="space-y-6">
      {/* Editorial Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-2 border-b border-[#E8E4DA]">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold tracking-wider uppercase text-[#C5A46D]">
              Deep Dissection
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-[11px] font-mono text-[#64748B]">Multi-Protocol Verification</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#182230] mt-1">
            Specialized Protocol Analysis Suite
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Dedicated analyzers verifying ICMP ping correlation, ARP bindings, DNS queries, and cleartext vs TLS transactions.
          </p>
        </div>
      </div>

      {/* Luxury Tabs Bar */}
      <div className="luxury-card p-1.5 bg-white border border-[#E8E4DA] flex flex-wrap gap-1.5 shadow-sm">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
                isActive
                  ? 'bg-[#182230] text-white shadow-xs'
                  : 'bg-white text-[#64748B] hover:text-[#182230] hover:bg-[#FAF8F5]'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-[#C5A46D]' : 'text-[#64748B]'}`} />
              <span>{tab.label}</span>
              <span className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                isActive ? 'bg-[#111827] text-white' : 'bg-[#FAF8F5] text-[#64748B] border border-[#E8E4DA]'
              }`}>
                {tab.badge}
              </span>
            </button>
          );
        })}
      </div>

      {loading ? (
        <div className="luxury-card p-12 text-center text-xs text-[#64748B] font-mono bg-white">
          Parsing {activeTab} protocol frames...
        </div>
      ) : (
        <div className="space-y-6">
          {/* ========================================= */}
          {/* 1. ICMP TAB */}
          {/* ========================================= */}
          {activeTab === 'ICMP' && data && (
            <div className="space-y-6">
              <div className="luxury-card p-5 bg-white border border-[#E8E4DA] border-l-4 border-l-[#16856A] flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-[#F0FDF4] border border-[#DCFCE7] flex items-center justify-center text-[#16856A] shrink-0">
                  <CheckCircle2 className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="font-semibold text-[#182230] text-sm">ICMP Ping Verification Confirmed (Lab Question 12)</h4>
                  <p className="text-xs text-[#64748B] mt-0.5 leading-relaxed">
                    {data.lab_verdict}
                  </p>
                </div>
              </div>

              {/* Stats overview */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="luxury-card p-5 bg-white border-t-2 border-t-[#16856A]">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-[#64748B] block mb-1">
                    Echo Requests (Machine A)
                  </span>
                  <span className="text-2xl font-bold font-sans text-[#16856A]">{data.echo_requests_count}</span>
                  <span className="text-[11px] text-[#94A3B8] block mt-1 font-mono">Type 8, Code 0 (Outbound Probe)</span>
                </div>
                <div className="luxury-card p-5 bg-white border-t-2 border-t-[#1D4ED8]">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-[#64748B] block mb-1">
                    Echo Replies (Machine B)
                  </span>
                  <span className="text-2xl font-bold font-sans text-[#1D4ED8]">{data.echo_replies_count}</span>
                  <span className="text-[11px] text-[#94A3B8] block mt-1 font-mono">Type 0, Code 0 (Inbound Response)</span>
                </div>
                <div className="luxury-card p-5 bg-white border-t-2 border-t-[#182230]">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-[#64748B] block mb-1">
                    Total ICMP Packets
                  </span>
                  <span className="text-2xl font-bold font-sans text-[#182230]">{data.total_icmp_packets}</span>
                  <span className="text-[11px] text-[#94A3B8] block mt-1 font-mono">IP Protocol Number 0x01</span>
                </div>
              </div>

              {/* Ping Correlation Table */}
              <div className="luxury-card p-6 bg-white space-y-4">
                <div>
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">Sequence Matching</span>
                  <h3 className="font-semibold text-sm text-[#182230]">Bidirectional Ping Correlation (Request ⇄ Reply Pairs)</h3>
                  <p className="text-xs text-[#64748B] mt-0.5">Correlating Machine A Echo Request sequence with Machine B Echo Reply</p>
                </div>
                
                <div className="overflow-x-auto border border-[#E8E4DA] rounded-lg">
                  <table className="w-full text-xs text-left">
                    <thead className="luxury-table-header text-[#64748B] uppercase font-semibold text-[10px] tracking-wider">
                      <tr>
                        <th className="py-3 px-4">Req #</th>
                        <th className="py-3 px-4">Req Time</th>
                        <th className="py-3 px-4">Reply #</th>
                        <th className="py-3 px-4">Sender (Machine A)</th>
                        <th className="py-3 px-4">Target (Machine B)</th>
                        <th className="py-3 px-4">Type/Code Exchange</th>
                        <th className="py-3 px-4 text-right">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#F1F5F9] font-mono text-[#182230]">
                      {data.ping_correlations?.map((pair: any, i: number) => (
                        <tr key={i} className="hover:bg-[#FAF8F5] transition-colors">
                          <td className="py-2.5 px-4 text-[#16856A] font-bold">#{pair.request_num}</td>
                          <td className="py-2.5 px-4 text-[#64748B]">{pair.request_time}</td>
                          <td className="py-2.5 px-4 text-[#1D4ED8] font-bold">#{pair.reply_num}</td>
                          <td className="py-2.5 px-4 text-[#182230]">{pair.source_host}</td>
                          <td className="py-2.5 px-4 text-[#182230]">{pair.target_host}</td>
                          <td className="py-2.5 px-4 text-[#7C3AED]">{pair.type_code_summary}</td>
                          <td className="py-2.5 px-4 text-right">
                            <span className="px-2.5 py-0.5 rounded-full bg-[#F0FDF4] text-[#16856A] text-[10px] font-semibold border border-[#DCFCE7]">
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

          {/* ========================================= */}
          {/* 2. ARP TAB */}
          {/* ========================================= */}
          {activeTab === 'ARP' && data && (
            <div className="space-y-6">
              <div className="luxury-card p-5 bg-white border border-[#E8E4DA] text-xs text-[#334155] leading-relaxed">
                <b className="text-[#182230]">Address Resolution Protocol (ARP):</b> {data.academic_note}
              </div>

              {/* Resolved IP to MAC Table */}
              <div className="luxury-card p-6 bg-white space-y-4">
                <div>
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">Hardware Mapping</span>
                  <h3 className="font-semibold text-sm text-[#182230]">Discovered IP-to-MAC Binding Table</h3>
                  <p className="text-xs text-[#64748B] mt-0.5">Physical MAC addresses mapped by ARP broadcast and unicast replies</p>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {data.resolved_ip_mac_table?.map((item: any, i: number) => (
                    <div key={i} className="p-4 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] flex items-center justify-between font-mono text-xs">
                      <div>
                        <span className="text-[#64748B] block text-[10px] uppercase font-semibold">IPv4 Address:</span>
                        <span className="text-[#1D4ED8] font-bold text-sm">{item.ip}</span>
                      </div>
                      <ArrowRight className="w-4 h-4 text-[#94A3B8]" />
                      <div className="text-right">
                        <span className="text-[#64748B] block text-[10px] uppercase font-semibold">Hardware MAC Address:</span>
                        <span className="text-[#16856A] font-bold text-sm">{item.mac}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* ARP Transaction Logs */}
              <div className="luxury-card p-6 bg-white space-y-4">
                <h3 className="font-semibold text-sm text-[#182230]">Captured ARP Broadcasts & Responses</h3>
                <div className="overflow-x-auto border border-[#E8E4DA] rounded-lg">
                  <table className="w-full text-xs text-left font-mono">
                    <thead className="luxury-table-header text-[#64748B] uppercase font-semibold text-[10px] tracking-wider">
                      <tr>
                        <th className="py-3 px-4">Pkt #</th>
                        <th className="py-3 px-4">Operation</th>
                        <th className="py-3 px-4">Sender IP</th>
                        <th className="py-3 px-4">Sender MAC</th>
                        <th className="py-3 px-4">Target IP</th>
                        <th className="py-3 px-4">Target MAC</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#F1F5F9] text-[#182230]">
                      {data.arp_transactions?.map((t: any, i: number) => (
                        <tr key={i} className="hover:bg-[#FAF8F5] transition-colors">
                          <td className="py-2.5 px-4 text-[#64748B]">#{t.packet_num}</td>
                          <td className="py-2.5 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              t.operation.includes('Request') ? 'bg-[#FFFBEB] text-[#C18A35] border-[#FEF3C7]' : 'bg-[#F0FDF4] text-[#16856A] border-[#DCFCE7]'
                            }`}>
                              {t.operation}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 text-[#1D4ED8] font-bold">{t.sender_ip}</td>
                          <td className="py-2.5 px-4 text-[#334155]">{t.sender_mac}</td>
                          <td className="py-2.5 px-4 text-[#16856A] font-bold">{t.target_ip}</td>
                          <td className="py-2.5 px-4 text-[#334155]">{t.target_mac}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ========================================= */}
          {/* 3. DNS TAB */}
          {/* ========================================= */}
          {activeTab === 'DNS' && data && (
            <div className="space-y-6">
              <div className="luxury-card p-5 bg-white border border-[#E8E4DA] text-xs text-[#334155] leading-relaxed">
                <b className="text-[#182230]">Domain Name System (DNS):</b> {data.academic_note}
              </div>

              {/* Resolution Map */}
              <div className="luxury-card p-6 bg-white space-y-4">
                <h3 className="font-semibold text-sm text-[#182230]">Domain Resolution Summary</h3>
                <div className="space-y-2.5 font-mono text-xs">
                  {data.domain_resolution_map?.map((item: any, i: number) => (
                    <div key={i} className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] flex items-center justify-between">
                      <div>
                        <span className="text-[#64748B] text-[10px] uppercase font-semibold block">Queried FQDN:</span>
                        <span className="text-[#7C3AED] font-bold text-sm">{item.domain}</span>
                      </div>
                      <div className="text-right">
                        <span className="text-[#64748B] text-[10px] uppercase font-semibold block">Resolved Address(es):</span>
                        <span className="text-[#16856A] font-bold text-sm">{item.addresses.join(', ')}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* DNS Queries Table */}
              <div className="luxury-card p-6 bg-white space-y-4">
                <h3 className="font-semibold text-sm text-[#182230]">DNS Packet Records (UDP Port 53)</h3>
                <div className="overflow-x-auto border border-[#E8E4DA] rounded-lg">
                  <table className="w-full text-xs text-left font-mono">
                    <thead className="luxury-table-header text-[#64748B] uppercase font-semibold text-[10px] tracking-wider">
                      <tr>
                        <th className="py-3 px-4">Pkt #</th>
                        <th className="py-3 px-4">Type</th>
                        <th className="py-3 px-4">Domain / Query Name</th>
                        <th className="py-3 px-4">Client</th>
                        <th className="py-3 px-4">Server</th>
                        <th className="py-3 px-4">Answers / RDATA</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#F1F5F9] text-[#182230]">
                      {data.dns_records?.map((d: any, i: number) => (
                        <tr key={i} className="hover:bg-[#FAF8F5] transition-colors">
                          <td className="py-2.5 px-4 text-[#64748B]">#{d.packet_num}</td>
                          <td className="py-2.5 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              d.is_response ? 'bg-[#F5F3FF] text-[#7C3AED] border-[#EDE9FE]' : 'bg-[#EFF6FF] text-[#1D4ED8] border-[#DBEAFE]'
                            }`}>
                              {d.is_response ? 'Response' : 'Query'} ({d.query_type})
                            </span>
                          </td>
                          <td className="py-2.5 px-4 font-semibold text-[#182230]">{d.query_name}</td>
                          <td className="py-2.5 px-4 text-[#1D4ED8]">{d.client_ip}</td>
                          <td className="py-2.5 px-4 text-[#64748B]">{d.server_ip}</td>
                          <td className="py-2.5 px-4 text-[#16856A] truncate max-w-xs font-semibold">
                            {d.answers?.length > 0 ? d.answers.join(', ') : 'Pending'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ========================================= */}
          {/* 4. HTTP TAB */}
          {/* ========================================= */}
          {activeTab === 'HTTP' && data && (
            <div className="space-y-6">
              <div className="luxury-card p-5 bg-white border border-[#E8E4DA] border-l-4 border-l-[#C64747] flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-[#FDF2F2] border border-[#FDE8E8] flex items-center justify-center text-[#C64747] shrink-0">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="font-semibold text-[#182230] text-sm">Security Evaluation: Unencrypted HTTP (CWE-319)</h4>
                  <p className="text-xs text-[#64748B] mt-0.5 leading-relaxed">
                    {data.security_verdict}
                  </p>
                </div>
              </div>

              {/* Leaked credentials cards */}
              {data.leaked_credentials?.length > 0 && (
                <div className="luxury-card p-6 bg-white space-y-4">
                  <h3 className="font-semibold text-sm text-[#C64747] flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4" />
                    Captured Cleartext Authentication Credentials
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {data.leaked_credentials.map((leak: any, i: number) => (
                      <div key={i} className="p-4 rounded-lg bg-[#FDF2F2] border border-[#FDE8E8] text-xs font-mono space-y-2">
                        <div className="flex justify-between border-b border-[#FEE2E2] pb-1.5">
                          <span className="text-[#64748B]">Captured in Frame:</span>
                          <span className="text-[#C64747] font-bold">#{leak.packet_num}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[#64748B]">Username:</span>
                          <span className="text-[#182230] font-bold">{leak.username}</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-[#64748B]">Password:</span>
                          <span className="text-[#C64747] font-bold bg-white px-2.5 py-0.5 rounded border border-[#FDE8E8]">{leak.password}</span>
                        </div>
                        <div className="pt-2 text-[10px] text-[#64748B] border-t border-[#FEE2E2]">
                          Evidence: <code className="text-[#C64747] font-bold">{leak.evidence}</code>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* HTTP Transactions Table */}
              <div className="luxury-card p-6 bg-white space-y-4">
                <h3 className="font-semibold text-sm text-[#182230]">HTTP Transactions (Port 80)</h3>
                <div className="overflow-x-auto border border-[#E8E4DA] rounded-lg">
                  <table className="w-full text-xs text-left font-mono">
                    <thead className="luxury-table-header text-[#64748B] uppercase font-semibold text-[10px] tracking-wider">
                      <tr>
                        <th className="py-3 px-4">Pkt #</th>
                        <th className="py-3 px-4">Method</th>
                        <th className="py-3 px-4">URI / Resource</th>
                        <th className="py-3 px-4">Source IP</th>
                        <th className="py-3 px-4">Destination IP</th>
                        <th className="py-3 px-4">Payload Data</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#F1F5F9] text-[#182230]">
                      {data.http_transactions?.map((h: any, i: number) => (
                        <tr key={i} className="hover:bg-[#FAF8F5] transition-colors">
                          <td className="py-2.5 px-4 text-[#64748B]">#{h.packet_num}</td>
                          <td className="py-2.5 px-4">
                            <span className="px-2 py-0.5 rounded bg-[#FFFBEB] text-[#C18A35] border border-[#FEF3C7] text-[10px] font-bold">
                              {h.method}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 font-semibold text-[#182230]">{h.uri}</td>
                          <td className="py-2.5 px-4 text-[#1D4ED8]">{h.src_ip}</td>
                          <td className="py-2.5 px-4 text-[#64748B]">{h.dst_ip}</td>
                          <td className="py-2.5 px-4 text-[#475569] truncate max-w-xs">{h.body || 'No Body'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ========================================= */}
          {/* 5. HTTPS TAB */}
          {/* ========================================= */}
          {activeTab === 'HTTPS' && data && (
            <div className="space-y-6">
              <div className="luxury-card p-5 bg-white border border-[#E8E4DA] border-l-4 border-l-[#0284C7] flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-[#F0F9FF] border border-[#E0F2FE] flex items-center justify-center text-[#0284C7] shrink-0">
                  <Lock className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="font-semibold text-[#182230] text-sm">Transport Layer Security (TLS 1.3 / 1.2) Confirmed</h4>
                  <p className="text-xs text-[#64748B] mt-0.5 leading-relaxed">
                    {data.security_verdict}
                  </p>
                </div>
              </div>

              {/* Stats overview */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                <div className="luxury-card p-5 bg-white">
                  <span className="text-[#64748B] block mb-1 font-sans font-semibold">Total HTTPS Packets</span>
                  <span className="text-2xl font-bold text-[#0284C7]">{data.total_https_packets}</span>
                  <span className="text-[11px] text-[#94A3B8] block mt-1 font-sans">Port 443 Encrypted Flow</span>
                </div>
                <div className="luxury-card p-5 bg-white">
                  <span className="text-[#64748B] block mb-1 font-sans font-semibold">Handshake Frames</span>
                  <span className="text-2xl font-bold text-[#7C3AED]">{data.handshake_packets_count}</span>
                  <span className="text-[11px] text-[#94A3B8] block mt-1 font-sans">Client/Server Hello, Key Share</span>
                </div>
                <div className="luxury-card p-5 bg-white">
                  <span className="text-[#64748B] block mb-1 font-sans font-semibold">Encrypted App Records</span>
                  <span className="text-2xl font-bold text-[#16856A]">{data.encrypted_app_data_count}</span>
                  <span className="text-[11px] text-[#94A3B8] block mt-1 font-sans">Opaque Ciphertext (0x17)</span>
                </div>
              </div>

              {/* SNI Hosts */}
              <div className="luxury-card p-6 bg-white space-y-3">
                <h3 className="font-semibold text-sm text-[#182230]">Observed Server Name Indications (SNI)</h3>
                <p className="text-xs text-[#64748B] leading-relaxed">
                  Domain identities negotiated in plaintext Client Hello before symmetric cipher lock is activated:
                </p>
                
                <div className="flex flex-wrap gap-2 pt-1">
                  {data.observed_sni_hosts?.map((sni: string, i: number) => (
                    <span key={i} className="px-3 py-1 rounded-md bg-[#FAF8F5] border border-[#E8E4DA] text-[#182230] font-mono text-xs">
                      {sni}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ========================================= */}
          {/* 6. FTP TAB */}
          {/* ========================================= */}
          {activeTab === 'FTP' && data && (
            <div className="space-y-6">
              <div className="luxury-card p-5 bg-white border border-[#E8E4DA] border-l-4 border-l-[#C64747] flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-[#FDF2F2] border border-[#FDE8E8] flex items-center justify-center text-[#C64747] shrink-0">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="font-semibold text-[#182230] text-sm">FTP Protocol Security Audit (RFC 959)</h4>
                  <p className="text-xs text-[#64748B] mt-0.5 leading-relaxed">
                    {data.security_verdict}
                  </p>
                </div>
              </div>

              {/* Plaintext Command History */}
              <div className="luxury-card p-6 bg-white space-y-4">
                <h3 className="font-semibold text-sm text-[#182230]">Captured FTP Command Stream (Port 21)</h3>
                <div className="overflow-x-auto border border-[#E8E4DA] rounded-lg">
                  <table className="w-full text-xs text-left font-mono">
                    <thead className="luxury-table-header text-[#64748B] uppercase font-semibold text-[10px] tracking-wider">
                      <tr>
                        <th className="py-3 px-4">Pkt #</th>
                        <th className="py-3 px-4">Source IP</th>
                        <th className="py-3 px-4">Destination IP</th>
                        <th className="py-3 px-4">Raw FTP Command / Response</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#F1F5F9] text-[#182230]">
                      {data.commands?.map((cmd: any, i: number) => (
                        <tr key={i} className="hover:bg-[#FAF8F5] transition-colors">
                          <td className="py-2.5 px-4 text-[#64748B]">#{cmd.packet_num}</td>
                          <td className="py-2.5 px-4 text-[#1D4ED8]">{cmd.src_ip}</td>
                          <td className="py-2.5 px-4 text-[#64748B]">{cmd.dst_ip}</td>
                          <td className="py-2.5 px-4 font-semibold text-[#182230]">{cmd.command}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
