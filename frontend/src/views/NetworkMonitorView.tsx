import React, { useState } from 'react';
import { 
  Network, Laptop, Server, Send, Play, CheckCircle2, 
  XCircle, Clock, ArrowRight, ShieldCheck, RefreshCw, Cpu, Settings2, Activity
} from 'lucide-react';
import { 
  LabHosts, NetworkInterface, PingResult, executePing, 
  saveLabSettings, getLabHosts 
} from '../api';

interface NetworkMonitorViewProps {
  labHosts: LabHosts | null;
  interfaces: NetworkInterface[];
  onRefresh: () => void;
  onNavigateToPackets: (protocol?: string) => void;
}

export const NetworkMonitorView: React.FC<NetworkMonitorViewProps> = ({ 
  labHosts, 
  interfaces, 
  onRefresh, 
  onNavigateToPackets 
}) => {
  const [targetIp, setTargetIp] = useState(labHosts?.machine_b.ip || '192.168.1.1');
  const [packetCount, setPacketCount] = useState(4);
  const [pinging, setPinging] = useState(false);
  const [pingResult, setPingResult] = useState<PingResult | null>(null);
  const [pingError, setPingError] = useState<string | null>(null);

  // Editable settings
  const [editingSettings, setEditingSettings] = useState(false);
  const [machineAIp, setMachineAIp] = useState(labHosts?.machine_a.ip || '192.168.1.6');
  const [machineAMac, setMachineAMac] = useState(labHosts?.machine_a.mac || '1c:ce:51:32:87:5e');
  const [machineBIp, setMachineBIp] = useState(labHosts?.machine_b.ip || '192.168.1.1');
  const [machineBMac, setMachineBMac] = useState(labHosts?.machine_b.mac || '00:0c:29:4d:5e:6f');

  React.useEffect(() => {
    if (labHosts) {
      if (labHosts.machine_b?.ip && targetIp === '192.168.1.20') {
        setTargetIp(labHosts.machine_b.ip);
      }
      setMachineAIp(labHosts.machine_a?.ip || '192.168.1.6');
      setMachineAMac(labHosts.machine_a?.mac || '1c:ce:51:32:87:5e');
      setMachineBIp(labHosts.machine_b?.ip || '192.168.1.1');
      setMachineBMac(labHosts.machine_b?.mac || '00:0c:29:4d:5e:6f');
    }
  }, [labHosts]);

  const handlePing = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetIp.trim()) return;

    try {
      setPinging(true);
      setPingError(null);
      const res = await executePing(targetIp.trim(), packetCount);
      setPingResult(res);
      onRefresh();
    } catch (err: any) {
      setPingError(err.message || 'Ping failed to execute');
    } finally {
      setPinging(false);
    }
  };

  const handleSaveSettings = async () => {
    try {
      await saveLabSettings({
        machine_a_ip: machineAIp,
        machine_a_mac: machineAMac,
        machine_b_ip: machineBIp,
        machine_b_mac: machineBMac,
      });
      setEditingSettings(false);
      onRefresh();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-7">
      {/* Editorial Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-2 border-b border-[#E8E4DA]">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold tracking-wider uppercase text-[#C5A46D]">
              Layer 2 & 3 Connectivity
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-[11px] font-mono text-[#64748B]">RFC 792 ICMP Diagnostics</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#182230] mt-1">
            Network Topology & Ping Telemetry
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Interconnected Ethernet LAN nodes: Machine A (Local Examiner) and Machine B (Remote Target).
          </p>
        </div>

        <button
          onClick={() => setEditingSettings(!editingSettings)}
          className="px-4 py-2 rounded-lg bg-white hover:bg-[#FAF8F5] text-[#182230] text-xs font-medium border border-[#E8E4DA] shadow-sm transition flex items-center gap-2 cursor-pointer"
        >
          <Settings2 className="w-3.5 h-3.5 text-[#C5A46D]" />
          {editingSettings ? 'Close Config' : 'Configure Machine Identifiers'}
        </button>
      </div>

      {/* Edit IP/MAC Modal / Drawer */}
      {editingSettings && (
        <div className="luxury-card p-6 bg-white border border-[#E8E4DA] space-y-4 animate-in fade-in duration-200">
          <div className="flex items-center justify-between pb-3 border-b border-[#E8E4DA]">
            <h3 className="font-semibold text-sm text-[#182230]">Custom Machine Identifiers Configuration</h3>
            <span className="text-[11px] text-[#64748B]">Update local and peer network parameters</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="space-y-2">
              <label className="text-xs font-semibold text-[#182230]">Machine A IP (Local Sender)</label>
              <input
                type="text"
                value={machineAIp}
                onChange={(e) => setMachineAIp(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs font-mono text-[#182230] focus:border-[#C5A46D] focus:bg-white focus:outline-none"
              />
              <label className="text-xs font-semibold text-[#182230] pt-1 block">Machine A MAC Address</label>
              <input
                type="text"
                value={machineAMac}
                onChange={(e) => setMachineAMac(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs font-mono text-[#182230] focus:border-[#C5A46D] focus:bg-white focus:outline-none"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs font-semibold text-[#182230]">Machine B IP (Target Host)</label>
              <input
                type="text"
                value={machineBIp}
                onChange={(e) => {
                  setMachineBIp(e.target.value);
                  setTargetIp(e.target.value);
                }}
                className="w-full px-3.5 py-2 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs font-mono text-[#182230] focus:border-[#C5A46D] focus:bg-white focus:outline-none"
              />
              <label className="text-xs font-semibold text-[#182230] pt-1 block">Machine B MAC Address</label>
              <input
                type="text"
                value={machineBMac}
                onChange={(e) => setMachineBMac(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs font-mono text-[#182230] focus:border-[#C5A46D] focus:bg-white focus:outline-none"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2 border-t border-[#E8E4DA]">
            <button
              onClick={handleSaveSettings}
              className="px-4 py-2 rounded-lg bg-[#182230] hover:bg-[#111827] text-white text-xs font-medium transition cursor-pointer"
            >
              Save Identifiers
            </button>
          </div>
        </div>
      )}

      {/* Visual LAN Topology Diagram */}
      <div className="luxury-card p-6 bg-white space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#E8E4DA]">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">
            Physical Interconnect
          </span>
          <span className="text-xs font-mono text-[#64748B]">Subnet Mask: 255.255.255.0 (/24)</span>
        </div>

        <div className="flex flex-col md:flex-row items-center justify-between gap-6 py-2">
          {/* Machine A */}
          <div className="w-full md:w-5/12 p-5 rounded-xl bg-[#FAF8F5] border border-[#E8E4DA] relative">
            <div className="flex items-center gap-3.5 mb-3.5">
              <div className="w-10 h-10 rounded-lg bg-white border border-[#E8E4DA] flex items-center justify-center text-[#182230] shadow-sm">
                <Laptop className="w-5 h-5 text-[#1D4ED8]" />
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono tracking-wider px-2 py-0.5 rounded bg-white text-[#182230] border border-[#E8E4DA] font-semibold">
                  Machine A
                </span>
                <h4 className="font-semibold text-[#182230] text-sm mt-0.5">Examiner / Sender Node</h4>
              </div>
            </div>

            <div className="space-y-2 text-xs font-mono pt-3 border-t border-[#E8E4DA]">
              <div className="flex justify-between">
                <span className="text-[#64748B]">IPv4 Address:</span>
                <span className="text-[#1D4ED8] font-bold">{labHosts?.machine_a.ip || '192.168.1.6'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748B]">MAC Address:</span>
                <span className="text-[#182230]">{labHosts?.machine_a.mac || '1c:ce:51:32:87:5e'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748B]">Interface:</span>
                <span className="text-[#475569] truncate max-w-[150px]">{labHosts?.machine_a.interface || 'Wi-Fi'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748B]">Role:</span>
                <span className="text-[#16856A] font-semibold">Originates Echo Request</span>
              </div>
            </div>
          </div>

          {/* Ethernet LAN Switch / Interconnect Link */}
          <div className="flex flex-col items-center justify-center text-center px-4 py-2">
            <div className="flex items-center gap-2 mb-1.5">
              <span className="w-10 h-[2px] bg-[#C5A46D]" />
              <div className="w-9 h-9 rounded-full bg-[#FAF8F5] border border-[#C5A46D] flex items-center justify-center text-[#C5A46D] shadow-sm">
                <Network className="w-4 h-4" />
              </div>
              <span className="w-10 h-[2px] bg-[#C5A46D]" />
            </div>
            <span className="text-xs font-semibold text-[#182230]">Ethernet LAN Switch</span>
            <span className="text-[10px] font-mono text-[#64748B]">IEEE 802.3 Gigabit Link</span>
            <div className="mt-2 text-[10px] px-2.5 py-0.5 rounded-full bg-[#FAF8F5] text-[#182230] border border-[#E8E4DA] font-mono">
              Link Status: Active
            </div>
          </div>

          {/* Machine B */}
          <div className="w-full md:w-5/12 p-5 rounded-xl bg-[#FAF8F5] border border-[#E8E4DA] relative">
            <div className="flex items-center gap-3.5 mb-3.5">
              <div className="w-10 h-10 rounded-lg bg-white border border-[#E8E4DA] flex items-center justify-center text-[#182230] shadow-sm">
                <Server className="w-5 h-5 text-[#16856A]" />
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono tracking-wider px-2 py-0.5 rounded bg-white text-[#182230] border border-[#E8E4DA] font-semibold">
                  Machine B
                </span>
                <h4 className="font-semibold text-[#182230] text-sm mt-0.5">Target / Receiver Node</h4>
              </div>
            </div>

            <div className="space-y-2 text-xs font-mono pt-3 border-t border-[#E8E4DA]">
              <div className="flex justify-between">
                <span className="text-[#64748B]">IPv4 Address:</span>
                <span className="text-[#16856A] font-bold">{labHosts?.machine_b.ip || '192.168.1.1'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748B]">MAC Address:</span>
                <span className="text-[#182230]">{labHosts?.machine_b.mac || '00:0c:29:4d:5e:6f'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748B]">Services:</span>
                <span className="text-[#475569]">HTTP (80), HTTPS (443), FTP (21)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748B]">Role:</span>
                <span className="text-[#1D4ED8] font-semibold">Generates Echo Reply</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Ping Machine B Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Ping Controller (5 Cols) */}
        <div className="lg:col-span-5 luxury-card p-6 bg-white space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E8E4DA]">
            <div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">Live Probe</span>
              <h3 className="font-semibold text-sm text-[#182230]">Execute Ping Command</h3>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-[#FAF8F5] border border-[#E8E4DA] text-[#64748B] font-mono">
              RFC 792 Probe
            </span>
          </div>

          <form onSubmit={handlePing} className="space-y-3.5">
            <div>
              <label className="block text-xs font-semibold text-[#182230] mb-1.5">Target Host / Machine B IP</label>
              <input
                type="text"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                placeholder="e.g. 192.168.1.1 or 127.0.0.1"
                className="w-full px-3.5 py-2.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs font-mono text-[#182230] placeholder-slate-400 focus:border-[#C5A46D] focus:bg-white focus:outline-none"
              />
            </div>

            <div className="flex gap-3">
              <div className="flex-1">
                <label className="block text-xs font-semibold text-[#182230] mb-1.5">Probe Count</label>
                <select
                  value={packetCount}
                  onChange={(e) => setPacketCount(Number(e.target.value))}
                  className="w-full px-3 py-2.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs font-mono text-[#182230] focus:border-[#C5A46D] focus:bg-white focus:outline-none"
                >
                  <option value={4}>4 Packets (Standard RFC)</option>
                  <option value={8}>8 Packets</option>
                  <option value={10}>10 Packets</option>
                </select>
              </div>

              <div className="flex items-end">
                <button
                  type="submit"
                  disabled={pinging}
                  className="px-5 py-2.5 rounded-lg bg-[#1D4ED8] hover:bg-[#1E40AF] text-white font-semibold text-xs flex items-center gap-2 shadow-sm disabled:opacity-50 transition cursor-pointer"
                >
                  {pinging ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      Probing...
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5" />
                      Ping Target
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>

          {pingError && (
            <div className="p-3 rounded-lg bg-[#FDF2F2] border border-[#FDE8E8] text-xs text-[#C64747]">
              {pingError}
            </div>
          )}

          {/* Quick Target Chips */}
          <div className="pt-3 border-t border-[#E8E4DA]">
            <span className="text-[11px] text-[#64748B] block mb-2 font-medium">Quick Target Select:</span>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => setTargetIp(labHosts?.machine_b.ip || '192.168.1.1')}
                className="text-[10px] px-2.5 py-1 rounded-md bg-[#FAF8F5] hover:bg-white text-[#182230] font-mono border border-[#E8E4DA] transition shadow-xs cursor-pointer"
              >
                Machine B ({labHosts?.machine_b.ip || '192.168.1.1'})
              </button>
              <button
                type="button"
                onClick={() => setTargetIp('127.0.0.1')}
                className="text-[10px] px-2.5 py-1 rounded-md bg-[#FAF8F5] hover:bg-white text-[#182230] font-mono border border-[#E8E4DA] transition shadow-xs cursor-pointer"
              >
                Localhost (127.0.0.1)
              </button>
              <button
                type="button"
                onClick={() => setTargetIp('8.8.8.8')}
                className="text-[10px] px-2.5 py-1 rounded-md bg-[#FAF8F5] hover:bg-white text-[#182230] font-mono border border-[#E8E4DA] transition shadow-xs cursor-pointer"
              >
                Gateway DNS (8.8.8.8)
              </button>
            </div>
          </div>
        </div>

        {/* Ping Metrics & Results (7 Cols) */}
        <div className="lg:col-span-7 luxury-card p-6 bg-white flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#E8E4DA]">
              <div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">Telemetry</span>
                <h3 className="font-semibold text-sm text-[#182230]">Ping Latency & Response Metrics</h3>
              </div>
              {pingResult && (
                <span className={`text-[11px] px-2.5 py-0.5 rounded-full font-mono font-semibold flex items-center gap-1 ${
                  pingResult.status === 'SUCCESS' ? 'bg-[#F0FDF4] text-[#16856A] border border-[#DCFCE7]' : 'bg-[#FDF2F2] text-[#C64747] border border-[#FDE8E8]'
                }`}>
                  {pingResult.status === 'SUCCESS' ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                  {pingResult.status}
                </span>
              )}
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-4 gap-3 my-4">
              <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-center">
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block mb-1">Sent / Recv</span>
                <span className="font-mono text-sm font-bold text-[#182230]">
                  {pingResult ? `${pingResult.packets_sent} / ${pingResult.packets_received}` : '– / –'}
                </span>
              </div>
              <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-center">
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block mb-1">Packet Loss</span>
                <span className={`font-mono text-sm font-bold ${
                  (pingResult?.packet_loss_pct || 0) === 0 ? 'text-[#16856A]' : 'text-[#C64747]'
                }`}>
                  {pingResult ? `${pingResult.packet_loss_pct}%` : '–'}
                </span>
              </div>
              <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-center">
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block mb-1">Avg Latency</span>
                <span className="font-mono text-sm font-bold text-[#1D4ED8]">
                  {pingResult ? `${pingResult.avg_rtt_ms} ms` : '–'}
                </span>
              </div>
              <div className="p-3.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-center">
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block mb-1">RTT Range</span>
                <span className="font-mono text-sm font-bold text-[#7C3AED]">
                  {pingResult ? `${pingResult.min_rtt_ms}–${pingResult.max_rtt_ms} ms` : '–'}
                </span>
              </div>
            </div>

            {/* Subprocess Raw Output Box */}
            <div className="p-3.5 rounded-lg bg-[#111827] text-slate-200 border border-[#1E293B] font-mono text-[11px] max-h-36 overflow-y-auto leading-relaxed shadow-inner">
              <p className="text-slate-400 mb-1">$ ping {targetIp} -n {packetCount}</p>
              {pingResult?.raw_output ? (
                <pre className="whitespace-pre-wrap text-slate-300">{pingResult.raw_output}</pre>
              ) : (
                <p className="text-slate-500 italic">Run ping to observe raw ICMP Echo datagram exchange output...</p>
              )}
            </div>
          </div>

          {/* Action Link to Inspector */}
          <div className="pt-3 border-t border-[#E8E4DA] flex items-center justify-between">
            <span className="text-xs text-[#64748B]">
              Echo Requests & Replies recorded in active capture session
            </span>
            <button
              onClick={() => onNavigateToPackets('ICMP')}
              className="px-3.5 py-1.5 rounded-lg bg-white hover:bg-[#FAF8F5] text-[#16856A] border border-[#E8E4DA] text-xs font-semibold flex items-center gap-1.5 shadow-sm transition cursor-pointer"
            >
              Inspect ICMP Packets (Type 8 / Type 0)
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Local System Interfaces Table */}
      <div className="luxury-card p-6 bg-white space-y-4">
        <div>
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">Hardware</span>
          <h3 className="font-semibold text-sm text-[#182230]">Detected Network Adapters (Machine A)</h3>
          <p className="text-xs text-[#64748B] mt-0.5">Physical and virtual interfaces accessible via Npcap packet filter</p>
        </div>

        <div className="overflow-x-auto border border-[#E8E4DA] rounded-lg">
          <table className="w-full text-xs text-left">
            <thead className="luxury-table-header text-[#64748B] uppercase font-semibold text-[10px] tracking-wider">
              <tr>
                <th className="py-3 px-4">Adapter Name</th>
                <th className="py-3 px-4">Description</th>
                <th className="py-3 px-4">IPv4 Address</th>
                <th className="py-3 px-4">MAC Address</th>
                <th className="py-3 px-4">Speed</th>
                <th className="py-3 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#F1F5F9] font-mono text-[#182230]">
              {interfaces.map((iface, idx) => (
                <tr key={idx} className="hover:bg-[#FAF8F5] transition-colors">
                  <td className="py-3 px-4 font-semibold text-[#182230]">{iface.name}</td>
                  <td className="py-3 px-4 text-[#64748B] font-sans text-[11px] truncate max-w-xs">{iface.description}</td>
                  <td className="py-3 px-4 text-[#1D4ED8] font-bold">{iface.ipv4}</td>
                  <td className="py-3 px-4 text-[#475569]">{iface.mac}</td>
                  <td className="py-3 px-4 text-[#64748B] font-sans">{iface.speed}</td>
                  <td className="py-3 px-4 text-right">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold ${
                      iface.is_up ? 'bg-[#F0FDF4] text-[#16856A] border border-[#DCFCE7]' : 'bg-[#FAF8F5] text-slate-400 border border-[#E8E4DA]'
                    }`}>
                      {iface.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
