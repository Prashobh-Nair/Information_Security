import React, { useState } from 'react';
import { 
  Network, Laptop, Server, Send, Play, CheckCircle2, 
  XCircle, ArrowRight, RefreshCw, Settings2
} from 'lucide-react';
import { 
  LabHosts, NetworkInterface, PingResult, executePing, 
  saveLabSettings 
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
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#E2E8F0]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#0F172A]">
            Network Topology & Ping Monitoring
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Machine A (Local Sender) and Machine B (Target Host) Ethernet LAN connectivity.
          </p>
        </div>

        <button
          onClick={() => setEditingSettings(!editingSettings)}
          className="px-3.5 py-1.5 rounded-lg bg-white hover:bg-[#F8FAFC] text-[#475569] text-xs font-medium border border-[#E2E8F0] shadow-xs transition flex items-center gap-1.5 cursor-pointer self-start"
        >
          <Settings2 className="w-3.5 h-3.5 text-[#64748B]" />
          {editingSettings ? 'Close Config' : 'Configure Machine IPs'}
        </button>
      </div>

      {/* Edit Modal */}
      {editingSettings && (
        <div className="p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-4">
          <h3 className="font-semibold text-xs text-[#0F172A]">Configure Lab Machine Addresses</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs text-[#64748B]">Machine A IP</label>
              <input
                type="text"
                value={machineAIp}
                onChange={(e) => setMachineAIp(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono text-[#0F172A] focus:outline-none focus:border-[#2563EB]"
              />
              <label className="text-xs text-[#64748B] pt-1 block">Machine A MAC</label>
              <input
                type="text"
                value={machineAMac}
                onChange={(e) => setMachineAMac(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono text-[#0F172A] focus:outline-none focus:border-[#2563EB]"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs text-[#64748B]">Machine B IP</label>
              <input
                type="text"
                value={machineBIp}
                onChange={(e) => {
                  setMachineBIp(e.target.value);
                  setTargetIp(e.target.value);
                }}
                className="w-full px-3 py-1.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono text-[#0F172A] focus:outline-none focus:border-[#2563EB]"
              />
              <label className="text-xs text-[#64748B] pt-1 block">Machine B MAC</label>
              <input
                type="text"
                value={machineBMac}
                onChange={(e) => setMachineBMac(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono text-[#0F172A] focus:outline-none focus:border-[#2563EB]"
              />
            </div>
          </div>
          <div className="flex justify-end pt-1">
            <button
              onClick={handleSaveSettings}
              className="px-4 py-1.5 rounded-lg bg-[#2563EB] text-white text-xs font-medium cursor-pointer"
            >
              Save Configuration
            </button>
          </div>
        </div>
      )}

      {/* Visual LAN Topology */}
      <div className="p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-4">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6 py-1">
          {/* Machine A */}
          <div className="w-full md:w-5/12 p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0]">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-lg bg-white border border-[#E2E8F0] flex items-center justify-center text-[#2563EB]">
                <Laptop className="w-4 h-4" />
              </div>
              <div>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-white border border-[#E2E8F0] text-[#0F172A]">
                  Machine A
                </span>
                <h4 className="font-semibold text-xs text-[#0F172A] mt-0.5">Sender / Examiner Host</h4>
              </div>
            </div>

            <div className="space-y-1.5 text-xs font-mono pt-2 border-t border-[#E2E8F0]">
              <div className="flex justify-between">
                <span className="text-[#64748B]">IPv4 Address:</span>
                <span className="text-[#2563EB] font-bold">{labHosts?.machine_a.ip || '192.168.1.6'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748B]">MAC Address:</span>
                <span className="text-[#0F172A]">{labHosts?.machine_a.mac || '1c:ce:51:32:87:5e'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748B]">Interface:</span>
                <span className="text-[#475569]">{labHosts?.machine_a.interface || 'Wi-Fi'}</span>
              </div>
            </div>
          </div>

          {/* Ethernet LAN Interconnect */}
          <div className="flex flex-col items-center justify-center text-center px-2">
            <div className="flex items-center gap-2 mb-1">
              <span className="w-8 h-[2px] bg-[#CBD5E1]" />
              <Network className="w-4 h-4 text-[#2563EB]" />
              <span className="w-8 h-[2px] bg-[#CBD5E1]" />
            </div>
            <span className="text-xs font-medium text-[#0F172A]">Ethernet LAN Switch</span>
            <span className="text-[10px] text-[#64748B] font-mono">1 Gbps • Subnet: /24</span>
          </div>

          {/* Machine B */}
          <div className="w-full md:w-5/12 p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0]">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-lg bg-white border border-[#E2E8F0] flex items-center justify-center text-[#059669]">
                <Server className="w-4 h-4" />
              </div>
              <div>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-white border border-[#E2E8F0] text-[#0F172A]">
                  Machine B
                </span>
                <h4 className="font-semibold text-xs text-[#0F172A] mt-0.5">Target / Receiver Host</h4>
              </div>
            </div>

            <div className="space-y-1.5 text-xs font-mono pt-2 border-t border-[#E2E8F0]">
              <div className="flex justify-between">
                <span className="text-[#64748B]">IPv4 Address:</span>
                <span className="text-[#059669] font-bold">{labHosts?.machine_b.ip || '192.168.1.1'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748B]">MAC Address:</span>
                <span className="text-[#0F172A]">{labHosts?.machine_b.mac || '00:0c:29:4d:5e:6f'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#64748B]">Role:</span>
                <span className="text-[#059669]">Generates Echo Reply</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Ping Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Ping Controller (5 Cols) */}
        <div className="lg:col-span-5 p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-4">
          <h3 className="font-semibold text-xs text-[#0F172A]">Execute Ping Command</h3>

          <form onSubmit={handlePing} className="space-y-3">
            <div>
              <label className="block text-xs text-[#64748B] mb-1">Target Host IP</label>
              <input
                type="text"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                placeholder="e.g. 192.168.1.1"
                className="w-full px-3 py-1.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono text-[#0F172A] focus:outline-none focus:border-[#2563EB]"
              />
            </div>

            <div className="flex gap-2.5">
              <div className="flex-1">
                <label className="block text-xs text-[#64748B] mb-1">Packet Count</label>
                <select
                  value={packetCount}
                  onChange={(e) => setPacketCount(Number(e.target.value))}
                  className="w-full px-3 py-1.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono text-[#0F172A] focus:outline-none focus:border-[#2563EB]"
                >
                  <option value={4}>4 Packets</option>
                  <option value={8}>8 Packets</option>
                  <option value={10}>10 Packets</option>
                </select>
              </div>

              <div className="flex items-end">
                <button
                  type="submit"
                  disabled={pinging}
                  className="px-4 py-1.5 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white font-medium text-xs flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                >
                  {pinging ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      Pinging...
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
            <div className="p-2.5 rounded-lg bg-[#FEF2F2] border border-[#FECACA] text-xs text-[#DC2626]">
              {pingError}
            </div>
          )}

          {/* Quick Targets */}
          <div className="pt-2 border-t border-[#F1F5F9] flex flex-wrap gap-1.5">
            <button
              type="button"
              onClick={() => setTargetIp(labHosts?.machine_b.ip || '192.168.1.1')}
              className="text-[11px] px-2 py-0.5 rounded bg-[#F8FAFC] border border-[#E2E8F0] text-[#475569] hover:bg-white cursor-pointer font-mono"
            >
              Machine B ({labHosts?.machine_b.ip || '192.168.1.1'})
            </button>
            <button
              type="button"
              onClick={() => setTargetIp('127.0.0.1')}
              className="text-[11px] px-2 py-0.5 rounded bg-[#F8FAFC] border border-[#E2E8F0] text-[#475569] hover:bg-white cursor-pointer font-mono"
            >
              127.0.0.1
            </button>
            <button
              type="button"
              onClick={() => setTargetIp('8.8.8.8')}
              className="text-[11px] px-2 py-0.5 rounded bg-[#F8FAFC] border border-[#E2E8F0] text-[#475569] hover:bg-white cursor-pointer font-mono"
            >
              8.8.8.8
            </button>
          </div>
        </div>

        {/* Ping Metrics (7 Cols) */}
        <div className="lg:col-span-7 p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs flex flex-col justify-between space-y-3">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-[#F1F5F9]">
              <h3 className="font-semibold text-xs text-[#0F172A]">Latency & Statistics</h3>
              {pingResult && (
                <span className={`text-[10px] px-2 py-0.2 rounded font-mono font-medium ${
                  pingResult.status === 'SUCCESS' ? 'bg-[#ECFDF5] text-[#059669]' : 'bg-[#FEF2F2] text-[#DC2626]'
                }`}>
                  {pingResult.status}
                </span>
              )}
            </div>

            <div className="grid grid-cols-4 gap-2.5 my-3">
              <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-center">
                <span className="text-[10px] text-[#64748B] block">Sent / Recv</span>
                <span className="font-mono text-xs font-bold text-[#0F172A]">
                  {pingResult ? `${pingResult.packets_sent} / ${pingResult.packets_received}` : '– / –'}
                </span>
              </div>
              <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-center">
                <span className="text-[10px] text-[#64748B] block">Loss</span>
                <span className={`font-mono text-xs font-bold ${
                  (pingResult?.packet_loss_pct || 0) === 0 ? 'text-[#059669]' : 'text-[#DC2626]'
                }`}>
                  {pingResult ? `${pingResult.packet_loss_pct}%` : '–'}
                </span>
              </div>
              <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-center">
                <span className="text-[10px] text-[#64748B] block">Avg RTT</span>
                <span className="font-mono text-xs font-bold text-[#2563EB]">
                  {pingResult ? `${pingResult.avg_rtt_ms} ms` : '–'}
                </span>
              </div>
              <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-center">
                <span className="text-[10px] text-[#64748B] block">Range</span>
                <span className="font-mono text-xs font-bold text-[#7C3AED]">
                  {pingResult ? `${pingResult.min_rtt_ms}–${pingResult.max_rtt_ms} ms` : '–'}
                </span>
              </div>
            </div>

            {/* Output Box */}
            <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] font-mono text-[11px] text-[#334155] max-h-32 overflow-y-auto">
              <p className="text-[#94A3B8] mb-1">$ ping {targetIp} -n {packetCount}</p>
              {pingResult?.raw_output ? (
                <pre className="whitespace-pre-wrap">{pingResult.raw_output}</pre>
              ) : (
                <p className="text-[#94A3B8] italic">Click Ping to test connectivity...</p>
              )}
            </div>
          </div>

          <div className="pt-2 border-t border-[#F1F5F9] flex justify-end">
            <button
              onClick={() => onNavigateToPackets('ICMP')}
              className="text-xs text-[#059669] font-medium hover:underline flex items-center gap-1 cursor-pointer"
            >
              Inspect ICMP Packets (Type 8 / Type 0) <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Network Adapters Table */}
      <div className="p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-3">
        <h3 className="font-semibold text-xs text-[#0F172A]">Available Network Adapters (Machine A)</h3>
        <div className="overflow-x-auto border border-[#E2E8F0] rounded-lg">
          <table className="w-full text-xs text-left">
            <thead className="bg-[#F8FAFC] text-[#64748B] uppercase font-semibold text-[10px] tracking-wider border-b border-[#E2E8F0]">
              <tr>
                <th className="py-2.5 px-3">Adapter Name</th>
                <th className="py-2.5 px-3">Description</th>
                <th className="py-2.5 px-3">IPv4 Address</th>
                <th className="py-2.5 px-3">MAC Address</th>
                <th className="py-2.5 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#F1F5F9] font-mono text-[#0F172A]">
              {interfaces.map((iface, idx) => (
                <tr key={idx} className="hover:bg-[#F8FAFC]">
                  <td className="py-2.5 px-3 font-medium text-[#0F172A]">{iface.name}</td>
                  <td className="py-2.5 px-3 text-[#64748B] font-sans truncate max-w-xs">{iface.description}</td>
                  <td className="py-2.5 px-3 text-[#2563EB]">{iface.ipv4}</td>
                  <td className="py-2.5 px-3 text-[#64748B]">{iface.mac}</td>
                  <td className="py-2.5 px-3 text-right">
                    <span className={`px-2 py-0.2 rounded text-[10px] ${
                      iface.is_up ? 'bg-[#ECFDF5] text-[#059669]' : 'bg-[#F1F5F9] text-[#94A3B8]'
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
