import React from 'react';
import { 
  ShieldAlert, Activity, ArrowUpRight, CheckCircle2 
} from 'lucide-react';
import { 
  ResponsiveContainer, PieChart, Pie, Cell, 
  AreaChart, Area, XAxis, YAxis, Tooltip, Legend 
} from 'recharts';
import { DashboardStats } from '../api';

interface DashboardViewProps {
  stats: DashboardStats | null;
  onNavigate: (view: string) => void;
  onStartCapture?: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ stats, onNavigate }) => {
  const counts = stats?.counts || {
    TCP: 0, UDP: 0, ICMP: 0, HTTP: 0, HTTPS: 0, DNS: 0, ARP: 0, FTP: 0
  };

  const statCards = [
    { label: 'Total Packets', value: stats?.total_packets || 0, sub: 'All Network Layers', color: 'text-[#0F172A]' },
    { label: 'TCP Streams', value: counts.TCP || 0, sub: 'Layer 4 Transport', color: 'text-[#2563EB]' },
    { label: 'UDP Datagrams', value: counts.UDP || 0, sub: 'Layer 4 Stateless', color: 'text-[#4F46E5]' },
    { label: 'ICMP Echo / Control', value: counts.ICMP || 0, sub: 'Ping Lab Probes', color: 'text-[#059669]' },
    { label: 'HTTP Requests', value: counts.HTTP || 0, sub: 'Unencrypted Web', color: 'text-[#D97706]' },
    { label: 'HTTPS (TLS)', value: counts.HTTPS || 0, sub: 'Encrypted Sessions', color: 'text-[#0284C7]' },
    { label: 'DNS Lookups', value: counts.DNS || 0, sub: 'Name Resolutions', color: 'text-[#7C3AED]' },
    { label: 'ARP Frames', value: counts.ARP || 0, sub: 'Hardware Resolution', color: 'text-[#DB2777]' },
  ];

  const distribution = stats?.protocol_distribution && stats.protocol_distribution.length > 0 
    ? stats.protocol_distribution 
    : [
        { name: 'ICMP', value: 8, percentage: 30.8, color: '#059669' },
        { name: 'TCP', value: 5, percentage: 19.2, color: '#2563EB' },
        { name: 'HTTP', value: 3, percentage: 11.5, color: '#D97706' },
        { name: 'HTTPS', value: 3, percentage: 11.5, color: '#0284C7' },
        { name: 'FTP', value: 3, percentage: 11.5, color: '#DC2626' },
        { name: 'DNS', value: 2, percentage: 7.7, color: '#7C3AED' },
        { name: 'ARP', value: 2, percentage: 7.7, color: '#DB2777' },
      ];

  const timeline = stats?.traffic_timeline && stats.traffic_timeline.length > 0
    ? stats.traffic_timeline
    : [
        { time: '14:25:00', packets: 4, icmp: 2, http: 0, https: 1 },
        { time: '14:25:05', packets: 8, icmp: 4, http: 2, https: 0 },
        { time: '14:25:10', packets: 12, icmp: 2, http: 4, https: 2 },
        { time: '14:25:15', packets: 6, icmp: 0, http: 1, https: 3 },
      ];

  const alerts = stats?.security_summary?.total_alerts || 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#E2E8F0]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#0F172A]">
            Network Security Dashboard
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Real-time traffic and packet statistics across Machine A and Machine B.
          </p>
        </div>

        <button
          onClick={() => onNavigate('capture')}
          className="px-3.5 py-1.5 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-xs font-medium shadow-xs transition flex items-center gap-1.5 cursor-pointer self-start"
        >
          <Activity className="w-3.5 h-3.5" />
          View Live Packets
        </button>
      </div>

      {/* Advisory Banner */}
      {alerts > 0 ? (
        <div className="p-4 rounded-xl bg-white border border-[#E2E8F0] border-l-4 border-l-[#DC2626] shadow-xs flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#FEF2F2] flex items-center justify-center text-[#DC2626] shrink-0">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="font-semibold text-[#0F172A] text-xs">Security Alert: Unencrypted Credentials Detected</h4>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#FEF2F2] text-[#DC2626] font-semibold">
                  CWE-319
                </span>
              </div>
              <p className="text-[11px] text-[#64748B] mt-0.5">
                {stats?.security_summary?.credential_leaks || 1} cleartext password leak(s) captured in unencrypted HTTP traffic.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigate('security-demo')}
            className="px-3 py-1.5 rounded-lg bg-[#DC2626] hover:bg-[#B91C1C] text-white text-xs font-medium transition cursor-pointer"
          >
            Review Credentials
          </button>
        </div>
      ) : (
        <div className="p-3.5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-[#059669]" />
            <span className="text-xs text-[#0F172A] font-medium">All network interfaces normal. Live packet monitoring active.</span>
          </div>
          <button
            onClick={() => onNavigate('network')}
            className="text-xs text-[#2563EB] font-medium hover:underline flex items-center gap-1 cursor-pointer"
          >
            Ping Machine B <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* 8 Statistics Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        {statCards.map((c, i) => (
          <div key={i} className="p-4 rounded-xl bg-white border border-[#E2E8F0] shadow-xs flex flex-col justify-between">
            <div>
              <span className="text-[11px] font-medium text-[#64748B] block">
                {c.label}
              </span>
              <div className="mt-1.5 flex items-baseline justify-between">
                <span className={`text-xl font-bold font-sans tracking-tight ${c.color}`}>
                  {c.value.toLocaleString()}
                </span>
              </div>
            </div>
            <div className="mt-2 pt-2 border-t border-[#F1F5F9] text-[10px] text-[#94A3B8]">
              {c.sub}
            </div>
          </div>
        ))}
      </div>

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Traffic Timeline (7 Cols) */}
        <div className="lg:col-span-7 p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#F1F5F9]">
            <h3 className="font-semibold text-xs text-[#0F172A]">Traffic Volume Timeline</h3>
            <div className="flex items-center gap-3 text-[11px] text-[#64748B]">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#2563EB]" /> Total
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#059669]" /> ICMP
              </span>
            </div>
          </div>

          <div className="h-64 w-full pt-1">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="blueGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#2563EB" stopOpacity={0.12}/>
                    <stop offset="95%" stopColor="#2563EB" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="greenGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#059669" stopOpacity={0.12}/>
                    <stop offset="95%" stopColor="#059669" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#94A3B8" tick={{ fontSize: 10, fill: '#64748B' }} axisLine={{ stroke: '#E2E8F0' }} tickLine={false} />
                <YAxis stroke="#94A3B8" tick={{ fontSize: 10, fill: '#64748B' }} axisLine={{ stroke: '#E2E8F0' }} tickLine={false} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#FFFFFF', 
                    borderColor: '#E2E8F0', 
                    borderRadius: '8px',
                    fontSize: '11px',
                    color: '#0F172A'
                  }} 
                />
                <Area type="monotone" dataKey="packets" name="Total Packets" stroke="#2563EB" strokeWidth={2} fill="url(#blueGrad)" />
                <Area type="monotone" dataKey="icmp" name="ICMP Probes" stroke="#059669" strokeWidth={2} fill="url(#greenGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution Donut (5 Cols) */}
        <div className="lg:col-span-5 p-5 rounded-xl bg-white border border-[#E2E8F0] shadow-xs space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#F1F5F9]">
            <h3 className="font-semibold text-xs text-[#0F172A]">Protocol Distribution</h3>
            <span className="text-[10px] text-[#64748B] font-mono">Layers 3 & 4</span>
          </div>

          <div className="h-64 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={distribution} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2} dataKey="value">
                  {distribution.map((entry: any, index: number) => (
                    <Cell key={`cell-${index}`} fill={entry.color || '#2563EB'} stroke="#FFFFFF" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip 
                  formatter={(val: any, name: any, item: any) => [`${val} packets (${item.payload.percentage ?? 0}%)`, name]}
                  contentStyle={{ backgroundColor: '#FFFFFF', borderColor: '#E2E8F0', borderRadius: '8px', fontSize: '11px' }} 
                />
                <Legend layout="horizontal" verticalAlign="bottom" align="center" wrapperStyle={{ fontSize: '11px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
