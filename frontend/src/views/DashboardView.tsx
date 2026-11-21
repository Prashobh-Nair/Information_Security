import React from 'react';
import { 
  ShieldAlert, Activity, Wifi, ArrowUpRight, 
  Lock, Unlock, Database, Cpu, ExternalLink, Play, CheckCircle2, TrendingUp
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
    { label: 'Total Packets', value: stats?.total_packets || 0, sub: 'All Network Layers', color: 'text-[#182230]', accent: 'border-t-2 border-[#182230]' },
    { label: 'TCP Streams', value: counts.TCP || 0, sub: 'Layer 4 Transport', color: 'text-[#1D4ED8]', accent: 'border-t-2 border-[#1D4ED8]' },
    { label: 'UDP Datagrams', value: counts.UDP || 0, sub: 'Layer 4 Stateless', color: 'text-[#4F46E5]', accent: 'border-t-2 border-[#4F46E5]' },
    { label: 'ICMP Echo / Control', value: counts.ICMP || 0, sub: 'Ping Lab Probes', color: 'text-[#16856A]', accent: 'border-t-2 border-[#16856A]' },
    { label: 'HTTP Requests', value: counts.HTTP || 0, sub: 'Unencrypted Web', color: 'text-[#C18A35]', accent: 'border-t-2 border-[#C18A35]' },
    { label: 'HTTPS (TLS)', value: counts.HTTPS || 0, sub: 'Encrypted Sessions', color: 'text-[#0284C7]', accent: 'border-t-2 border-[#0284C7]' },
    { label: 'DNS Lookups', value: counts.DNS || 0, sub: 'Name Resolutions', color: 'text-[#7C3AED]', accent: 'border-t-2 border-[#7C3AED]' },
    { label: 'ARP Frames', value: counts.ARP || 0, sub: 'Hardware Resolution', color: 'text-[#DB2777]', accent: 'border-t-2 border-[#DB2777]' },
  ];

  const distribution = stats?.protocol_distribution && stats.protocol_distribution.length > 0 
    ? stats.protocol_distribution 
    : [
        { name: 'ICMP', value: 8, percentage: 30.8, color: '#16856A' },
        { name: 'TCP', value: 5, percentage: 19.2, color: '#1D4ED8' },
        { name: 'HTTP', value: 3, percentage: 11.5, color: '#C18A35' },
        { name: 'HTTPS', value: 3, percentage: 11.5, color: '#0284C7' },
        { name: 'FTP', value: 3, percentage: 11.5, color: '#C64747' },
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
    <div className="space-y-7">
      {/* Editorial Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-2 border-b border-[#E8E4DA]">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold tracking-wider uppercase text-[#C5A46D]">
              Executive Overview
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-[11px] font-mono text-[#64748B]">Real-Time Diagnostics</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#182230] mt-1">
            Security Intelligence Dashboard
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Continuous packet inspection across Machine A and Machine B on the Ethernet LAN.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => onNavigate('capture')}
            className="px-4 py-2 rounded-lg bg-[#182230] hover:bg-[#111827] text-white text-xs font-medium shadow-sm transition flex items-center gap-2 cursor-pointer"
          >
            <Activity className="w-3.5 h-3.5 text-[#C5A46D]" />
            Inspect Live Packets
          </button>
        </div>
      </div>

      {/* Advisory Banner (Restrained luxury styling) */}
      {alerts > 0 ? (
        <div className="p-5 rounded-xl bg-white border border-[#E8E4DA] border-l-4 border-l-[#C64747] shadow-sm flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <div className="w-9 h-9 rounded-lg bg-[#FDF2F2] border border-[#FDE8E8] flex items-center justify-center text-[#C64747]">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="font-semibold text-[#182230] text-sm">Security Advisory: Cleartext Exposure Detected</h4>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#FDF2F2] text-[#C64747] font-semibold">
                  CWE-319
                </span>
              </div>
              <p className="text-xs text-[#64748B] mt-0.5">
                {stats?.security_summary?.credential_leaks || 0} plaintext credential leak(s) identified in unencrypted HTTP/FTP traffic streams on the local segment.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigate('security-demo')}
            className="px-4 py-2 rounded-lg bg-[#C64747] hover:bg-[#B91C1C] text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition cursor-pointer"
          >
            Review Exposed Credentials
            <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>
      ) : (
        <div className="p-4 rounded-xl bg-white border border-[#E8E4DA] shadow-sm flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <div className="w-8 h-8 rounded-lg bg-[#F0FDF4] border border-[#DCFCE7] flex items-center justify-center text-[#16856A]">
              <CheckCircle2 className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-semibold text-[#182230] text-xs">LAN Traffic Monitoring Operational</h4>
              <p className="text-[11px] text-[#64748B]">
                Interface telemetry and packet capture engine active with no unencrypted credential anomalies.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigate('network')}
            className="px-3.5 py-1.5 rounded-lg bg-white hover:bg-[#FAF8F5] text-[#1D4ED8] text-xs font-medium border border-[#E8E4DA] flex items-center gap-1.5 shadow-sm transition cursor-pointer"
          >
            Ping Machine B
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* 8 Statistics Cards (Stripe / Apple / Financial Analytics style) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {statCards.map((c, i) => (
          <div 
            key={i} 
            className={`luxury-card p-5 bg-white flex flex-col justify-between ${c.accent}`}
          >
            <div>
              <span className="text-[11px] uppercase tracking-wider font-semibold text-[#64748B] block">
                {c.label}
              </span>
              <div className="mt-2.5 flex items-baseline justify-between">
                <span className={`text-2xl font-bold font-sans tracking-tight ${c.color}`}>
                  {c.value.toLocaleString()}
                </span>
              </div>
            </div>
            <div className="mt-3 pt-2.5 border-t border-[#F1F5F9] flex items-center justify-between text-[11px] text-[#94A3B8]">
              <span>{c.sub}</span>
              <span className="font-mono text-[10px] text-slate-400">Recorded</span>
            </div>
          </div>
        ))}
      </div>

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Traffic Volume Timeline (7 Cols) */}
        <div className="lg:col-span-7 luxury-card p-6 bg-white space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E8E4DA]">
            <div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">Throughput</span>
              <h3 className="font-semibold text-sm text-[#182230]">Traffic Volume & Density Timeline</h3>
            </div>
            <div className="flex items-center gap-3 text-xs text-[#64748B]">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#1D4ED8]" />
                <span>Total Packets</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#16856A]" />
                <span>ICMP</span>
              </span>
            </div>
          </div>

          <div className="h-68 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="blueGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#1D4ED8" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#1D4ED8" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="greenGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#16856A" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#16856A" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <XAxis 
                  dataKey="time" 
                  stroke="#94A3B8" 
                  tick={{ fontSize: 11, fill: '#64748B' }} 
                  axisLine={{ stroke: '#E8E4DA' }}
                  tickLine={false}
                />
                <YAxis 
                  stroke="#94A3B8" 
                  tick={{ fontSize: 11, fill: '#64748B' }} 
                  axisLine={{ stroke: '#E8E4DA' }}
                  tickLine={false}
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#FFFFFF', 
                    borderColor: '#E8E4DA', 
                    borderRadius: '8px',
                    boxShadow: '0 4px 14px rgba(24, 34, 48, 0.08)',
                    fontSize: '11px',
                    color: '#182230'
                  }} 
                />
                <Area 
                  type="monotone" 
                  dataKey="packets" 
                  name="Total Packets" 
                  stroke="#1D4ED8" 
                  strokeWidth={2}
                  fillOpacity={1} 
                  fill="url(#blueGradient)" 
                />
                <Area 
                  type="monotone" 
                  dataKey="icmp" 
                  name="ICMP Probes" 
                  stroke="#16856A" 
                  strokeWidth={2}
                  fillOpacity={1} 
                  fill="url(#greenGradient)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution Donut (5 Cols) */}
        <div className="lg:col-span-5 luxury-card p-6 bg-white space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E8E4DA]">
            <div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">Composition</span>
              <h3 className="font-semibold text-sm text-[#182230]">Protocol Distribution</h3>
            </div>
            <span className="text-xs font-mono text-[#64748B]">Layer 3 & 4</span>
          </div>

          <div className="h-68 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={distribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {distribution.map((entry: any, index: number) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={entry.color || '#C5A46D'} 
                      stroke="#FFFFFF" 
                      strokeWidth={2}
                    />
                  ))}
                </Pie>
                <Tooltip 
                  formatter={(val: any, name: any, item: any) => [
                    `${val} packets (${item.payload.percentage ?? 0}%)`,
                    name
                  ]}
                  contentStyle={{ 
                    backgroundColor: '#FFFFFF', 
                    borderColor: '#E8E4DA', 
                    borderRadius: '8px',
                    boxShadow: '0 4px 14px rgba(24, 34, 48, 0.08)',
                    fontSize: '11px',
                    color: '#182230'
                  }} 
                />
                <Legend 
                  layout="horizontal" 
                  verticalAlign="bottom" 
                  align="center"
                  wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
