import React from 'react';
import { 
  LayoutDashboard, Network, Radio, Search, 
  Layers, KeyRound, FileSpreadsheet, Shield, ChevronRight
} from 'lucide-react';

interface SidebarProps {
  currentView: string;
  onViewChange: (view: string) => void;
  packetCount?: number;
  alertCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ 
  currentView, 
  onViewChange, 
  packetCount = 0,
  alertCount = 0 
}) => {
  const navItems = [
    {
      id: 'dashboard',
      label: 'Security Dashboard',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'network',
      label: 'Network & Ping Monitor',
      icon: Network,
      badge: 'Machine A⇄B',
    },
    {
      id: 'capture',
      label: 'Live Packet Capture',
      icon: Radio,
      badge: packetCount > 0 ? `${packetCount}` : null,
      badgeColor: 'bg-[#16856A]/20 text-[#16856A] border border-[#16856A]/30',
    },
    {
      id: 'inspector',
      label: 'Packet Inspector',
      icon: Search,
      badge: 'L2–L7 Hex',
    },
    {
      id: 'protocols',
      label: 'Protocol Analysis',
      icon: Layers,
      badge: 'ICMP/ARP/HTTP',
    },
    {
      id: 'security-demo',
      label: 'HTTP Password Sniffer',
      icon: KeyRound,
      badge: alertCount > 0 ? `${alertCount} Alert` : 'Demo',
      badgeColor: alertCount > 0 
        ? 'bg-[#C64747]/20 text-[#C64747] border border-[#C64747]/30' 
        : 'bg-[#C18A35]/20 text-[#C18A35] border border-[#C18A35]/30',
    },
    {
      id: 'reports',
      label: 'Reports & Lab Guide',
      icon: FileSpreadsheet,
      badge: 'PDF / CSV',
    },
  ];

  return (
    <aside className="w-68 border-r border-[#1E293B] bg-[#111827] flex flex-col justify-between p-5 shrink-0 text-slate-200 select-none sidebar-scroll">
      <div className="space-y-7">
        {/* Brand Header */}
        <div className="px-2 pt-1">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#1E293B] to-[#0F172A] border border-[#C5A46D]/40 flex items-center justify-center shadow-sm">
              <Shield className="w-5 h-5 text-[#C5A46D]" strokeWidth={2.2} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-base tracking-tight text-white">NETSECURE</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#1F2937] border border-[#C5A46D]/40 text-[#C5A46D]">
                  ENTERPRISE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-sans tracking-normal">
                Traffic & Security Analysis
              </p>
            </div>
          </div>
        </div>

        {/* Navigation List */}
        <div className="space-y-1.5">
          <p className="px-3 text-[11px] uppercase tracking-wider font-semibold text-slate-400 mb-2">
            Analysis Modules
          </p>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onViewChange(item.id)}
                className={`w-full group flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all duration-200 relative ${
                  isActive
                    ? 'bg-[#1F2937] text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-[#1E293B]/60'
                }`}
              >
                {/* Thin Champagne Gold Selected Indicator */}
                {isActive && (
                  <span className="absolute left-0 top-2 bottom-2 w-1 rounded-r bg-[#C5A46D]" />
                )}

                <div className="flex items-center gap-3">
                  <Icon 
                    className={`w-4 h-4 transition-colors ${
                      isActive ? 'text-[#C5A46D]' : 'text-slate-400 group-hover:text-slate-200'
                    }`} 
                    strokeWidth={1.8}
                  />
                  <span className={isActive ? 'font-semibold text-white' : 'font-normal'}>
                    {item.label}
                  </span>
                </div>

                {item.badge && (
                  <span className={`text-[10px] px-2 py-0.5 rounded-md font-mono ${
                    item.badgeColor || (isActive ? 'bg-[#111827] text-slate-300 border border-slate-700' : 'bg-[#1E293B] text-slate-400')
                  }`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Footer / Telemetry Badge */}
      <div className="pt-4 border-t border-[#1E293B] space-y-3 px-2">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#16856A]" />
            <span>LAN Monitoring</span>
          </span>
          <span className="font-mono text-slate-400">v2.4 Pro</span>
        </div>
        <div className="p-3 rounded-lg bg-[#0F172A] border border-[#1E293B] text-[11px] text-slate-400">
          <div className="text-white font-medium mb-0.5 flex items-center justify-between">
            <span>Academic Workstation</span>
            <span className="text-[10px] text-[#C5A46D] font-mono">Sem 5</span>
          </div>
          <p className="text-[10px] text-slate-400 leading-relaxed">
            Navrachana University • Lab #12
          </p>
        </div>
      </div>
    </aside>
  );
};
