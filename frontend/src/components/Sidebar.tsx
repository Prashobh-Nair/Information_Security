import React from 'react';
import { 
  LayoutDashboard, Network, Radio, Search, 
  Layers, KeyRound, FileSpreadsheet, Shield
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
      badgeColor: 'bg-[#ECFDF5] text-[#059669] border border-[#A7F3D0]',
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
        ? 'bg-[#FEF2F2] text-[#DC2626] border border-[#FECACA]' 
        : 'bg-[#FFFBEB] text-[#D97706] border border-[#FDE68A]',
    },
    {
      id: 'reports',
      label: 'Reports & Lab Guide',
      icon: FileSpreadsheet,
      badge: 'PDF / CSV',
    },
  ];

  return (
    <aside className="w-64 border-r border-[#E2E8F0] bg-white flex flex-col justify-between p-4 shrink-0 text-[#0F172A] select-none">
      <div className="space-y-6">
        {/* Brand Header */}
        <div className="px-2 pt-1">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#2563EB] flex items-center justify-center text-white shadow-xs">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-semibold text-sm tracking-tight text-[#0F172A]">NetSecure</span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#F1F5F9] text-[#64748B] font-medium">
                  v1.0
                </span>
              </div>
              <p className="text-[11px] text-[#64748B]">
                Traffic & Security Analysis
              </p>
            </div>
          </div>
        </div>

        {/* Navigation List */}
        <div className="space-y-1">
          <p className="px-3 text-[10px] uppercase tracking-wider font-semibold text-[#94A3B8] mb-1.5">
            Modules
          </p>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onViewChange(item.id)}
                className={`w-full group flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                  isActive
                    ? 'bg-[#EFF6FF] text-[#2563EB] font-semibold'
                    : 'text-[#64748B] hover:text-[#0F172A] hover:bg-[#F8FAFC]'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon 
                    className={`w-4 h-4 ${isActive ? 'text-[#2563EB]' : 'text-[#64748B] group-hover:text-[#0F172A]'}`} 
                  />
                  <span>{item.label}</span>
                </div>

                {item.badge && (
                  <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                    item.badgeColor || (isActive ? 'bg-white text-[#2563EB] border border-[#BFDBFE]' : 'bg-[#F1F5F9] text-[#64748B]')
                  }`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Clean Footer Badge */}
      <div className="pt-3 border-t border-[#E2E8F0] space-y-2 px-2">
        <div className="flex items-center justify-between text-[11px] text-[#64748B]">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#059669]" />
            <span>LAN Monitoring</span>
          </span>
          <span className="font-mono text-[#94A3B8]">Semester 5</span>
        </div>
        <div className="p-2.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-[11px] text-[#64748B]">
          <div className="text-[#0F172A] font-medium text-xs mb-0.5">
            Navrachana University
          </div>
          <p className="text-[10px] text-[#64748B]">
            Information Security • Lab #12
          </p>
        </div>
      </div>
    </aside>
  );
};
