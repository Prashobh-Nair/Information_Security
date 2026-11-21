import React, { useState, useEffect, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { DashboardView } from './views/DashboardView';
import { NetworkMonitorView } from './views/NetworkMonitorView';
import { LiveCaptureView } from './views/LiveCaptureView';
import { PacketDetailsView } from './views/PacketDetailsView';
import { ProtocolAnalysisView } from './views/ProtocolAnalysisView';
import { SecurityDemoView } from './views/SecurityDemoView';
import { ReportsView } from './views/ReportsView';
import { 
  getSystemStatus, getInterfaces, getLabHosts, 
  getPackets, getDashboardStats, getCaptureStatus,
  SystemStatus, NetworkInterface, LabHosts, PacketItem, DashboardStats
} from './api';

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<string>('dashboard');
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [labHosts, setLabHosts] = useState<LabHosts | null>(null);
  const [packets, setPackets] = useState<PacketItem[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<PacketItem | null>(null);
  const [selectedProtocol, setSelectedProtocol] = useState<string>('ALL');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isCapturing, setIsCapturing] = useState<boolean>(false);
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  const wsRef = useRef<WebSocket | null>(null);

  // Initialize data on mount
  useEffect(() => {
    refreshAllData();
    setupWebSocket();

    const interval = setInterval(() => {
      checkCaptureStatus();
    }, 3000);

    return () => {
      clearInterval(interval);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const setupWebSocket = () => {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/packets`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'packet' && msg.data) {
            setPackets((prev) => [msg.data, ...prev.slice(0, 999)]);
            fetchStats();
          }
        } catch (e) {
          console.error(e);
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        setTimeout(setupWebSocket, 3000);
      };

      ws.onerror = () => {
        setWsConnected(false);
      };
    } catch (e) {
      console.error('WebSocket connection error:', e);
    }
  };

  const refreshAllData = async () => {
    try {
      const [statusRes, ifacesRes, hostsRes, pktsRes, statsRes] = await Promise.all([
        getSystemStatus(),
        getInterfaces(),
        getLabHosts(),
        getPackets({ limit: 500 }),
        getDashboardStats(),
      ]);

      setSystemStatus(statusRes);
      setInterfaces(ifacesRes.interfaces);
      setLabHosts(hostsRes);
      setPackets(pktsRes.packets);
      setStats(statsRes);

      if (pktsRes.packets.length > 0 && !selectedPacket) {
        setSelectedPacket(pktsRes.packets[0]);
      }
    } catch (err) {
      console.error('Failed to load initial data:', err);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await getDashboardStats();
      setStats(res);
    } catch (err) {
      console.error(err);
    }
  };

  const checkCaptureStatus = async () => {
    try {
      const res = await getCaptureStatus();
      setIsCapturing(res.is_running);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSelectPacketForInspect = (packetNum: number) => {
    const found = packets.find(p => p.packet_num === packetNum);
    if (found) {
      setSelectedPacket(found);
      setCurrentView('inspector');
    }
  };

  const handleNavigateToPacketsWithFilter = (protocol?: string) => {
    if (protocol) {
      setSelectedProtocol(protocol);
    }
    setCurrentView('capture');
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#F5F2EA] text-[#182230]">
      {/* Enterprise Midnight Navy Sidebar */}
      <Sidebar 
        currentView={currentView}
        onViewChange={setCurrentView}
        packetCount={packets.length}
        alertCount={stats?.security_summary?.credential_leaks || 0}
      />

      {/* Main Workspace Layout (Warm Ivory & Pure White Content Surfaces) */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto bg-[#F5F2EA]">
        <Navbar 
          systemStatus={systemStatus}
          wsConnected={wsConnected}
          onNavigate={setCurrentView}
          onRefresh={refreshAllData}
        />

        <main className="flex-1 p-8 max-w-7xl w-full mx-auto space-y-6">
          {currentView === 'dashboard' && (
            <DashboardView 
              stats={stats}
              onNavigate={setCurrentView}
            />
          )}

          {currentView === 'network' && (
            <NetworkMonitorView 
              labHosts={labHosts}
              interfaces={interfaces}
              onRefresh={refreshAllData}
              onNavigateToPackets={handleNavigateToPacketsWithFilter}
            />
          )}

          {currentView === 'capture' && (
            <LiveCaptureView 
              packets={packets}
              interfaces={interfaces}
              isCapturing={isCapturing}
              selectedPacket={selectedPacket}
              onSelectPacket={(pkt) => {
                setSelectedPacket(pkt);
                setCurrentView('inspector');
              }}
              onRefresh={refreshAllData}
              selectedProtocol={selectedProtocol}
              onProtocolChange={setSelectedProtocol}
            />
          )}

          {currentView === 'inspector' && (
            <PacketDetailsView 
              packet={selectedPacket}
            />
          )}

          {currentView === 'protocols' && (
            <ProtocolAnalysisView 
              onSelectPacketForInspect={handleSelectPacketForInspect}
            />
          )}

          {currentView === 'security-demo' && (
            <SecurityDemoView 
              onRefresh={refreshAllData}
            />
          )}

          {currentView === 'reports' && (
            <ReportsView 
              stats={stats}
            />
          )}
        </main>
      </div>
    </div>
  );
};
export default App;
