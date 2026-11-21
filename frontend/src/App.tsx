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
  const isCloudPreview = typeof window !== 'undefined' && 
    (window.location.hostname.includes('github.io') || window.location.protocol === 'file:');

  const [currentView, setCurrentView] = useState<string>('dashboard');
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [labHosts, setLabHosts] = useState<LabHosts | null>(null);
  const [packets, setPackets] = useState<PacketItem[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<PacketItem | null>(null);
  const [selectedProtocol, setSelectedProtocol] = useState<string>('ALL');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isCapturing, setIsCapturing] = useState<boolean>(false);
  const [wsConnected, setWsConnected] = useState<boolean>(isCloudPreview);

  const wsRef = useRef<WebSocket | null>(null);
  const simIntervalRef = useRef<any>(null);

  useEffect(() => {
    refreshAllData();

    if (!isCloudPreview) {
      setupWebSocket();
      const interval = setInterval(() => {
        checkCaptureStatus();
      }, 3000);

      return () => {
        clearInterval(interval);
        if (wsRef.current) wsRef.current.close();
      };
    } else {
      setWsConnected(true);
    }
  }, []);

  // Simulated live stream for Cloud Preview / GitHub Pages mode
  useEffect(() => {
    if (isCloudPreview && isCapturing) {
      let counter = packets.length + 1;
      simIntervalRef.current = setInterval(() => {
        const protocols = ['ICMP', 'HTTP', 'TCP', 'DNS', 'HTTPS', 'ARP'];
        const chosen = protocols[Math.floor(Math.random() * protocols.length)];
        const newPkt: PacketItem = {
          packet_num: counter++,
          timestamp: new Date().toLocaleTimeString() + '.' + Math.floor(Math.random() * 900 + 100),
          src_ip: '192.168.1.6',
          dst_ip: chosen === 'DNS' ? '8.8.8.8' : '192.168.1.1',
          src_mac: '1c:ce:51:32:87:5e',
          dst_mac: '00:0c:29:4d:5e:6f',
          protocol: chosen,
          length: Math.floor(Math.random() * 400 + 64),
          info: chosen === 'ICMP' 
            ? `Echo (ping) request  id=0x0001, seq=${counter}/256` 
            : chosen === 'HTTP' 
            ? 'GET /index.html HTTP/1.1 (Host: 192.168.1.1)' 
            : chosen === 'HTTPS'
            ? 'TLSv1.3 Application Data (Encrypted)'
            : chosen === 'DNS'
            ? 'Standard query 0x1a2b A gateway.netsecure'
            : 'TCP 52144 → 80 [ACK] Seq=102 Ack=204',
          l4_proto: chosen === 'DNS' ? 'UDP' : chosen === 'ICMP' ? 'ICMP' : 'TCP',
          src_port: chosen === 'HTTP' ? 52140 : chosen === 'HTTPS' ? 52144 : chosen === 'DNS' ? 53120 : null,
          dst_port: chosen === 'HTTP' ? 80 : chosen === 'HTTPS' ? 443 : chosen === 'DNS' ? 53 : null,
          icmp_type: chosen === 'ICMP' ? 8 : null,
          icmp_code: chosen === 'ICMP' ? 0 : null,
          icmp_meaning: chosen === 'ICMP' ? 'Echo Request (Ping Probe)' : '',
          payload_hex: '00 0c 29 4d 5e 6f 1c ce 51 32 87 5e 08 00 45 00 00 3c 1a 2b 00 00 80 01 7c 3b',
          payload_ascii: '..)M^o..Q2..E..<.+..|;',
          details: {
            ethernet: { src_mac: '1c:ce:51:32:87:5e', dst_mac: '00:0c:29:4d:5e:6f', ether_type: 'IPv4 (0x0800)' },
            network: { protocol: 'IPv4', src_ip: '192.168.1.6', dst_ip: chosen === 'DNS' ? '8.8.8.8' : '192.168.1.1', ttl: 128 },
            transport: { type: chosen === 'ICMP' ? 8 : undefined, code: chosen === 'ICMP' ? 0 : undefined }
          }
        };

        setPackets(prev => [newPkt, ...prev.slice(0, 499)]);
      }, 1800);

      return () => {
        if (simIntervalRef.current) clearInterval(simIntervalRef.current);
      };
    } else {
      if (simIntervalRef.current) clearInterval(simIntervalRef.current);
    }
  }, [isCloudPreview, isCapturing]);

  const setupWebSocket = () => {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/packets`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => setWsConnected(true);
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
      ws.onerror = () => setWsConnected(false);
    } catch (e) {
      console.error(e);
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
    <div className="flex h-screen w-screen overflow-hidden bg-[#F8FAFC] text-[#0F172A]">
      {/* Clean White Sidebar */}
      <Sidebar 
        currentView={currentView}
        onViewChange={setCurrentView}
        packetCount={packets.length}
        alertCount={stats?.security_summary?.credential_leaks || 1}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto bg-[#F8FAFC]">
        <Navbar 
          systemStatus={systemStatus}
          wsConnected={wsConnected}
          isCloudPreview={isCloudPreview}
          onNavigate={setCurrentView}
          onRefresh={refreshAllData}
        />

        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
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
