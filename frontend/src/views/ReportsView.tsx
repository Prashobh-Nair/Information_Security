import React, { useState } from 'react';
import { 
  FileText, Download, CheckCircle2, ShieldAlert, 
  Users, BookOpen, ExternalLink, FileSpreadsheet, Sparkles
} from 'lucide-react';
import { getPdfReportUrl, getCsvReportUrl, getPcapExportUrl, DashboardStats } from '../api';

interface ReportsViewProps {
  stats: DashboardStats | null;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ stats }) => {
  const teamMembers = [
    { name: 'Student Lead', role: 'Machine A Operator (Traffic Capture & Analysis)' },
    { name: 'Team Member 2', role: 'Machine B Operator (Target Host Administration & Ping)' },
    { name: 'Team Member 3', role: 'HTTP vs. HTTPS Password Sniffing Demonstration' },
    { name: 'Team Member 4', role: 'Protocol Dissection (ICMP, ARP, DNS, FTP) & Documentation' },
  ];

  const milestones = [
    { title: 'LAN Ethernet Interconnection', desc: 'Direct Ethernet cable or lab switch connecting Machine A and Machine B.', status: 'Complete' },
    { title: 'ICMP Ping Probe (Machine A → B)', desc: 'Captured ICMP Echo Request (Type 8) and Echo Reply (Type 0).', status: 'Complete' },
    { title: 'Packet Layer Dissection', desc: 'Identified IP, MAC, transport ports, and ICMP meanings.', status: 'Complete' },
    { title: 'Multi-Protocol Traffic Analysis', desc: 'Dissected HTTP, HTTPS, DNS, ARP, and FTP packets.', status: 'Complete' },
    { title: 'HTTP Password Sniffing Proof', desc: 'Captured cleartext credentials in HTTP POST transaction.', status: 'Complete' },
    { title: 'Formal Report & PCAP Export', desc: 'Exportable academic PDF report and standard PCAP packet trace.', status: 'Complete' },
  ];

  return (
    <div className="space-y-6">
      {/* Clean Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-4 border-b border-[#E2E8F0]">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold tracking-wider uppercase text-[#2563EB]">
              Formal Documentation
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-[11px] font-mono text-[#64748B]">Exercise 12 Academic Deliverable</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[#0F172A] mt-1">
            Network Analysis Audit & Lab Guide
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Publication-ready documentation, executive report generation, and binary PCAP export.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5">
          <a
            href={getPdfReportUrl()}
            target="_blank"
            rel="noreferrer"
            className="px-4 py-2 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-xs font-semibold flex items-center gap-2 shadow-xs transition"
          >
            <Download className="w-3.5 h-3.5" />
            Download PDF Report
          </a>

          <a
            href={getCsvReportUrl()}
            download="netsecure_packets.csv"
            className="px-3.5 py-2 rounded-lg bg-white hover:bg-[#F8FAFC] text-[#0F172A] text-xs font-medium border border-[#E2E8F0] flex items-center gap-1.5 shadow-xs transition"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-[#059669]" />
            Export CSV
          </a>

          <a
            href={getPcapExportUrl()}
            download="netsecure_capture.pcap"
            className="px-3.5 py-2 rounded-lg bg-white hover:bg-[#F8FAFC] text-[#0F172A] text-xs font-medium border border-[#E2E8F0] flex items-center gap-1.5 shadow-xs transition"
          >
            <Download className="w-3.5 h-3.5 text-[#2563EB]" />
            Export PCAP
          </a>
        </div>
      </div>

      {/* Lab Project Team Roster (4 Members) */}
      <div className="clean-card p-6 bg-white space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#E2E8F0]">
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-[#2563EB]" />
            <h3 className="font-semibold text-sm text-[#0F172A]">Project Team Roster (Team of 4 Members)</h3>
          </div>
          <span className="text-[11px] font-mono text-[#64748B]">Information Security • Semester 5</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {teamMembers.map((member, i) => (
            <div key={i} className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] flex flex-col justify-between">
              <div>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-white text-[#2563EB] border border-[#E2E8F0] font-semibold">
                  Member #{i + 1}
                </span>
                <h4 className="font-semibold text-[#0F172A] text-sm mt-2">{member.name}</h4>
              </div>
              <p className="text-[11px] text-[#64748B] mt-2 leading-relaxed">{member.role}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Lab Objectives Verification Checklist */}
      <div className="clean-card p-6 bg-white space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#E2E8F0]">
          <div className="flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-[#059669]" />
            <h3 className="font-semibold text-sm text-[#0F172A]">Lab Exercise 12 Verification Matrix</h3>
          </div>
          <span className="text-[11px] font-mono text-[#059669] font-semibold">6 / 6 Milestones Completed</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {milestones.map((m, i) => (
            <div key={i} className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] flex items-start justify-between gap-3">
              <div>
                <h4 className="font-semibold text-[#0F172A] text-xs">{m.title}</h4>
                <p className="text-[11px] text-[#64748B] mt-1 leading-relaxed">{m.desc}</p>
              </div>
              <span className="px-2.5 py-0.5 rounded-full bg-[#ECFDF5] text-[#059669] text-[10px] font-mono font-semibold border border-[#D1FAE5] shrink-0">
                {m.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Report Sections Preview */}
      <div className="clean-card p-6 bg-white space-y-4">
        <h3 className="font-semibold text-sm text-[#0F172A]">Contents of the Exported PDF Audit Report</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-[#475569]">
            <b className="text-[#2563EB] block mb-1 font-sans">Section 1: Capture Metadata</b>
            Host IPs, MAC addresses, LAN subnet mask, timestamps, interface link speeds, and driver state.
          </div>
          <div className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-[#475569]">
            <b className="text-[#059669] block mb-1 font-sans">Section 2: ICMP Ping Correlation</b>
            Echo Request/Reply pairs with Type 8 / Type 0, RTT latency, sequence numbers, and packet loss.
          </div>
          <div className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-[#475569]">
            <b className="text-[#DC2626] block mb-1 font-sans">Section 3: Security Vulnerability Evidence</b>
            Wireshark/TShark packet body extraction proving cleartext password exposure & TLS recommendation.
          </div>
        </div>
      </div>
    </div>
  );
};
