import React, { useState } from 'react';
import { 
  KeyRound, ShieldAlert, ShieldCheck, Lock, Unlock, 
  ArrowRight, CheckCircle2, AlertTriangle, Eye, EyeOff, Terminal, Sparkles
} from 'lucide-react';
import { submitDummyLogin } from '../api';

export const SecurityDemoView: React.FC<{ onRefresh: () => void }> = ({ onRefresh }) => {
  const [protocolMode, setProtocolMode] = useState<'HTTP' | 'HTTPS'>('HTTP');
  const [username, setUsername] = useState('student_alex');
  const [password, setPassword] = useState('Secr3tLabP@ssw0rd!');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [demoResult, setDemoResult] = useState<any>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) return;

    try {
      setSubmitting(true);
      const res = await submitDummyLogin({
        username,
        password,
        protocol: protocolMode,
        source_ip: '192.168.1.6',
        target_ip: '192.168.1.1',
      });
      setDemoResult(res);
      onRefresh();
    } catch (err: any) {
      alert(err.message || 'Demo submission failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Editorial Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-2 border-b border-[#E8E4DA]">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold tracking-wider uppercase text-[#C5A46D]">
              Vulnerability Proof
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-[11px] font-mono text-[#64748B]">CWE-319 Cleartext Analysis</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-[#182230] mt-1">
            HTTP vs. HTTPS Password Sniffing Demonstration
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Empirical demonstration contrasting unencrypted HTTP POST interception with TLS 1.3 cryptographic protection.
          </p>
        </div>

        <div className="p-3 rounded-lg bg-white border border-[#E8E4DA] text-right font-mono text-xs shadow-xs shrink-0">
          <span className="text-[#64748B] block text-[10px] uppercase font-semibold">CVSS v3.1 Severity</span>
          <span className="text-[#C64747] font-bold text-sm">CRITICAL 9.8</span>
          <span className="text-[#64748B] block text-[10px]">CWE-319 Cleartext Transmission</span>
        </div>
      </div>

      {/* Main Interactive Lab Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Dummy Login Portal Form (5 Cols) */}
        <div className="lg:col-span-5 luxury-card p-6 bg-white space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E8E4DA]">
            <div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">Target Portal</span>
              <h3 className="font-semibold text-sm text-[#182230]">Simulated University Login</h3>
            </div>
            
            {/* Protocol Mode Switcher */}
            <div className="flex items-center p-1 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs font-mono">
              <button
                type="button"
                onClick={() => setProtocolMode('HTTP')}
                className={`px-3 py-1 rounded font-bold transition flex items-center gap-1.5 cursor-pointer ${
                  protocolMode === 'HTTP'
                    ? 'bg-[#C64747] text-white shadow-xs'
                    : 'text-[#64748B] hover:text-[#182230]'
                }`}
              >
                <Unlock className="w-3 h-3" />
                HTTP
              </button>
              <button
                type="button"
                onClick={() => setProtocolMode('HTTPS')}
                className={`px-3 py-1 rounded font-bold transition flex items-center gap-1.5 cursor-pointer ${
                  protocolMode === 'HTTPS'
                    ? 'bg-[#16856A] text-white shadow-xs'
                    : 'text-[#64748B] hover:text-[#182230]'
                }`}
              >
                <Lock className="w-3 h-3" />
                HTTPS
              </button>
            </div>
          </div>

          {/* Protocol Warning Banner */}
          {protocolMode === 'HTTP' ? (
            <div className="p-3.5 rounded-lg bg-[#FDF2F2] border border-[#FDE8E8] text-xs text-[#C64747] flex items-center gap-2.5">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span><b>UNENCRYPTED:</b> Form will transmit across Ethernet LAN in plaintext without TLS.</span>
            </div>
          ) : (
            <div className="p-3.5 rounded-lg bg-[#F0FDF4] border border-[#DCFCE7] text-xs text-[#16856A] flex items-center gap-2.5">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              <span><b>ENCRYPTED:</b> Form will be sealed with TLS 1.3 AES-256-GCM session keys.</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-3.5 pt-1">
            <div>
              <label className="block text-xs font-semibold text-[#182230] mb-1.5">Dummy Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs text-[#182230] font-mono focus:border-[#C5A46D] focus:bg-white focus:outline-none"
                required
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-[#182230] mb-1.5">Dummy Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3.5 py-2.5 pr-10 rounded-lg bg-[#FAF8F5] border border-[#E8E4DA] text-xs text-[#182230] font-mono focus:border-[#C5A46D] focus:bg-white focus:outline-none"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2.5 text-[#64748B] hover:text-[#182230] cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={submitting}
                className={`w-full py-2.5 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 shadow-sm transition cursor-pointer ${
                  protocolMode === 'HTTP'
                    ? 'bg-[#C64747] hover:bg-[#B91C1C] text-white'
                    : 'bg-[#16856A] hover:bg-[#13735B] text-white'
                }`}
              >
                {submitting ? 'Transmitting Over Wire...' : `Submit Credentials via ${protocolMode}`}
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </form>

          <p className="text-[11px] text-[#64748B] text-center pt-1">
            * Strictly for university academic laboratory demonstration. Never submit real personal passwords.
          </p>
        </div>

        {/* 5-Step Visual Flowchart & Sniffer Results (7 Cols) */}
        <div className="lg:col-span-7 luxury-card p-6 bg-white space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E8E4DA]">
            <div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">Wire Dissection</span>
              <h3 className="font-semibold text-sm text-[#182230]">5-Stage Sniffing & Cryptographic Analysis</h3>
            </div>
            {demoResult && (
              <span className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold border ${
                demoResult.password_exposed
                  ? 'bg-[#FDF2F2] text-[#C64747] border-[#FDE8E8]'
                  : 'bg-[#F0FDF4] text-[#16856A] border-[#DCFCE7]'
              }`}>
                {demoResult.security_status}
              </span>
            )}
          </div>

          {/* 5-Step Visual Flowchart */}
          {demoResult ? (
            <div className="space-y-3 font-mono text-xs">
              {demoResult.steps?.map((step: any) => (
                <div 
                  key={step.step}
                  className={`p-3.5 rounded-lg border transition ${
                    step.highlight && demoResult.password_exposed
                      ? 'bg-[#FDF2F2] border-[#FDE8E8]'
                      : step.highlight && !demoResult.password_exposed
                      ? 'bg-[#F0FDF4] border-[#DCFCE7]'
                      : 'bg-[#FAF8F5] border-[#E8E4DA]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className={`w-5 h-5 rounded-full flex items-center justify-center font-bold text-[10px] ${
                        step.highlight && demoResult.password_exposed
                          ? 'bg-[#C64747] text-white'
                          : step.highlight && !demoResult.password_exposed
                          ? 'bg-[#16856A] text-white'
                          : 'bg-[#182230] text-white'
                      }`}>
                        {step.step}
                      </span>
                      <h4 className="font-semibold text-[#182230] text-xs">{step.title}</h4>
                    </div>
                    <span className="text-[10px] text-[#64748B]">{step.actor}</span>
                  </div>
                  <p className="text-[#475569] pl-7 text-[11px] leading-relaxed font-sans">{step.detail}</p>
                </div>
              ))}

              {/* Wire Evidence Callout */}
              <div className="mt-4 p-4 rounded-xl bg-[#FAF8F5] border border-[#E8E4DA] space-y-2">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[#182230] text-xs font-semibold flex items-center gap-1.5 font-sans">
                    <Terminal className="w-3.5 h-3.5 text-[#182230]" />
                    Wireshark / TShark Packet Interception Result:
                  </span>
                  <span className="text-[10px] text-[#64748B]">Payload Inspection</span>
                </div>

                {demoResult.password_exposed ? (
                  <div className="space-y-2">
                    <div className="p-3 rounded-lg bg-[#FDF2F2] border border-[#FDE8E8] text-[#C64747]">
                      <span className="text-[10px] font-semibold uppercase block">Intercepted Cleartext Password:</span>
                      <span className="text-base font-bold text-[#C64747] font-mono tracking-wider">
                        "{demoResult.exposed_password}"
                      </span>
                    </div>
                    <div className="text-[11px] text-[#475569]">
                      <b className="text-[#182230]">Raw Wire Payload:</b> <code className="text-[#C64747] font-mono font-semibold">{demoResult.wire_payload}</code>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="p-3 rounded-lg bg-[#F0FDF4] border border-[#DCFCE7] text-[#16856A]">
                      <span className="text-[10px] font-semibold uppercase block">Wire Confidentiality Status:</span>
                      <span className="text-sm font-bold text-[#16856A] font-mono">
                        {demoResult.exposed_password}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#64748B]">
                      <b className="text-[#182230]">Encrypted Ciphertext Record:</b> <code className="text-[#0284C7] font-mono">{demoResult.wire_payload}</code>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="py-16 text-center text-[#64748B] font-sans">
              <KeyRound className="w-10 h-10 text-[#C5A46D] mx-auto mb-2 opacity-40" />
              <p className="text-sm font-semibold text-[#182230]">Ready for Educational Submission</p>
              <p className="text-xs text-[#64748B] mt-1 max-w-sm mx-auto">
                Submit credentials using HTTP to observe cleartext interception, then switch to HTTPS to observe TLS cryptographic protection.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Comparison Matrix Table */}
      <div className="luxury-card p-6 bg-white space-y-4">
        <div>
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[#C5A46D]">Academic Evaluation</span>
          <h3 className="font-semibold text-sm text-[#182230]">HTTP vs. HTTPS Security Comparison Matrix</h3>
          <p className="text-xs text-[#64748B] mt-0.5">Formal evaluation matrix for university project defense</p>
        </div>

        <div className="overflow-x-auto border border-[#E8E4DA] rounded-lg">
          <table className="w-full text-xs text-left">
            <thead className="luxury-table-header text-[#64748B] uppercase font-semibold text-[10px] tracking-wider">
              <tr>
                <th className="py-3 px-4">Evaluation Dimension</th>
                <th className="py-3 px-4 text-[#C64747]">Unencrypted HTTP (RFC 2616)</th>
                <th className="py-3 px-4 text-[#16856A]">Encrypted HTTPS (RFC 8446 - TLS 1.3)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#F1F5F9] font-mono text-[#182230]">
              <tr className="hover:bg-[#FAF8F5] transition-colors">
                <td className="py-3 px-4 font-semibold text-[#182230] font-sans">Transport Port</td>
                <td className="py-3 px-4 text-[#C64747]">TCP Port 80</td>
                <td className="py-3 px-4 text-[#16856A]">TCP Port 443</td>
              </tr>
              <tr className="hover:bg-[#FAF8F5] transition-colors">
                <td className="py-3 px-4 font-semibold text-[#182230] font-sans">Wire Payload Visibility</td>
                <td className="py-3 px-4 text-[#C64747] font-bold">100% Plaintext (ASCII / UTF-8)</td>
                <td className="py-3 px-4 text-[#16856A] font-bold">Opaque Ciphertext (AES-256-GCM)</td>
              </tr>
              <tr className="hover:bg-[#FAF8F5] transition-colors">
                <td className="py-3 px-4 font-semibold text-[#182230] font-sans">Passive Sniffing Feasibility</td>
                <td className="py-3 px-4 text-[#C64747] font-bold">TRIVIAL (No keys or decryption needed)</td>
                <td className="py-3 px-4 text-[#16856A] font-bold">IMPOSSIBLE without private session keys</td>
              </tr>
              <tr className="hover:bg-[#FAF8F5] transition-colors">
                <td className="py-3 px-4 font-semibold text-[#182230] font-sans">Data Integrity Guarantee</td>
                <td className="py-3 px-4 text-[#64748B]">None (Tampering undetectable)</td>
                <td className="py-3 px-4 text-[#16856A]">HMAC / Poly1305 Cryptographic Integrity</td>
              </tr>
              <tr className="hover:bg-[#FAF8F5] transition-colors">
                <td className="py-3 px-4 font-semibold text-[#182230] font-sans">Remediation</td>
                <td className="py-3 px-4 text-[#64748B]">Deprecate port 80 endpoints</td>
                <td className="py-3 px-4 text-[#16856A]">Enforce HSTS with max-age=31536000</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
