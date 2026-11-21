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
      {/* Clean Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-4 border-b border-[#E2E8F0]">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold tracking-wider uppercase text-[#2563EB]">
              Vulnerability Proof
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-[11px] font-mono text-[#64748B]">CWE-319 Cleartext Analysis</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[#0F172A] mt-1">
            HTTP vs. HTTPS Password Sniffing Demonstration
          </h1>
          <p className="text-xs text-[#64748B] mt-0.5">
            Empirical demonstration contrasting unencrypted HTTP POST interception with TLS 1.3 cryptographic protection.
          </p>
        </div>

        <div className="p-3 rounded-lg bg-white border border-[#E2E8F0] text-right font-mono text-xs shadow-xs shrink-0">
          <span className="text-[#64748B] block text-[10px] uppercase font-semibold">CVSS v3.1 Severity</span>
          <span className="text-[#DC2626] font-bold text-sm">CRITICAL 9.8</span>
          <span className="text-[#64748B] block text-[10px]">CWE-319 Cleartext Transmission</span>
        </div>
      </div>

      {/* Main Interactive Lab Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Dummy Login Portal Form (5 Cols) */}
        <div className="lg:col-span-5 clean-card p-6 bg-white space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E2E8F0]">
            <div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[#2563EB]">Target Portal</span>
              <h3 className="font-semibold text-sm text-[#0F172A]">Simulated University Login</h3>
            </div>
            
            {/* Protocol Mode Switcher */}
            <div className="flex items-center p-1 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs font-mono">
              <button
                type="button"
                onClick={() => setProtocolMode('HTTP')}
                className={`px-3 py-1 rounded font-bold transition flex items-center gap-1.5 cursor-pointer ${
                  protocolMode === 'HTTP'
                    ? 'bg-[#DC2626] text-white shadow-xs'
                    : 'text-[#64748B] hover:text-[#0F172A]'
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
                    ? 'bg-[#059669] text-white shadow-xs'
                    : 'text-[#64748B] hover:text-[#0F172A]'
                }`}
              >
                <Lock className="w-3 h-3" />
                HTTPS
              </button>
            </div>
          </div>

          {/* Protocol Warning Banner */}
          {protocolMode === 'HTTP' ? (
            <div className="p-3.5 rounded-lg bg-[#FEF2F2] border border-[#FEE2E2] text-xs text-[#DC2626] flex items-center gap-2.5">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span><b>UNENCRYPTED:</b> Form will transmit across Ethernet LAN in plaintext without TLS.</span>
            </div>
          ) : (
            <div className="p-3.5 rounded-lg bg-[#ECFDF5] border border-[#D1FAE5] text-xs text-[#059669] flex items-center gap-2.5">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              <span><b>ENCRYPTED:</b> Form will be sealed with TLS 1.3 AES-256-GCM session keys.</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-3.5 pt-1">
            <div>
              <label className="block text-xs font-semibold text-[#0F172A] mb-1.5">Dummy Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs text-[#0F172A] font-mono focus:border-[#2563EB] focus:bg-white focus:outline-none"
                required
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-[#0F172A] mb-1.5">Dummy Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3.5 py-2.5 pr-10 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-xs text-[#0F172A] font-mono focus:border-[#2563EB] focus:bg-white focus:outline-none"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2.5 text-[#64748B] hover:text-[#0F172A] cursor-pointer"
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
                    ? 'bg-[#DC2626] hover:bg-[#B91C1C] text-white'
                    : 'bg-[#059669] hover:bg-[#047857] text-white'
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
        <div className="lg:col-span-7 clean-card p-6 bg-white space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E2E8F0]">
            <div>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[#2563EB]">Wire Dissection</span>
              <h3 className="font-semibold text-sm text-[#0F172A]">5-Stage Sniffing & Cryptographic Analysis</h3>
            </div>
            {demoResult && (
              <span className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold border ${
                demoResult.password_exposed
                  ? 'bg-[#FEF2F2] text-[#DC2626] border-[#FEE2E2]'
                  : 'bg-[#ECFDF5] text-[#059669] border-[#D1FAE5]'
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
                      ? 'bg-[#FEF2F2] border-[#FEE2E2]'
                      : step.highlight && !demoResult.password_exposed
                      ? 'bg-[#ECFDF5] border-[#D1FAE5]'
                      : 'bg-[#F8FAFC] border-[#E2E8F0]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className={`w-5 h-5 rounded-full flex items-center justify-center font-bold text-[10px] ${
                        step.highlight && demoResult.password_exposed
                          ? 'bg-[#DC2626] text-white'
                          : step.highlight && !demoResult.password_exposed
                          ? 'bg-[#059669] text-white'
                          : 'bg-[#0F172A] text-white'
                      }`}>
                        {step.step}
                      </span>
                      <h4 className="font-semibold text-[#0F172A] text-xs">{step.title}</h4>
                    </div>
                    <span className="text-[10px] text-[#64748B]">{step.actor}</span>
                  </div>
                  <p className="text-[#475569] pl-7 text-[11px] leading-relaxed font-sans">{step.detail}</p>
                </div>
              ))}

              {/* Wire Evidence Callout */}
              <div className="mt-4 p-4 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] space-y-2">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[#0F172A] text-xs font-semibold flex items-center gap-1.5 font-sans">
                    <Terminal className="w-3.5 h-3.5 text-[#0F172A]" />
                    Wireshark / TShark Packet Interception Result:
                  </span>
                  <span className="text-[10px] text-[#64748B]">Payload Inspection</span>
                </div>

                {demoResult.password_exposed ? (
                  <div className="space-y-2">
                    <div className="p-3 rounded-lg bg-[#FEF2F2] border border-[#FEE2E2] text-[#DC2626]">
                      <span className="text-[10px] font-semibold uppercase block">Intercepted Cleartext Password:</span>
                      <span className="text-base font-bold text-[#DC2626] font-mono tracking-wider">
                        "{demoResult.exposed_password}"
                      </span>
                    </div>
                    <div className="text-[11px] text-[#475569]">
                      <b className="text-[#0F172A]">Raw Wire Payload:</b> <code className="text-[#DC2626] font-mono font-semibold">{demoResult.wire_payload}</code>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="p-3 rounded-lg bg-[#ECFDF5] border border-[#D1FAE5] text-[#059669]">
                      <span className="text-[10px] font-semibold uppercase block">Wire Confidentiality Status:</span>
                      <span className="text-sm font-bold text-[#059669] font-mono">
                        {demoResult.exposed_password}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#64748B]">
                      <b className="text-[#0F172A]">Encrypted Ciphertext Record:</b> <code className="text-[#2563EB] font-mono">{demoResult.wire_payload}</code>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="py-16 text-center text-[#64748B] font-sans">
              <KeyRound className="w-10 h-10 text-[#2563EB] mx-auto mb-2 opacity-30" />
              <p className="text-sm font-semibold text-[#0F172A]">Ready for Educational Submission</p>
              <p className="text-xs text-[#64748B] mt-1 max-w-sm mx-auto">
                Submit credentials using HTTP to observe cleartext interception, then switch to HTTPS to observe TLS cryptographic protection.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Comparison Matrix Table */}
      <div className="clean-card p-6 bg-white space-y-4">
        <div>
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[#2563EB]">Academic Evaluation</span>
          <h3 className="font-semibold text-sm text-[#0F172A]">HTTP vs. HTTPS Security Comparison Matrix</h3>
          <p className="text-xs text-[#64748B] mt-0.5">Formal evaluation matrix for university project defense</p>
        </div>

        <div className="overflow-x-auto border border-[#E2E8F0] rounded-lg">
          <table className="w-full text-xs text-left">
            <thead className="clean-table-header text-[#64748B] uppercase font-semibold text-[10px] tracking-wider">
              <tr>
                <th className="py-3 px-4">Evaluation Dimension</th>
                <th className="py-3 px-4 text-[#DC2626]">Unencrypted HTTP (RFC 2616)</th>
                <th className="py-3 px-4 text-[#059669]">Encrypted HTTPS (RFC 8446 - TLS 1.3)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] font-mono text-[#0F172A]">
              <tr className="hover:bg-[#F8FAFC] transition-colors">
                <td className="py-3 px-4 font-semibold text-[#0F172A] font-sans">Transport Port</td>
                <td className="py-3 px-4 text-[#DC2626]">TCP Port 80</td>
                <td className="py-3 px-4 text-[#059669]">TCP Port 443</td>
              </tr>
              <tr className="hover:bg-[#F8FAFC] transition-colors">
                <td className="py-3 px-4 font-semibold text-[#0F172A] font-sans">Wire Payload Visibility</td>
                <td className="py-3 px-4 text-[#DC2626] font-bold">100% Plaintext (ASCII / UTF-8)</td>
                <td className="py-3 px-4 text-[#059669] font-bold">Opaque Ciphertext (AES-256-GCM)</td>
              </tr>
              <tr className="hover:bg-[#F8FAFC] transition-colors">
                <td className="py-3 px-4 font-semibold text-[#0F172A] font-sans">Passive Sniffing Feasibility</td>
                <td className="py-3 px-4 text-[#DC2626] font-bold">TRIVIAL (No keys or decryption needed)</td>
                <td className="py-3 px-4 text-[#059669] font-bold">IMPOSSIBLE without private session keys</td>
              </tr>
              <tr className="hover:bg-[#F8FAFC] transition-colors">
                <td className="py-3 px-4 font-semibold text-[#0F172A] font-sans">Data Integrity Guarantee</td>
                <td className="py-3 px-4 text-[#64748B]">None (Tampering undetectable)</td>
                <td className="py-3 px-4 text-[#059669]">HMAC / Poly1305 Cryptographic Integrity</td>
              </tr>
              <tr className="hover:bg-[#F8FAFC] transition-colors">
                <td className="py-3 px-4 font-semibold text-[#0F172A] font-sans">Remediation</td>
                <td className="py-3 px-4 text-[#64748B]">Deprecate port 80 endpoints</td>
                <td className="py-3 px-4 text-[#059669]">Enforce HSTS with max-age=31536000</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
