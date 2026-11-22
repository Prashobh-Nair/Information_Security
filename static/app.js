// NetSecure - Light-Themed Wireshark Telemetry & Security Lab (app.js)

let currentPackets = [];
let selectedPacket = null;
let activeProtocolFilter = 'ALL';
let currentLoginMode = 'HTTP';

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initLoginModeToggle();
  initForms();
  initFilters();
  loadSystemStatus();
  loadPackets();
});

// 1. Tab Navigation
function initTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      
      tab.classList.add('active');
      const targetId = tab.getAttribute('data-tab');
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add('active');

      if (targetId === 'tab-wireshark') {
        loadPackets();
      }
    });
  });
}

// 2. HTTP vs HTTPS Toggle
function initLoginModeToggle() {
  const btnHttp = document.getElementById('btn-mode-http');
  const btnHttps = document.getElementById('btn-mode-https');
  const banner = document.getElementById('protocol-banner');
  const submitBtn = document.getElementById('btn-submit-login');
  const statusBadge = document.getElementById('sniffer-status-badge');

  btnHttp.addEventListener('click', () => {
    currentLoginMode = 'HTTP';
    btnHttp.className = 'toggle-btn active-http';
    btnHttps.className = 'toggle-btn';
    banner.className = 'banner banner-danger';
    banner.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>
      <span><b>UNENCRYPTED HTTP:</b> Credentials will transmit across the LAN in plain ASCII text. Wireshark can intercept the password directly.</span>
    `;
    submitBtn.textContent = 'Submit Credentials via HTTP';
    submitBtn.className = 'btn btn-primary btn-block';
    statusBadge.textContent = 'VULNERABLE (HTTP)';
    statusBadge.className = 'badge badge-vulnerable';
  });

  btnHttps.addEventListener('click', () => {
    currentLoginMode = 'HTTPS';
    btnHttps.className = 'toggle-btn active-https';
    btnHttp.className = 'toggle-btn';
    banner.className = 'banner banner-success';
    banner.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      <span><b>ENCRYPTED HTTPS (TLS 1.3):</b> Credentials will be encrypted with AES-256-GCM. Passive sniffers in Wireshark see only opaque ciphertext.</span>
    `;
    submitBtn.textContent = 'Submit Credentials via HTTPS (Encrypted)';
    submitBtn.className = 'btn btn-primary btn-block';
    statusBadge.textContent = 'SECURE (TLS 1.3)';
    statusBadge.className = 'badge badge-success';
  });
}

// 3. Form Handlers
function initForms() {
  // Dummy Login Form
  const loginForm = document.getElementById('dummy-login-form');
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('input-username').value;
    const password = document.getElementById('input-password').value;

    try {
      const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, protocol: currentLoginMode })
      });
      const data = await res.json();
      displaySnifferResult(data);
      loadPackets(); // Refresh packets so Wireshark pane immediately has the new frame
    } catch (err) {
      alert('Login submission error: ' + err.message);
    }
  });

  // Ping Form
  const pingForm = document.getElementById('ping-form');
  pingForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target_ip = document.getElementById('ping-target-ip').value.trim();
    const count = parseInt(document.getElementById('ping-count-sel').value, 10);
    const consoleBox = document.getElementById('ping-console-output');

    consoleBox.textContent = `$ ping ${target_ip} -n ${count}\nTransmitting live ICMP Echo Requests...`;

    try {
      const res = await fetch('/api/ping', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_ip, count })
      });
      const data = await res.json();
      consoleBox.textContent = data.raw_console || 'Ping finished.';
      updatePingAnswers(data);
      loadPackets();
    } catch (err) {
      consoleBox.textContent = 'Ping error: ' + err.message;
    }
  });
}

// 4. Sniffer Result Presentation
function displaySnifferResult(data) {
  document.getElementById('sniffer-empty').classList.add('hidden');
  const resultBox = document.getElementById('sniffer-result');
  resultBox.classList.remove('hidden');

  const alertBox = document.getElementById('result-alert-box');
  const pwdText = document.getElementById('result-password-text');
  const wirePre = document.getElementById('result-wire-payload');
  const stage3Text = document.getElementById('stage-3-text');
  const stage3Item = document.getElementById('stage-3-alert');

  if (data.password_exposed) {
    alertBox.className = 'result-alert alert-danger';
    alertBox.querySelector('.label').textContent = 'INTERCEPTED CLEARTEXT PASSWORD:';
    pwdText.textContent = `"${data.exposed_password}"`;
    pwdText.style.color = 'var(--red)';
    wirePre.textContent = data.wire_payload;
    stage3Item.className = 'stage-item alert';
    stage3Text.innerHTML = `<b>Wireshark Passive Interception:</b> Password extracted in cleartext: <code>"${data.exposed_password}"</code> from unencrypted HTTP body.`;
  } else {
    alertBox.className = 'result-alert alert-success';
    alertBox.querySelector('.label').textContent = 'WIRE CONFIDENTIALITY STATUS:';
    pwdText.textContent = 'PROTECTED BY TLS 1.3 (AES-256-GCM)';
    pwdText.style.color = 'var(--green)';
    wirePre.textContent = `[Encrypted Ciphertext Block]\n${data.wire_payload}`;
    stage3Item.className = 'stage-item completed';
    stage3Text.innerHTML = `<b>TLS Cryptographic Protection:</b> Passive sniffers cannot decrypt payload without ephemeral Diffie-Hellman private session keys.`;
  }
}

// 5. Update 6 Fields in Ping View
function updatePingAnswers(data) {
  if (data.exercise_12_answers) {
    const a = data.exercise_12_answers;
    document.getElementById('ans-src-ip').textContent = a['1_source_ip'];
    document.getElementById('ans-dst-ip').textContent = a['2_destination_ip'];
    document.getElementById('ans-src-mac').textContent = a['4_source_mac'];
    document.getElementById('ans-dst-mac').textContent = a['5_destination_mac'];
    document.getElementById('node-b-mac').textContent = a['5_destination_mac'];
  }
}

// 6. Wireshark 3-Pane Packet Loader
async function loadPackets() {
  try {
    const query = activeProtocolFilter !== 'ALL' ? `?protocol=${activeProtocolFilter}` : '';
    const res = await fetch(`/api/packets${query}`);
    const data = await res.json();
    currentPackets = data.packets || [];
    renderPacketTable();
  } catch (err) {
    console.error('Failed to load packets:', err);
  }
}

function renderPacketTable() {
  const tbody = document.getElementById('packet-table-body');
  const search = document.getElementById('packet-search-input').value.toLowerCase().trim();
  tbody.innerHTML = '';

  const filtered = currentPackets.filter(p => {
    if (!search) return true;
    return (p.src_ip && p.src_ip.toLowerCase().includes(search)) ||
           (p.dst_ip && p.dst_ip.toLowerCase().includes(search)) ||
           (p.info && p.info.toLowerCase().includes(search)) ||
           (p.protocol && p.protocol.toLowerCase().includes(search));
  });

  document.getElementById('packet-count-lbl').textContent = `Showing ${filtered.length} packets`;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 24px; color: #94A3B8;">No packets match filter</td></tr>`;
    return;
  }

  filtered.forEach((pkt, index) => {
    const tr = document.createElement('tr');
    if (selectedPacket && selectedPacket.id === pkt.id) tr.classList.add('selected');
    if (pkt.has_leak) tr.classList.add('has-leak');

    tr.innerHTML = `
      <td style="text-align: center; color: #94A3B8; font-weight: 600;">${index + 1}</td>
      <td style="color: #64748B;">${pkt.timestamp || '00:00:00.000'}</td>
      <td style="color: #2563EB; font-weight: 600;">${pkt.src_ip}</td>
      <td style="font-weight: 600;">${pkt.dst_ip}</td>
      <td><span class="proto-tag ${getProtoTagClass(pkt.protocol)}">${pkt.protocol}</span></td>
      <td style="color: #64748B;">${pkt.length} B</td>
      <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;">
        ${pkt.has_leak ? '<span class="badge badge-vulnerable" style="margin-right: 4px;">LEAK</span>' : ''}
        ${pkt.info}
      </td>
    `;

    tr.addEventListener('click', () => {
      selectPacket(pkt);
      document.querySelectorAll('#packet-table-body tr').forEach(r => r.classList.remove('selected'));
      tr.classList.add('selected');
    });

    tbody.appendChild(tr);
  });

  if (!selectedPacket && filtered.length > 0) {
    selectPacket(filtered[0]);
  }
}

function selectPacket(pkt) {
  selectedPacket = pkt;
  document.getElementById('selected-pkt-badge').textContent = `Packet #${pkt.id || 1} [${pkt.protocol}]`;

  // Pane 2: OSI Layer Tree
  const layers = pkt.layers || {};
  document.getElementById('tree-frame').textContent = layers.frame || `Frame (${pkt.length} bytes on wire)`;
  document.getElementById('tree-ethernet').textContent = layers.ethernet || `Ethernet II, Src: ${pkt.src_mac || '1c:ce:51:32:87:5e'}, Dst: ${pkt.dst_mac || '70:b6:4f:1e:04:f1'}`;
  document.getElementById('tree-ip').textContent = layers.ip || `Internet Protocol Version 4, Src: ${pkt.src_ip}, Dst: ${pkt.dst_ip}`;
  
  const transNode = document.getElementById('tree-transport');
  if (layers.http) transNode.textContent = layers.http;
  else if (layers.tls) transNode.textContent = layers.tls;
  else if (layers.icmp) transNode.textContent = layers.icmp;
  else if (layers.dns) transNode.textContent = layers.dns;
  else if (layers.arp) transNode.textContent = layers.arp;
  else if (layers.ftp) transNode.textContent = layers.ftp;
  else transNode.textContent = pkt.info;

  // Pane 3: Hex Dump
  document.getElementById('hex-dump-pre').textContent = pkt.hex_dump || '0000  00 00 00 00 00 00 00 00 00 00';
}

function getProtoTagClass(proto) {
  switch ((proto || '').toUpperCase()) {
    case 'ICMP': return 'tag-cyan';
    case 'ARP': return 'tag-pink';
    case 'DNS': return 'tag-purple';
    case 'HTTP': return 'tag-orange';
    case 'HTTPS': return 'tag-green';
    case 'FTP': return 'tag-blue';
    default: return 'tag-cyan';
  }
}

// 7. Filter Pills & Search
function initFilters() {
  const pills = document.querySelectorAll('#filter-pills-container .pill');
  pills.forEach(pill => {
    pill.addEventListener('click', () => {
      pills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      activeProtocolFilter = pill.getAttribute('data-proto');
      loadPackets();
    });
  });

  const searchInput = document.getElementById('packet-search-input');
  searchInput.addEventListener('input', () => {
    renderPacketTable();
  });
}

// 8. Load Real Host Identity
async function loadSystemStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    if (data.machine_a) {
      document.getElementById('hdr-host-ip').textContent = data.machine_a.ip;
      document.getElementById('hdr-host-mac').textContent = data.machine_a.mac;
      document.getElementById('hdr-host-iface').textContent = data.machine_a.interface;

      document.getElementById('node-a-ip').textContent = data.machine_a.ip;
      document.getElementById('node-a-mac').textContent = data.machine_a.mac;
      document.getElementById('ans-src-ip').textContent = data.machine_a.ip;
      document.getElementById('ans-src-mac').textContent = data.machine_a.mac;
    }
    if (data.machine_b) {
      document.getElementById('node-b-ip').textContent = data.machine_b.ip;
      document.getElementById('node-b-mac').textContent = data.machine_b.mac;
      document.getElementById('ping-target-ip').value = data.machine_b.ip;
      document.getElementById('ans-dst-ip').textContent = data.machine_b.ip;
      document.getElementById('ans-dst-mac').textContent = data.machine_b.mac;
    }
  } catch (err) {
    console.error('Failed to load system status:', err);
  }
}
