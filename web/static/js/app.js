/**
 * macOS Advanced IP Scanner - Frontend Controller
 */

// Application State
const state = {
  interfaces: [],
  selectedIface: null,
  isScanning: false,
  hosts: new Map(), // ip -> host object
  activeFilter: 'all',
  searchQuery: '',
  sortField: 'ip',
  sortAsc: true,
  eventSource: null,
  activeModalHost: null,
  activePingInterval: null,
  settings: {
    timeoutMs: 350,
    concurrency: 50,
  }
};

// DOM Element Cache
const elements = {
  themeToggleBtn: document.getElementById('themeToggleBtn'),
  ifaceSelect: document.getElementById('ifaceSelect'),
  ipRangeInput: document.getElementById('ipRangeInput'),
  detectSubnetBtn: document.getElementById('detectSubnetBtn'),
  startScanBtn: document.getElementById('startScanBtn'),
  stopScanBtn: document.getElementById('stopScanBtn'),
  optScanPorts: document.getElementById('optScanPorts'),
  optDeepScan: document.getElementById('optDeepScan'),
  optResolveNames: document.getElementById('optResolveNames'),
  extraPortsInput: document.getElementById('extraPortsInput'),
  exportDropdownBtn: document.getElementById('exportDropdownBtn'),
  exportMenu: document.getElementById('exportMenu'),
  statScanned: document.getElementById('statScanned'),
  statAlive: document.getElementById('statAlive'),
  statTime: document.getElementById('statTime'),
  statGateway: document.getElementById('statGateway'),
  progressFill: document.getElementById('progressFill'),
  scannerStatusText: document.getElementById('scannerStatusText'),
  statusPulse: document.getElementById('statusPulse'),
  radarIcon: document.getElementById('radarIcon'),
  searchInput: document.getElementById('searchInput'),
  clearSearchBtn: document.getElementById('clearSearchBtn'),
  filterChips: document.getElementById('filterChips'),
  countAll: document.getElementById('countAll'),
  hostsTable: document.getElementById('hostsTable'),
  hostsTableBody: document.getElementById('hostsTableBody'),
  emptyStateRow: document.getElementById('emptyStateRow'),
  toastContainer: document.getElementById('toastContainer'),

  // Device Modal
  deviceModal: document.getElementById('deviceModal'),
  closeDeviceModalBtn: document.getElementById('closeDeviceModalBtn'),
  modalDeviceIcon: document.getElementById('modalDeviceIcon'),
  modalDeviceTitle: document.getElementById('modalDeviceTitle'),
  modalDeviceIP: document.getElementById('modalDeviceIP'),
  modalIP: document.getElementById('modalIP'),
  modalMAC: document.getElementById('modalMAC'),
  modalVendor: document.getElementById('modalVendor'),
  modalType: document.getElementById('modalType'),
  modalHostname: document.getElementById('modalHostname'),
  modalNetBIOS: document.getElementById('modalNetBIOS'),
  modalLatency: document.getElementById('modalLatency'),
  modalRole: document.getElementById('modalRole'),
  modalPortsList: document.getElementById('modalPortsList'),
  modalRescanPortsBtn: document.getElementById('modalRescanPortsBtn'),
  modalActionHttp: document.getElementById('modalActionHttp'),
  modalActionSSH: document.getElementById('modalActionSSH'),
  modalActionPing: document.getElementById('modalActionPing'),
  modalActionWOL: document.getElementById('modalActionWOL'),

  // Ping Modal
  pingModal: document.getElementById('pingModal'),
  closePingModalBtn: document.getElementById('closePingModalBtn'),
  pingTargetIP: document.getElementById('pingTargetIP'),
  pingSentCount: document.getElementById('pingSentCount'),
  pingSuccessCount: document.getElementById('pingSuccessCount'),
  pingAvgLatency: document.getElementById('pingAvgLatency'),
  pingLogTerminal: document.getElementById('pingLogTerminal'),
  togglePingTestBtn: document.getElementById('togglePingTestBtn'),

  // Settings Modal
  settingsModal: document.getElementById('settingsModal'),
  settingsModalBtn: document.getElementById('settingsModalBtn'),
  closeSettingsModalBtn: document.getElementById('closeSettingsModalBtn'),
  saveSettingsBtn: document.getElementById('saveSettingsBtn'),
  cfgTimeout: document.getElementById('cfgTimeout'),
  cfgConcurrency: document.getElementById('cfgConcurrency'),
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  fetchInterfaces();
  setupEventListeners();
  initEventSource();
});

// Theme Management
function initTheme() {
  const savedTheme = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);

  elements.themeToggleBtn.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const target = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', target);
    localStorage.setItem('theme', target);
    showToast(`Tema ${target === 'dark' ? 'Karanlık' : 'Aydınlık'} olarak ayarlandı`, 'info');
  });
}

// Fetch Local Interfaces
async function fetchInterfaces() {
  try {
    const res = await fetch('/api/interfaces');
    if (!res.ok) throw new Error('Arayüzler alınamadı');
    const ifaces = await res.json();
    state.interfaces = ifaces || [];

    elements.ifaceSelect.innerHTML = '';
    let defaultIface = null;

    state.interfaces.forEach((iface) => {
      const opt = document.createElement('option');
      opt.value = iface.name;
      opt.textContent = `${iface.name} - ${iface.ip} (${iface.cidr})`;
      elements.ifaceSelect.appendChild(opt);

      if (iface.isDefault) {
        defaultIface = iface;
      }
    });

    if (!defaultIface && state.interfaces.length > 0) {
      defaultIface = state.interfaces[0];
    }

    if (defaultIface) {
      elements.ifaceSelect.value = defaultIface.name;
      selectInterface(defaultIface);
    }
  } catch (err) {
    showToast('Ağ arayüzleri algılanamadı: ' + err.message, 'error');
  }
}

function selectInterface(iface) {
  state.selectedIface = iface;
  if (iface.startIp && iface.endIp) {
    elements.ipRangeInput.value = `${iface.startIp}-${iface.endIp}`;
  }
  if (iface.gatewayIp) {
    elements.statGateway.textContent = iface.gatewayIp;
  } else {
    elements.statGateway.textContent = '-';
  }
}

// Setup Event Listeners
function setupEventListeners() {
  // Interface selection changed
  elements.ifaceSelect.addEventListener('change', (e) => {
    const selected = state.interfaces.find(i => i.name === e.target.value);
    if (selected) selectInterface(selected);
  });

  // Auto-detect button
  elements.detectSubnetBtn.addEventListener('click', () => {
    if (state.selectedIface) {
      selectInterface(state.selectedIface);
      showToast(`Alt ağ ${state.selectedIface.startIp}-${state.selectedIface.endIp} olarak belirlendi`, 'info');
    }
  });

  // Start & Stop Scan
  elements.startScanBtn.addEventListener('click', startScan);
  elements.stopScanBtn.addEventListener('click', stopScan);

  // Search filter
  elements.searchInput.addEventListener('input', (e) => {
    state.searchQuery = e.target.value.toLowerCase().trim();
    elements.clearSearchBtn.classList.toggle('hidden', state.searchQuery === '');
    renderHostsTable();
  });

  elements.clearSearchBtn.addEventListener('click', () => {
    elements.searchInput.value = '';
    state.searchQuery = '';
    elements.clearSearchBtn.classList.add('hidden');
    renderHostsTable();
  });

  // Chips filter
  elements.filterChips.addEventListener('click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    elements.filterChips.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    state.activeFilter = chip.dataset.filter;
    renderHostsTable();
  });

  // Table Column Sorting
  elements.hostsTable.querySelectorAll('thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const field = th.dataset.sort;
      if (state.sortField === field) {
        state.sortAsc = !state.sortAsc;
      } else {
        state.sortField = field;
        state.sortAsc = true;
      }
      renderHostsTable();
    });
  });

  // Export Menu
  elements.exportDropdownBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    elements.exportMenu.classList.toggle('hidden');
  });

  document.addEventListener('click', () => {
    elements.exportMenu.classList.add('hidden');
  });

  elements.exportMenu.addEventListener('click', (e) => {
    const item = e.target.closest('.menu-item');
    if (!item) return;
    const format = item.dataset.format;
    window.location.href = `/api/export?format=${format}`;
    showToast(`${format.toUpperCase()} raporu indiriliyor...`, 'success');
  });

  // Modals Light-Dismiss & Close
  elements.closeDeviceModalBtn.addEventListener('click', () => elements.deviceModal.close());
  elements.deviceModal.addEventListener('click', (e) => {
    if (e.target === elements.deviceModal) elements.deviceModal.close();
  });

  elements.closePingModalBtn.addEventListener('click', closePingModal);
  elements.pingModal.addEventListener('click', (e) => {
    if (e.target === elements.pingModal) closePingModal();
  });

  // Settings Modal
  elements.settingsModalBtn.addEventListener('click', () => {
    elements.cfgTimeout.value = state.settings.timeoutMs;
    elements.cfgConcurrency.value = state.settings.concurrency;
    elements.settingsModal.showModal();
  });

  elements.closeSettingsModalBtn.addEventListener('click', () => elements.settingsModal.close());
  elements.settingsModal.addEventListener('click', (e) => {
    if (e.target === elements.settingsModal) elements.settingsModal.close();
  });

  elements.saveSettingsBtn.addEventListener('click', () => {
    state.settings.timeoutMs = parseInt(elements.cfgTimeout.value) || 350;
    state.settings.concurrency = parseInt(elements.cfgConcurrency.value) || 50;
    elements.settingsModal.close();
    showToast('Ayarlar kaydedildi', 'success');
  });

  // Modal Rescan Ports Button
  elements.modalRescanPortsBtn.addEventListener('click', async () => {
    if (!state.activeModalHost) return;
    elements.modalRescanPortsBtn.disabled = true;
    elements.modalPortsList.innerHTML = '<span class="text-muted">Portlar taranıyor...</span>';
    try {
      const res = await fetch('/api/action/ports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: state.activeModalHost.ip })
      });
      const data = await res.json();
      if (data.openPorts && data.openPorts.length > 0) {
        state.activeModalHost.openPorts = data.openPorts;
        state.hosts.set(state.activeModalHost.ip, state.activeModalHost);
        renderModalPorts(data.openPorts, state.activeModalHost.ip);
        renderHostsTable();
        showToast(`${data.openPorts.length} açık port bulundu`, 'success');
      } else {
        elements.modalPortsList.innerHTML = '<span class="text-muted">Açık port bulunamadı.</span>';
        showToast('Açık port bulunamadı', 'info');
      }
    } catch (err) {
      showToast('Port taraması başarısız: ' + err.message, 'error');
    } finally {
      elements.modalRescanPortsBtn.disabled = false;
    }
  });

  // Modal Actions
  elements.modalActionHttp.addEventListener('click', () => {
    if (!state.activeModalHost) return;
    const ip = state.activeModalHost.ip;
    window.open(`http://${ip}`, '_blank');
  });

  elements.modalActionSSH.addEventListener('click', () => {
    if (!state.activeModalHost) return;
    const ip = state.activeModalHost.ip;
    navigator.clipboard.writeText(`ssh ${ip}`);
    showToast(`SSH komutu kopyalandı: ssh ${ip}`, 'info');
  });

  elements.modalActionPing.addEventListener('click', () => {
    if (!state.activeModalHost) return;
    openPingModal(state.activeModalHost.ip);
  });

  elements.modalActionWOL.addEventListener('click', async () => {
    if (!state.activeModalHost || !state.activeModalHost.mac) {
      showToast('Cihazın MAC adresi bilinmiyor', 'warn');
      return;
    }
    try {
      const res = await fetch('/api/action/wol', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac: state.activeModalHost.mac })
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Wake-on-LAN paketi ${state.activeModalHost.mac} adresine gönderildi`, 'success');
      } else {
        showToast('WOL başarısız: ' + data.error, 'error');
      }
    } catch (err) {
      showToast('WOL hatası: ' + err.message, 'error');
    }
  });
}

// Setup Server-Sent Events (SSE)
function initEventSource() {
  if (state.eventSource) state.eventSource.close();

  const es = new EventSource('/api/scan/events');
  state.eventSource = es;

  es.addEventListener('initial_state', (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.hosts && data.hosts.length > 0) {
        data.hosts.forEach(h => state.hosts.set(h.ip, h));
        renderHostsTable();
      }
      if (data.isScanning) {
        setScanningUIState(true);
      }
    } catch (err) {
      console.error('Initial state error', err);
    }
  });

  es.addEventListener('progress', (e) => {
    try {
      const p = JSON.parse(e.data);
      updateProgressUI(p);
    } catch (err) {
      console.error('Progress error', err);
    }
  });

  es.addEventListener('host_found', (e) => {
    try {
      const host = JSON.parse(e.data);
      state.hosts.set(host.ip, host);
      renderHostsTable();
    } catch (err) {
      console.error('Host found error', err);
    }
  });

  es.addEventListener('finished', (e) => {
    try {
      const p = JSON.parse(e.data);
      setScanningUIState(false);
      updateProgressUI(p);
      showToast(`Tarama tamamlandı: ${p.aliveIps} aktif cihaz bulundu (${p.elapsedSec.toFixed(1)}s)`, 'success');
    } catch (err) {
      console.error('Finished error', err);
    }
  });

  es.onerror = () => {
    // SSE will automatically attempt reconnection
  };
}

// Scan API Operations
async function startScan() {
  const ipRange = elements.ipRangeInput.value.trim();
  if (!ipRange) {
    showToast('Lütfen geçerli bir IP aralığı girin', 'warn');
    return;
  }

  const payload = {
    ipRange: ipRange,
    timeoutMs: state.settings.timeoutMs,
    concurrency: state.settings.concurrency,
    scanPorts: elements.optScanPorts.checked,
    deepScan: elements.optDeepScan.checked,
    extraPorts: elements.extraPortsInput.value.trim(),
    resolveNames: elements.optResolveNames.checked,
  };

  try {
    // Reset table for clean scan
    state.hosts.clear();
    renderHostsTable();
    setScanningUIState(true);

    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(err);
    }

    showToast('Ağ taraması başlatıldı...', 'info');
  } catch (err) {
    setScanningUIState(false);
    showToast('Tarama başlatılamadı: ' + err.message, 'error');
  }
}

async function stopScan() {
  try {
    elements.stopScanBtn.disabled = true;
    const res = await fetch('/api/scan/stop', { method: 'POST' });
    if (res.ok) {
      setScanningUIState(false);
      showToast('Tarama kullanıcı tarafından durduruldu', 'info');
    }
  } catch (err) {
    showToast('Durdurma hatası: ' + err.message, 'error');
  }
}

function setScanningUIState(isScanning) {
  state.isScanning = isScanning;
  elements.startScanBtn.disabled = isScanning;
  elements.stopScanBtn.disabled = !isScanning;
  elements.ipRangeInput.disabled = isScanning;
  elements.ifaceSelect.disabled = isScanning;

  if (isScanning) {
    elements.radarIcon.classList.add('scanning');
    elements.statusPulse.className = 'pulse-dot scanning';
    elements.scannerStatusText.textContent = 'Taranıyor...';
  } else {
    elements.radarIcon.classList.remove('scanning');
    elements.statusPulse.className = 'pulse-dot idle';
    elements.scannerStatusText.textContent = 'Hazır';
  }
}

function updateProgressUI(p) {
  elements.statScanned.textContent = `${p.scannedIps} / ${p.totalIps}`;
  elements.statAlive.textContent = p.aliveIps;
  elements.statTime.textContent = `${p.elapsedSec.toFixed(1)}s`;
  elements.progressFill.style.width = `${p.percent.toFixed(1)}%`;
}

// Render Results Table
function renderHostsTable() {
  const hostsArray = Array.from(state.hosts.values());
  elements.countAll.textContent = hostsArray.length;

  // Filter hosts
  const filtered = hostsArray.filter(host => {
    // 1. Text Search Filter
    if (state.searchQuery) {
      const q = state.searchQuery;
      const matchIP = host.ip.includes(q);
      const matchMAC = (host.mac || '').toLowerCase().includes(q);
      const matchHost = (host.hostname || '').toLowerCase().includes(q);
      const matchVendor = (host.vendor || '').toLowerCase().includes(q);
      const matchPorts = (host.openPorts || []).some(p => p.port.toString().includes(q) || p.service.toLowerCase().includes(q));

      if (!matchIP && !matchMAC && !matchHost && !matchVendor && !matchPorts) {
        return false;
      }
    }

    // 2. Chip Filter
    switch (state.activeFilter) {
      case 'router':
        return host.isGateway || host.deviceType === 'Router / Gateway';
      case 'computer':
        return host.deviceType === 'Computer';
      case 'mobile':
        return host.deviceType === 'Mobile / Tablet';
      case 'apple':
        return (host.vendor || '').toLowerCase().includes('apple');
      case 'iot':
        return host.deviceType === 'Smart / IoT Device' || host.deviceType === 'Printer';
      case 'hasPorts':
        return host.openPorts && host.openPorts.length > 0;
      default:
        return true;
    }
  });

  // Sort hosts
  filtered.sort((a, b) => {
    let valA = a[state.sortField];
    let valB = b[state.sortField];

    if (state.sortField === 'ip') {
      return state.sortAsc ? compareIPs(a.ip, b.ip) : compareIPs(b.ip, a.ip);
    }
    if (state.sortField === 'ping') {
      valA = a.pingTimeMs || 0;
      valB = b.pingTimeMs || 0;
    }

    valA = (valA || '').toString().toLowerCase();
    valB = (valB || '').toString().toLowerCase();

    if (valA < valB) return state.sortAsc ? -1 : 1;
    if (valA > valB) return state.sortAsc ? 1 : -1;
    return 0;
  });

  // Update DOM Table
  elements.hostsTableBody.innerHTML = '';

  if (filtered.length === 0) {
    elements.emptyStateRow.style.display = '';
    elements.hostsTableBody.appendChild(elements.emptyStateRow);
    return;
  }

  elements.emptyStateRow.style.display = 'none';

  filtered.forEach(h => {
    const tr = document.createElement('tr');
    tr.className = 'host-row';
    tr.dataset.ip = h.ip;

    // Type icon
    const icon = getDeviceIcon(h.deviceType, h.vendor);

    // Latency badge class
    let latClass = 'latency-badge';
    if (h.pingTimeMs > 40) latClass += ' med';
    if (h.pingTimeMs > 120) latClass += ' slow';

    // Ports HTML
    let portsHTML = '<span class="text-muted">-</span>';
    if (h.openPorts && h.openPorts.length > 0) {
      portsHTML = `<div class="ports-cluster">` +
        h.openPorts.map(p => {
          let pillClass = 'port-pill';
          let clickAttr = '';
          if (p.port === 80 || p.port === 443 || p.port === 8080 || p.port === 8000 || p.port === 3000) {
            pillClass += ' web';
            const proto = (p.port === 443 || p.port === 8443) ? 'https' : 'http';
            clickAttr = `onclick="window.open('${proto}://${h.ip}:${p.port}', '_blank'); event.stopPropagation();" title="${p.service} (Tarayıcıda Aç)"`;
          } else if (p.port === 22 || p.port === 3389 || p.port === 5900) {
            pillClass += ' remote';
            clickAttr = `title="${p.service} Bağlantısı"`;
          }
          return `<span class="${pillClass}" ${clickAttr}>${p.port} ${p.service}</span>`;
        }).join('') +
        `</div>`;
    }

    // Role tags
    let roleTags = '';
    if (h.isGateway) {
      roleTags += `<span class="role-tag gw" title="Ağ Geçidi (Default Gateway)">GW</span>`;
    }
    if (h.isLocalHost) {
      roleTags += `<span class="role-tag me" title="Bu Bilgisayar (Bu Mac)">BU MAC</span>`;
    }

    tr.innerHTML = `
      <td class="col-status">
        <div class="status-cell">
          <span class="alive-dot" title="Aktif Cihaz"></span>
        </div>
      </td>
      <td class="col-type">
        <span class="type-badge">${icon} ${h.deviceType || 'Cihaz'}</span>
      </td>
      <td class="col-ip">
        <a class="ip-link" href="javascript:void(0)" onclick="copyText('${h.ip}', 'IP kopyalandı'); event.stopPropagation();" title="Tıkla ve IP'yi Kopyala">
          ${h.ip} ${roleTags}
        </a>
      </td>
      <td class="col-hostname">
        <span class="font-mono text-primary">${escapeHTML(h.hostname || h.netbios || '-')}</span>
      </td>
      <td class="col-mac">
        <span class="mac-val" onclick="copyText('${h.mac || ''}', 'MAC adresi kopyalandı'); event.stopPropagation();" title="Tıkla ve Kopyala">
          ${h.mac || '<span class="text-muted">-</span>'}
        </span>
      </td>
      <td class="col-vendor">
        <span class="vendor-text">${escapeHTML(h.vendor || 'Bilinmiyor')}</span>
      </td>
      <td class="col-ping">
        <span class="${latClass}">${h.pingTimeMs ? h.pingTimeMs.toFixed(1) + ' ms' : '<1 ms'}</span>
      </td>
      <td class="col-ports">${portsHTML}</td>
      <td class="col-actions">
        <div class="actions-cell">
          <button class="action-btn" title="Web Arayüzünü Aç (HTTP)" onclick="window.open('http://${h.ip}', '_blank'); event.stopPropagation();">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line></svg>
          </button>
          <button class="action-btn" title="SSH Komutunu Kopyala" onclick="copyText('ssh ${h.ip}', 'SSH komutu kopyalandı'); event.stopPropagation();">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
          </button>
          <button class="action-btn" title="Canlı Ping Testi" onclick="openPingModal('${h.ip}'); event.stopPropagation();">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
          </button>
          <button class="action-btn" title="Cihaz Detayları" onclick="openDeviceModal('${h.ip}'); event.stopPropagation();">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
          </button>
        </div>
      </td>
    `;

    tr.addEventListener('click', () => openDeviceModal(h.ip));
    elements.hostsTableBody.appendChild(tr);
  });
}

// Device Detail Modal Controller
function openDeviceModal(ip) {
  const host = state.hosts.get(ip);
  if (!host) return;

  state.activeModalHost = host;
  const icon = getDeviceIcon(host.deviceType, host.vendor);

  elements.modalDeviceIcon.textContent = icon;
  elements.modalDeviceTitle.textContent = host.hostname || host.vendor || 'Cihaz Detayları';
  elements.modalDeviceIP.textContent = host.ip;

  elements.modalIP.textContent = host.ip;
  elements.modalIP.onclick = () => copyText(host.ip, 'IP adresi kopyalandı');

  elements.modalMAC.textContent = host.mac || 'Bilinmiyor';
  elements.modalMAC.onclick = () => copyText(host.mac || '', 'MAC adresi kopyalandı');

  elements.modalVendor.textContent = host.vendor || 'Bilinmiyor';
  elements.modalType.textContent = host.deviceType || 'Cihaz';
  elements.modalHostname.textContent = host.hostname || '-';
  elements.modalNetBIOS.textContent = host.netbios || '-';
  elements.modalLatency.textContent = host.pingTimeMs ? `${host.pingTimeMs.toFixed(2)} ms` : '<1 ms';

  let roleStr = 'İstemci Cihaz';
  if (host.isGateway) roleStr = 'Ağ Geçidi / Modem / Router';
  if (host.isLocalHost) roleStr = 'Bu Bilgisayar (Yerel Mac)';
  elements.modalRole.textContent = roleStr;

  renderModalPorts(host.openPorts, host.ip);
  elements.deviceModal.showModal();
}

function renderModalPorts(ports, ip) {
  if (!ports || ports.length === 0) {
    elements.modalPortsList.innerHTML = '<span class="text-muted">Açık port tespit edilmedi. "Tüm Portları Tara" butonuyla derin tarama yapabilirsiniz.</span>';
    return;
  }

  elements.modalPortsList.innerHTML = ports.map(p => {
    let proto = (p.port === 443 || p.port === 8443) ? 'https' : 'http';
    let isWeb = (p.port === 80 || p.port === 443 || p.port === 8080 || p.port === 8000 || p.port === 3000);
    let clickAttr = isWeb ? `onclick="window.open('${proto}://${ip}:${p.port}', '_blank')"` : '';
    return `<span class="port-pill ${isWeb ? 'web' : ''}" ${clickAttr} title="${p.service}">${p.port} / ${p.service}</span>`;
  }).join('');
}

// Live Ping Modal Controller
function openPingModal(ip) {
  elements.pingTargetIP.textContent = ip;
  elements.pingSentCount.textContent = '0';
  elements.pingSuccessCount.textContent = '0';
  elements.pingAvgLatency.textContent = '0 ms';
  elements.pingLogTerminal.innerHTML = `<div class="terminal-line text-muted">${ip} için canlı ping başlatıldı...</div>`;

  elements.pingModal.showModal();

  let sent = 0;
  let success = 0;
  let totalLatency = 0;

  const runPing = async () => {
    sent++;
    elements.pingSentCount.textContent = sent;

    try {
      const res = await fetch('/api/action/ping', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();

      if (data.alive) {
        success++;
        totalLatency += data.latencyMs;
        const avg = (totalLatency / success).toFixed(1);
        elements.pingSuccessCount.textContent = success;
        elements.pingAvgLatency.textContent = `${avg} ms`;

        appendPingTerminal(`64 bayt ${ip} adresinden yanıt: süre=${data.latencyMs.toFixed(2)}ms`, 'text-emerald');
      } else {
        appendPingTerminal(`${ip} için istek zaman aşımına uğradı.`, 'text-rose');
      }
    } catch (err) {
      appendPingTerminal(`Ping hatası: ${err.message}`, 'text-rose');
    }
  };

  runPing();
  state.activePingInterval = setInterval(runPing, 1000);

  elements.togglePingTestBtn.textContent = 'Durdur';
  elements.togglePingTestBtn.onclick = () => {
    if (state.activePingInterval) {
      clearInterval(state.activePingInterval);
      state.activePingInterval = null;
      elements.togglePingTestBtn.textContent = 'Yeniden Başlat';
      appendPingTerminal('Ping testi durduruldu.', 'text-muted');
    } else {
      elements.togglePingTestBtn.textContent = 'Durdur';
      runPing();
      state.activePingInterval = setInterval(runPing, 1000);
    }
  };
}

function appendPingTerminal(text, colorClass = '') {
  const line = document.createElement('div');
  line.className = `terminal-line ${colorClass}`;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  elements.pingLogTerminal.appendChild(line);
  elements.pingLogTerminal.scrollTop = elements.pingLogTerminal.scrollHeight;
}

function closePingModal() {
  if (state.activePingInterval) {
    clearInterval(state.activePingInterval);
    state.activePingInterval = null;
  }
  elements.pingModal.close();
}

// Helpers
function getDeviceIcon(type, vendor) {
  vendor = (vendor || '').toLowerCase();
  if (type === 'Router / Gateway') return '🌐';
  if (type === 'Printer') return '🖨️';
  if (type === 'Mobile / Tablet') return '📱';
  if (type === 'Smart / IoT Device') return '💡';
  if (type === 'Server / NAS') return '🗄️';
  if (vendor.includes('apple')) return '🍎';
  return '💻';
}

function compareIPs(ipA, ipB) {
  const partsA = ipA.split('.').map(Number);
  const partsB = ipB.split('.').map(Number);
  for (let i = 0; i < 4; i++) {
    if (partsA[i] !== partsB[i]) return partsA[i] - partsB[i];
  }
  return 0;
}

function copyText(str, msg) {
  if (!str) return;
  navigator.clipboard.writeText(str);
  showToast(msg || 'Kopyalandı', 'success');
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  elements.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(12px) scale(0.96)';
    setTimeout(() => toast.remove(), 250);
  }, 3200);
}

function escapeHTML(str) {
  return (str || '').replace(/[&<>'"]/g, 
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag)
  );
}
