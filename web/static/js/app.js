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
  currentView: 'table', // 'table' | 'topology'
  eventSource: null,
  activeModalHost: null,
  activePingInterval: null,
  pingLatencyHistory: [],
  previousScanIPs: new Set(JSON.parse(localStorage.getItem('scanner_prev_ips') || '[]')),
  settings: {
    timeoutMs: 350,
    concurrency: 50,
  },
  topology: {
    panX: 0,
    panY: 0,
    isDragging: false,
    dragStartX: 0,
    dragStartY: 0,
    hoveredNode: null,
    animId: null,
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
  countNew: document.getElementById('countNew'),
  hostsTable: document.getElementById('hostsTable'),
  hostsTableBody: document.getElementById('hostsTableBody'),
  emptyStateRow: document.getElementById('emptyStateRow'),
  toastContainer: document.getElementById('toastContainer'),

  // View switchers
  viewTableBtn: document.getElementById('viewTableBtn'),
  viewTopologyBtn: document.getElementById('viewTopologyBtn'),
  tableViewContainer: document.getElementById('tableViewContainer'),
  topologyViewContainer: document.getElementById('topologyViewContainer'),
  topologyCanvas: document.getElementById('topologyCanvas'),
  resetTopologyBtn: document.getElementById('resetTopologyBtn'),
  topolAliveCount: document.getElementById('topolAliveCount'),

  // Device Modal
  deviceModal: document.getElementById('deviceModal'),
  closeDeviceModalBtn: document.getElementById('closeDeviceModalBtn'),
  modalDeviceIcon: document.getElementById('modalDeviceIcon'),
  modalDeviceTitle: document.getElementById('modalDeviceTitle'),
  modalDeviceIP: document.getElementById('modalDeviceIP'),
  modalIP: document.getElementById('modalIP'),
  modalMAC: document.getElementById('modalMAC'),
  modalVendor: document.getElementById('modalVendor'),
  modalModel: document.getElementById('modalModel'),
  modalType: document.getElementById('modalType'),
  modalHostname: document.getElementById('modalHostname'),
  modalNetBIOS: document.getElementById('modalNetBIOS'),
  modalLatency: document.getElementById('modalLatency'),
  modalRole: document.getElementById('modalRole'),
  modalAliasInput: document.getElementById('modalAliasInput'),
  modalNotesInput: document.getElementById('modalNotesInput'),
  saveAliasBtn: document.getElementById('saveAliasBtn'),
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
  pingMinLatency: document.getElementById('pingMinLatency'),
  pingMaxLatency: document.getElementById('pingMaxLatency'),
  pingCanvas: document.getElementById('pingCanvas'),
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
  initTopology();
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
    if (state.currentView === 'topology') renderTopology();
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
      opt.textContent = `${iface.name} - ${iface.ip} (${iface.cidr || ''})`;
      if (iface.isDefault) {
        opt.textContent += ' [Varsayılan]';
        defaultIface = iface;
      }
      elements.ifaceSelect.appendChild(opt);
    });

    if (defaultIface) {
      elements.ifaceSelect.value = defaultIface.name;
      selectInterface(defaultIface);
    } else if (state.interfaces.length > 0) {
      selectInterface(state.interfaces[0]);
    }
  } catch (err) {
    showToast('Ağ arayüzleri taranamadı: ' + err.message, 'error');
  }
}

function selectInterface(iface) {
  state.selectedIface = iface;
  if (iface.startIp && iface.endIp) {
    elements.ipRangeInput.value = `${iface.startIp}-${iface.endIp}`;
  } else if (iface.cidr) {
    elements.ipRangeInput.value = iface.cidr;
  }
  if (iface.gatewayIp) {
    elements.statGateway.textContent = iface.gatewayIp;
  }
}

// Setup Event Listeners
function setupEventListeners() {
  elements.ifaceSelect.addEventListener('change', (e) => {
    const iface = state.interfaces.find(i => i.name === e.target.value);
    if (iface) selectInterface(iface);
  });

  elements.detectSubnetBtn.addEventListener('click', () => {
    if (state.selectedIface) {
      selectInterface(state.selectedIface);
      showToast('Alt ağ aralığı yenilendi', 'info');
    }
  });

  elements.startScanBtn.addEventListener('click', startScan);
  elements.stopScanBtn.addEventListener('click', stopScan);

  // View Switcher (Table vs Topology)
  elements.viewTableBtn.addEventListener('click', () => switchView('table'));
  elements.viewTopologyBtn.addEventListener('click', () => switchView('topology'));

  // Export Dropdown
  elements.exportDropdownBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    elements.exportMenu.classList.toggle('hidden');
  });

  document.addEventListener('click', () => {
    elements.exportMenu.classList.add('hidden');
  });

  elements.exportMenu.querySelectorAll('.menu-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const format = btn.dataset.format;
      window.location.href = `/api/export?format=${format}`;
      showToast(`Rapor indiriliyor (.${format})`, 'info');
    });
  });

  // Search & Filter
  elements.searchInput.addEventListener('input', (e) => {
    state.searchQuery = e.target.value.trim().toLowerCase();
    elements.clearSearchBtn.classList.toggle('hidden', !state.searchQuery);
    renderHostsTable();
    if (state.currentView === 'topology') renderTopology();
  });

  elements.clearSearchBtn.addEventListener('click', () => {
    elements.searchInput.value = '';
    state.searchQuery = '';
    elements.clearSearchBtn.classList.add('hidden');
    renderHostsTable();
    if (state.currentView === 'topology') renderTopology();
  });

  elements.filterChips.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      elements.filterChips.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      state.activeFilter = chip.dataset.filter;
      renderHostsTable();
      if (state.currentView === 'topology') renderTopology();
    });
  });

  // Table Sorting
  elements.hostsTable.querySelectorAll('th[data-sort]').forEach(th => {
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

  // Modal Closers
  elements.closeDeviceModalBtn.addEventListener('click', () => elements.deviceModal.close());
  elements.deviceModal.addEventListener('click', (e) => {
    if (e.target === elements.deviceModal) elements.deviceModal.close();
  });

  elements.closePingModalBtn.addEventListener('click', closePingModal);
  elements.pingModal.addEventListener('click', (e) => {
    if (e.target === elements.pingModal) closePingModal();
  });

  // Save Custom Alias / Notes
  elements.saveAliasBtn.addEventListener('click', async () => {
    if (!state.activeModalHost) return;
    const host = state.activeModalHost;
    const alias = elements.modalAliasInput.value.trim();
    const notes = elements.modalNotesInput.value.trim();
    const targetID = host.mac || host.ip;

    try {
      const res = await fetch('/api/hosts/alias', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: targetID, alias, notes })
      });
      const data = await res.json();
      if (data.success) {
        host.customName = alias;
        host.comments = notes;
        state.hosts.set(host.ip, host);
        renderHostsTable();
        if (state.currentView === 'topology') renderTopology();
        showToast('Cihaz tanımı başarıyla kaydedildi', 'success');
      }
    } catch (err) {
      showToast('Kaydetme hatası: ' + err.message, 'error');
    }
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

  // Modal Quick Actions
  elements.modalActionHttp.addEventListener('click', () => {
    if (!state.activeModalHost) return;
    window.open(`http://${state.activeModalHost.ip}`, '_blank');
  });

  elements.modalActionSSH.addEventListener('click', () => {
    if (!state.activeModalHost) return;
    copyText(`ssh ${state.activeModalHost.ip}`, `SSH komutu kopyalandı: ssh ${state.activeModalHost.ip}`);
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

// Switch between Table and Topology view
function switchView(view) {
  state.currentView = view;
  if (view === 'table') {
    elements.viewTableBtn.classList.add('active');
    elements.viewTopologyBtn.classList.remove('active');
    elements.tableViewContainer.classList.remove('hidden');
    elements.topologyViewContainer.classList.add('hidden');
  } else {
    elements.viewTableBtn.classList.remove('active');
    elements.viewTopologyBtn.classList.add('active');
    elements.tableViewContainer.classList.add('hidden');
    elements.topologyViewContainer.classList.remove('hidden');
    renderTopology();
  }
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
        data.hosts.forEach(h => {
          checkIfNewDevice(h);
          state.hosts.set(h.ip, h);
        });
        renderHostsTable();
        if (state.currentView === 'topology') renderTopology();
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
      checkIfNewDevice(host);
      state.hosts.set(host.ip, host);
      renderHostsTable();
      if (state.currentView === 'topology') renderTopology();
    } catch (err) {
      console.error('Host found error', err);
    }
  });

  es.addEventListener('alias_updated', (e) => {
    try {
      const item = JSON.parse(e.data);
      state.hosts.forEach(h => {
        if (h.ip === item.id || h.mac === item.id) {
          h.customName = item.alias;
          h.comments = item.notes;
        }
      });
      renderHostsTable();
      if (state.currentView === 'topology') renderTopology();
    } catch (err) {
      console.error('Alias updated error', err);
    }
  });

  es.addEventListener('finished', (e) => {
    try {
      const p = JSON.parse(e.data);
      setScanningUIState(false);
      updateProgressUI(p);
      showToast(`Tarama tamamlandı: ${p.aliveIps} aktif cihaz bulundu (${p.elapsedSec.toFixed(1)}s)`, 'success');

      // Save scanned IPs for next scan diffing
      const currentAlive = Array.from(state.hosts.keys());
      if (currentAlive.length > 0) {
        localStorage.setItem('scanner_prev_ips', JSON.stringify(currentAlive));
      }

      // Sync all discovered hosts from backend on completion
      fetch('/api/scan/status')
        .then(res => res.json())
        .then(data => {
          const list = Array.isArray(data) ? data : (data.hosts || []);
          if (list && list.length > 0) {
            list.forEach(h => {
              checkIfNewDevice(h);
              state.hosts.set(h.ip, h);
            });
            renderHostsTable();
            if (state.currentView === 'topology') renderTopology();
          }
        })
        .catch(() => {});
    } catch (err) {
      console.error('Finished error', err);
    }
  });
}

function checkIfNewDevice(host) {
  if (state.previousScanIPs.size > 0 && !state.previousScanIPs.has(host.ip)) {
    host.isNew = true;
  }
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
  elements.ifaceSelect.disabled = isScanning;
  elements.ipRangeInput.disabled = isScanning;

  if (isScanning) {
    elements.radarIcon.classList.add('scanning');
    elements.statusPulse.className = 'pulse-dot scanning';
    elements.scannerStatusText.textContent = 'Taranıyor...';
    elements.progressTrack.classList.add('active');
  } else {
    elements.radarIcon.classList.remove('scanning');
    elements.statusPulse.className = 'pulse-dot idle';
    elements.scannerStatusText.textContent = 'Tamamlandı / Hazır';
    elements.progressTrack.classList.remove('active');
  }
}

function updateProgressUI(p) {
  elements.statScanned.textContent = `${p.scannedIps} / ${p.totalIps}`;
  elements.statAlive.textContent = p.aliveIps;
  elements.statTime.textContent = `${p.elapsedSec.toFixed(1)}s`;
  elements.progressFill.style.width = `${p.percent.toFixed(1)}%`;
  elements.countAll.textContent = p.aliveIps;
}

// Render Table with Search & Filters
function renderHostsTable() {
  const hosts = Array.from(state.hosts.values());
  elements.countAll.textContent = hosts.length;

  let newCount = 0;
  hosts.forEach(h => { if (h.isNew) newCount++; });
  if (elements.countNew) elements.countNew.textContent = newCount;
  if (elements.topolAliveCount) elements.topolAliveCount.textContent = hosts.length;

  // Filter hosts
  const filtered = hosts.filter(host => {
    if (state.searchQuery) {
      const q = state.searchQuery;
      const match =
        (host.ip || '').toLowerCase().includes(q) ||
        (host.hostname || '').toLowerCase().includes(q) ||
        (host.customName || '').toLowerCase().includes(q) ||
        (host.model || '').toLowerCase().includes(q) ||
        (host.mac || '').toLowerCase().includes(q) ||
        (host.vendor || '').toLowerCase().includes(q) ||
        (host.deviceType || '').toLowerCase().includes(q) ||
        (host.comments || '').toLowerCase().includes(q) ||
        (host.openPorts || []).some(p => p.port.toString().includes(q) || p.service.toLowerCase().includes(q));
      if (!match) return false;
    }

    switch (state.activeFilter) {
      case 'new':
        return !!host.isNew;
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

    const icon = getDeviceIcon(h.deviceType, h.vendor, h.model);

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
            clickAttr = `title="${p.service} (${p.banner || 'Açık Port'})"`;
          }
          const bannerText = p.banner ? ` (${p.banner.slice(0, 15)})` : '';
          return `<span class="${pillClass}" ${clickAttr}>${p.port} ${p.service}${bannerText}</span>`;
        }).join('') +
        `</div>`;
    }

    // Role tags & New badge
    let roleTags = '';
    if (h.isGateway) roleTags += `<span class="role-tag gw" title="Ağ Geçidi">GW</span>`;
    if (h.isLocalHost) roleTags += `<span class="role-tag me" title="Bu Bilgisayar">BU MAC</span>`;
    if (h.isNew) roleTags += `<span class="badge-new">YENİ</span>`;

    // Hostname / Alias / Model
    let nameHTML = '';
    if (h.customName) {
      nameHTML += `<span class="custom-name-text">🏷️ ${escapeHTML(h.customName)}</span>`;
    }
    const mainName = h.hostname || h.netbios || h.mdnsName || '-';
    nameHTML += `<span class="font-mono text-primary">${escapeHTML(mainName)}</span>`;
    if (h.model) {
      nameHTML += `<span class="badge-model">${escapeHTML(h.model)}</span>`;
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
        <a class="ip-link" href="javascript:void(0)" onclick="copyText('${h.ip}', 'IP kopyalandı'); event.stopPropagation();" title="IP'yi Kopyala">
          ${h.ip} ${roleTags}
        </a>
      </td>
      <td class="col-hostname">
        ${nameHTML}
      </td>
      <td class="col-mac">
        <span class="mac-val" onclick="copyText('${h.mac || ''}', 'MAC adresi kopyalandı'); event.stopPropagation();" title="MAC Kopyala">
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
  const icon = getDeviceIcon(host.deviceType, host.vendor, host.model);

  elements.modalDeviceIcon.textContent = icon;
  elements.modalDeviceTitle.textContent = host.customName || host.hostname || host.model || host.vendor || 'Cihaz Detayları';
  elements.modalDeviceIP.textContent = host.ip;

  elements.modalIP.textContent = host.ip;
  elements.modalIP.onclick = () => copyText(host.ip, 'IP adresi kopyalandı');

  elements.modalMAC.textContent = host.mac || 'Bilinmiyor';
  elements.modalMAC.onclick = () => copyText(host.mac || '', 'MAC adresi kopyalandı');

  elements.modalVendor.textContent = host.vendor || 'Bilinmiyor';
  elements.modalModel.textContent = host.model || '-';
  elements.modalType.textContent = host.deviceType || 'Cihaz';
  elements.modalHostname.textContent = host.hostname || '-';
  elements.modalNetBIOS.textContent = host.netbios || '-';
  elements.modalLatency.textContent = host.pingTimeMs ? `${host.pingTimeMs.toFixed(2)} ms` : '<1 ms';

  elements.modalAliasInput.value = host.customName || '';
  elements.modalNotesInput.value = host.comments || '';

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
    let banner = p.banner ? ` <small class="text-muted">(${escapeHTML(p.banner)})</small>` : '';
    return `<span class="port-pill ${isWeb ? 'web' : ''}" ${clickAttr} title="${p.service}">${p.port} / ${p.service}${banner}</span>`;
  }).join('');
}

// Live Ping Modal Controller
function openPingModal(ip) {
  elements.pingTargetIP.textContent = ip;
  elements.pingSentCount.textContent = '0';
  elements.pingSuccessCount.textContent = '0';
  elements.pingAvgLatency.textContent = '0 ms';
  elements.pingMinLatency.textContent = '-';
  elements.pingMaxLatency.textContent = '-';
  elements.pingLogTerminal.innerHTML = `<div class="terminal-line text-muted">${ip} için canlı ping başlatıldı...</div>`;

  state.pingLatencyHistory = [];
  drawPingCanvas();
  elements.pingModal.showModal();

  let sent = 0;
  let success = 0;
  let totalLatency = 0;
  let minLat = 999999;
  let maxLat = 0;

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
        if (data.latencyMs < minLat) minLat = data.latencyMs;
        if (data.latencyMs > maxLat) maxLat = data.latencyMs;

        const avg = (totalLatency / success).toFixed(1);
        elements.pingSuccessCount.textContent = success;
        elements.pingAvgLatency.textContent = `${avg} ms`;
        elements.pingMinLatency.textContent = `${minLat.toFixed(1)} ms`;
        elements.pingMaxLatency.textContent = `${maxLat.toFixed(1)} ms`;

        state.pingLatencyHistory.push(data.latencyMs);
        if (state.pingLatencyHistory.length > 35) state.pingLatencyHistory.shift();
        drawPingCanvas();

        appendPingTerminal(`64 bayt ${ip} adresinden yanıt: süre=${data.latencyMs.toFixed(2)}ms`, 'text-emerald');
      } else {
        state.pingLatencyHistory.push(null);
        if (state.pingLatencyHistory.length > 35) state.pingLatencyHistory.shift();
        drawPingCanvas();
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

function drawPingCanvas() {
  const canvas = elements.pingCanvas;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 560;
  const h = canvas.clientHeight || 110;

  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr;
    canvas.height = h * dpr;
  }

  ctx.save();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  // Background grid
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
  ctx.lineWidth = 1;
  for (let y = 20; y < h; y += 25) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  const history = state.pingLatencyHistory;
  if (history.length < 2) {
    ctx.restore();
    return;
  }

  const validPoints = history.filter(v => v !== null);
  const maxVal = Math.max(...validPoints, 30);
  const stepX = w / (history.length - 1);

  // Path coordinates
  const coords = history.map((val, idx) => {
    const x = idx * stepX;
    if (val === null) return { x, y: h - 5, isDrop: true };
    const y = h - 10 - ((val / (maxVal * 1.2)) * (h - 25));
    return { x, y: Math.max(8, y), isDrop: false };
  });

  // Gradient fill area under curve
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(16, 185, 129, 0.35)');
  grad.addColorStop(1, 'rgba(16, 185, 129, 0.0)');

  ctx.beginPath();
  ctx.moveTo(coords[0].x, h);
  coords.forEach(pt => ctx.lineTo(pt.x, pt.y));
  ctx.lineTo(coords[coords.length - 1].x, h);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line stroke
  ctx.beginPath();
  ctx.moveTo(coords[0].x, coords[0].y);
  coords.forEach(pt => ctx.lineTo(pt.x, pt.y));
  ctx.strokeStyle = '#10b981';
  ctx.lineWidth = 2.5;
  ctx.lineJoin = 'round';
  ctx.stroke();

  // Plot dots
  coords.forEach(pt => {
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, pt.isDrop ? 3 : 2.5, 0, Math.PI * 2);
    ctx.fillStyle = pt.isDrop ? '#f43f5e' : '#34d399';
    ctx.fill();
  });

  ctx.restore();
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

// Network Topology Interactive Visualizer
function initTopology() {
  const canvas = elements.topologyCanvas;
  if (!canvas) return;

  canvas.addEventListener('mousedown', (e) => {
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    // Check if clicked a node
    const clicked = getNodeAt(mouseX, mouseY);
    if (clicked) {
      openDeviceModal(clicked.ip);
      return;
    }

    state.topology.isDragging = true;
    state.topology.dragStartX = e.clientX - state.topology.panX;
    state.topology.dragStartY = e.clientY - state.topology.panY;
  });

  window.addEventListener('mousemove', (e) => {
    if (state.topology.isDragging) {
      state.topology.panX = e.clientX - state.topology.dragStartX;
      state.topology.panY = e.clientY - state.topology.dragStartY;
      renderTopology();
      return;
    }

    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    const node = getNodeAt(mouseX, mouseY);
    if (node !== state.topology.hoveredNode) {
      state.topology.hoveredNode = node;
      canvas.style.cursor = node ? 'pointer' : 'grab';
      renderTopology();
    }
  });

  window.addEventListener('mouseup', () => {
    state.topology.isDragging = false;
  });

  elements.resetTopologyBtn.addEventListener('click', () => {
    state.topology.panX = 0;
    state.topology.panY = 0;
    renderTopology();
  });

  window.addEventListener('resize', () => {
    if (state.currentView === 'topology') renderTopology();
  });
}

function getNodeAt(x, y) {
  const dpr = window.devicePixelRatio || 1;
  const nodes = state.topology.nodes || [];
  for (let i = nodes.length - 1; i >= 0; i--) {
    const n = nodes[i];
    const dx = x - (n.x + state.topology.panX);
    const dy = y - (n.y + state.topology.panY);
    if (Math.sqrt(dx * dx + dy * dy) <= (n.radius + 6)) {
      return n;
    }
  }
  return null;
}

function renderTopology() {
  const canvas = elements.topologyCanvas;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 800;
  const h = canvas.clientHeight || 480;

  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr;
    canvas.height = h * dpr;
  }

  ctx.save();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const hosts = Array.from(state.hosts.values());
  if (hosts.length === 0) {
    ctx.fillStyle = 'rgba(255, 255, 255, 0.4)';
    ctx.font = '14px var(--font-sans)';
    ctx.textAlign = 'center';
    ctx.fillText('Henüz aktif cihaz tespit edilmedi. Yukarıdaki "Tara" butonuna tıklayın.', w / 2, h / 2);
    ctx.restore();
    return;
  }

  const cx = w / 2 + state.topology.panX;
  const cy = h / 2 + state.topology.panY;

  // Identify Gateway or primary host
  const gateway = hosts.find(h => h.isGateway) || hosts[0];
  const clients = hosts.filter(h => h.ip !== gateway.ip);

  // Concentric orbit rings
  const ring1Radius = Math.min(w, h) * 0.35;
  ctx.strokeStyle = 'rgba(59, 130, 246, 0.12)';
  ctx.lineWidth = 1.5;
  ctx.setLineDash([4, 6]);
  ctx.beginPath();
  ctx.arc(cx, cy, ring1Radius, 0, Math.PI * 2);
  ctx.stroke();
  ctx.setLineDash([]);

  // Calculate nodes
  const nodes = [];
  nodes.push({
    ip: gateway.ip,
    name: gateway.customName || gateway.hostname || 'Gateway',
    type: 'gateway',
    deviceType: gateway.deviceType,
    vendor: gateway.vendor,
    model: gateway.model,
    x: w / 2,
    y: h / 2,
    radius: 24,
    color: '#3b82f6',
    icon: '🌐'
  });

  const totalClients = clients.length;
  clients.forEach((c, idx) => {
    const angle = (idx / totalClients) * (Math.PI * 2) - Math.PI / 2;
    // Vary radius slightly for aesthetic balance
    const r = ring1Radius + (idx % 2 === 0 ? -15 : 20);
    const nx = w / 2 + Math.cos(angle) * r;
    const ny = h / 2 + Math.sin(angle) * r;

    let col = '#0ea5e9'; // default blue
    if ((c.vendor || '').toLowerCase().includes('apple')) col = '#a855f7';
    if (c.deviceType === 'Printer') col = '#10b981';
    if (c.deviceType === 'Smart / IoT Device') col = '#f59e0b';
    if (c.deviceType === 'Server / NAS') col = '#f43f5e';
    if (c.deviceType === 'Mobile / Tablet') col = '#ec4899';

    nodes.push({
      ip: c.ip,
      name: c.customName || c.hostname || c.model || c.vendor || c.ip,
      type: 'client',
      deviceType: c.deviceType,
      vendor: c.vendor,
      model: c.model,
      x: nx,
      y: ny,
      radius: 16,
      color: col,
      icon: getDeviceIcon(c.deviceType, c.vendor, c.model)
    });
  });

  state.topology.nodes = nodes;

  // Draw connecting laser lines from gateway to clients
  nodes.slice(1).forEach(n => {
    const startX = cx;
    const startY = cy;
    const endX = n.x + state.topology.panX;
    const endY = n.y + state.topology.panY;

    const grad = ctx.createLinearGradient(startX, startY, endX, endY);
    grad.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
    grad.addColorStop(1, 'rgba(255, 255, 255, 0.1)');

    ctx.beginPath();
    ctx.moveTo(startX, startY);
    ctx.lineTo(endX, endY);
    ctx.strokeStyle = grad;
    ctx.lineWidth = 1.2;
    ctx.stroke();
  });

  // Draw Nodes
  nodes.forEach(n => {
    const drawX = n.x + state.topology.panX;
    const drawY = n.y + state.topology.panY;
    const isHovered = (state.topology.hoveredNode && state.topology.hoveredNode.ip === n.ip);
    const r = isHovered ? n.radius + 4 : n.radius;

    // Glowing aura
    const glow = ctx.createRadialGradient(drawX, drawY, r * 0.4, drawX, drawY, r * 2);
    glow.addColorStop(0, n.color + '44');
    glow.addColorStop(1, 'transparent');
    ctx.fillStyle = glow;
    ctx.beginPath();
    ctx.arc(drawX, drawY, r * 2, 0, Math.PI * 2);
    ctx.fill();

    // Node body
    ctx.fillStyle = '#1e293b';
    ctx.beginPath();
    ctx.arc(drawX, drawY, r, 0, Math.PI * 2);
    ctx.fill();

    ctx.strokeStyle = n.color;
    ctx.lineWidth = isHovered ? 3 : 2;
    ctx.stroke();

    // Node Icon
    ctx.font = `${Math.floor(r * 0.9)}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(n.icon, drawX, drawY);

    // Label below node
    ctx.fillStyle = isHovered ? '#ffffff' : '#cbd5e1';
    ctx.font = `${isHovered ? '600 ' : ''}11px var(--font-sans)`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';

    const displayName = n.name.length > 18 ? n.name.slice(0, 15) + '...' : n.name;
    ctx.fillText(displayName, drawX, drawY + r + 5);

    ctx.fillStyle = 'rgba(255, 255, 255, 0.45)';
    ctx.font = '10px var(--font-mono)';
    ctx.fillText(n.ip, drawX, drawY + r + 18);
  });

  ctx.restore();
}

// Helpers
function getDeviceIcon(type, vendor, model) {
  const combined = ((vendor || '') + ' ' + (model || '')).toLowerCase();
  if (type === 'Router / Gateway') return '🌐';
  if (type === 'Printer') return '🖨️';
  if (type === 'Mobile / Tablet') return '📱';
  if (type === 'Smart / IoT Device') {
    if (combined.includes('tv')) return '📺';
    if (combined.includes('speaker') || combined.includes('sonos')) return '🔊';
    return '💡';
  }
  if (type === 'Server / NAS') return '🗄️';
  if (combined.includes('apple')) return '🍎';
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
