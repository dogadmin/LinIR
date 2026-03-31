// LinIR GUI - 前端逻辑
let resultData = null;

// ========== 采集控制 ==========

async function startCollect() {
  const btn = document.getElementById('btn-collect');
  const status = document.getElementById('status');
  btn.disabled = true;
  status.className = 'badge badge-running';
  status.textContent = '采集中...';

  try {
    const yaraRules = (document.getElementById('yara-rules').value || '').trim();
    const body = yaraRules ? JSON.stringify({ yara_rules: yaraRules }) : '{}';
    const resp = await fetch('/api/collect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body,
    });
    if (!resp.ok) throw new Error(await resp.text());
    resultData = await resp.json();
    renderAll(resultData);
    status.className = 'badge badge-done';
    status.textContent = '采集完成';
    document.getElementById('btn-export').disabled = false;
  } catch (e) {
    status.className = 'badge badge-error';
    status.textContent = '采集失败';
    alert('采集失败: ' + e.message);
  } finally {
    btn.disabled = false;
  }
}

function exportJSON() {
  if (!resultData) return;
  const blob = new Blob([JSON.stringify(resultData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'linir-' + (resultData.host?.hostname || 'report') + '.json';
  a.click();
  URL.revokeObjectURL(url);
}

// 页面加载时检查是否已有数据
window.addEventListener('load', async () => {
  try {
    const resp = await fetch('/api/result');
    if (resp.ok) {
      const data = await resp.json();
      if (data && data.version) {
        resultData = data;
        renderAll(data);
        document.getElementById('status').className = 'badge badge-done';
        document.getElementById('status').textContent = '已有数据';
        document.getElementById('btn-export').disabled = false;
      }
    }
  } catch (_) {}
});

// ========== 渲染 ==========

function renderAll(r) {
  renderOverview(r);
  renderEvidence(r.score);
  renderProcesses(r.processes || []);
  renderConnections(r.connections || []);
  renderPersistence(r.persistence || []);
  renderIntegrity(r.integrity);
  renderPreflight(r.self_check, r.preflight);
  renderErrors(r.errors || []);
}

function renderOverview(r) {
  const score = r.score || {};
  const sev = score.severity || 'info';

  document.getElementById('v-score').textContent = score.total ?? '—';
  document.getElementById('v-severity').textContent = (sev || '').toUpperCase();
  const scoreCard = document.getElementById('card-score');
  scoreCard.className = 'card card-score score-' + sev;

  const trust = r.preflight?.host_trust_level || '—';
  const trustEl = document.getElementById('v-trust');
  trustEl.textContent = trust.toUpperCase();
  trustEl.className = 'card-value trust-' + trust;
  document.getElementById('v-hostname').textContent = r.host?.hostname || '—';

  const procs = r.processes || [];
  const suspProcs = procs.filter(p => p.suspicious_flags && p.suspicious_flags.length > 0);
  document.getElementById('v-procs').textContent = procs.length;
  document.getElementById('v-procs-suspicious').textContent = suspProcs.length + ' 个可疑';

  const conns = r.connections || [];
  const suspConns = conns.filter(c => c.suspicious_flags && c.suspicious_flags.length > 0);
  document.getElementById('v-conns').textContent = conns.length;
  document.getElementById('v-conns-suspicious').textContent = suspConns.length + ' 个可疑';

  const persist = r.persistence || [];
  const riskyPersist = persist.filter(p => p.risk_flags && p.risk_flags.length > 0);
  document.getElementById('v-persist').textContent = persist.length;
  document.getElementById('v-persist-risky').textContent = riskyPersist.length + ' 个有风险';

  document.getElementById('v-yara').textContent = (r.yara_hits || []).length;
}

function renderEvidence(score) {
  const section = document.getElementById('evidence-section');
  if (!score || !score.evidence || score.evidence.length === 0) {
    section.style.display = 'none';
    return;
  }
  section.style.display = 'block';
  const tbody = document.querySelector('#evidence-table tbody');
  tbody.innerHTML = '';
  score.evidence.forEach(e => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="sev-${e.severity}">${e.severity.toUpperCase()}</span></td>
      <td>${esc(e.domain)}</td>
      <td><code>${esc(e.rule)}</code></td>
      <td>${esc(e.description)}</td>
      <td><strong>+${e.score}</strong></td>`;
    tbody.appendChild(tr);
  });
}

function renderProcesses(procs) {
  const tbody = document.querySelector('#proc-table tbody');
  tbody.innerHTML = '';
  procs.forEach(p => {
    const flags = (p.suspicious_flags || []);
    const isSusp = flags.length > 0;
    const tr = document.createElement('tr');
    if (isSusp) tr.className = 'suspicious';
    tr.setAttribute('data-searchable', [p.pid, p.ppid, p.username, p.name, p.exe, flags.join(' ')].join(' ').toLowerCase());
    tr.setAttribute('data-suspicious', isSusp ? '1' : '0');
    tr.innerHTML = `
      <td>${p.pid}</td>
      <td>${p.ppid}</td>
      <td>${esc(p.username)}</td>
      <td><strong>${esc(p.name)}</strong></td>
      <td title="${esc(p.exe)}">${esc(p.exe)}</td>
      <td>${flags.map(f => tagHTML(f)).join(' ')}</td>`;
    tbody.appendChild(tr);
  });
}

function renderConnections(conns) {
  const tbody = document.querySelector('#conn-table tbody');
  tbody.innerHTML = '';
  conns.forEach(c => {
    const flags = (c.suspicious_flags || []);
    const tr = document.createElement('tr');
    if (flags.length > 0) tr.className = 'suspicious';
    tr.setAttribute('data-searchable', [c.proto, c.local_address, c.local_port, c.remote_address, c.remote_port, c.state, c.pid, c.process_name].join(' ').toLowerCase());
    tr.innerHTML = `
      <td>${esc(c.proto)}</td>
      <td>${esc(c.local_address)}</td>
      <td>${c.local_port}</td>
      <td>${esc(c.remote_address)}</td>
      <td>${c.remote_port}</td>
      <td>${esc(c.state)}</td>
      <td>${c.pid || '—'}</td>
      <td>${esc(c.process_name || '')}</td>
      <td>${flags.map(f => tagHTML(f)).join(' ')}</td>`;
    tbody.appendChild(tr);
  });
}

function renderPersistence(items) {
  const tbody = document.querySelector('#persist-table tbody');
  tbody.innerHTML = '';
  items.forEach(item => {
    const flags = (item.risk_flags || []);
    const tr = document.createElement('tr');
    if (flags.length > 0) tr.className = 'suspicious';
    tr.innerHTML = `
      <td>${tagHTML(item.type, 'blue')}</td>
      <td title="${esc(item.path)}">${esc(item.path)}</td>
      <td title="${esc(item.target)}">${esc(item.target)}</td>
      <td>${esc(item.user_scope)}</td>
      <td>${flags.map(f => tagHTML(f)).join(' ')}</td>`;
    tbody.appendChild(tr);
  });
}

function renderIntegrity(ir) {
  const el = document.getElementById('integrity-content');
  if (!ir) { el.innerHTML = '<p class="muted">无数据</p>'; return; }

  let html = '';
  if (ir.rootkit_suspected) {
    html += '<div class="integrity-item danger"><strong>Rootkit 疑似：是</strong></div>';
  }
  if (ir.kernel_taint && ir.kernel_taint !== '0') {
    html += `<div class="integrity-item warn">内核 Taint: ${esc(ir.kernel_taint)}</div>`;
  }
  html += renderIntegrityGroup('进程视图不一致', ir.process_view_mismatch, 'warn');
  html += renderIntegrityGroup('网络视图不一致', ir.network_view_mismatch, 'warn');
  html += renderIntegrityGroup('文件视图不一致', ir.file_view_mismatch, 'warn');
  html += renderIntegrityGroup('模块视图不一致', ir.module_view_mismatch, 'danger');
  html += renderIntegrityGroup('可见性异常', ir.visibility_anomalies, 'warn');
  html += renderIntegrityGroup('建议操作', ir.recommended_action, '');

  el.innerHTML = html || '<p class="muted">未发现异常</p>';
}

function renderIntegrityGroup(title, items, cls) {
  if (!items || items.length === 0) return '';
  let html = `<div class="integrity-group"><h3>${esc(title)} (${items.length})</h3>`;
  items.forEach(item => {
    html += `<div class="integrity-item ${cls}">${esc(item)}</div>`;
  });
  return html + '</div>';
}

function renderPreflight(sc, pf) {
  const el = document.getElementById('preflight-content');
  if (!sc && !pf) { el.innerHTML = '<p class="muted">无数据</p>'; return; }

  let html = '<div class="integrity-group"><h3>自检结果</h3>';
  if (sc) {
    html += `<div class="integrity-item">采集可信度: <strong>${esc(sc.collection_confidence)}</strong></div>`;
    html += `<div class="integrity-item">自身路径: ${esc(sc.self_path)}</div>`;
    if (sc.ld_preload_present) html += '<div class="integrity-item danger">LD_PRELOAD: 已检测到</div>';
    if (sc.dyld_injection_present) html += '<div class="integrity-item danger">DYLD 注入: 已检测到</div>';
    (sc.self_env_anomaly || []).forEach(a => {
      html += `<div class="integrity-item warn">${esc(a)}</div>`;
    });
  }
  html += '</div>';

  if (pf) {
    html += renderIntegrityGroup('PATH 异常', pf.path_anomaly, 'warn');
    html += renderIntegrityGroup('Loader 异常', pf.loader_anomaly, 'danger');
    html += renderIntegrityGroup('环境变量异常', pf.env_anomaly, 'warn');
    html += renderIntegrityGroup('Shell Profile 异常', pf.shell_profile_anomaly, 'warn');
    html += renderIntegrityGroup('可见性风险', pf.visibility_risk, 'danger');
    html += renderIntegrityGroup('备注', pf.notes, '');
  }

  el.innerHTML = html;
}

function renderErrors(errors) {
  const el = document.getElementById('errors-content');
  if (errors.length === 0) { el.innerHTML = '<p class="muted">无错误</p>'; return; }
  let html = '';
  errors.forEach(e => {
    html += `<div class="integrity-item warn"><strong>[${esc(e.phase)}]</strong> ${esc(e.message)}</div>`;
  });
  el.innerHTML = html;
}

// ========== 交互 ==========

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
}

function filterTable(tableId, query) {
  const q = query.toLowerCase();
  document.querySelectorAll('#' + tableId + ' tbody tr').forEach(tr => {
    const text = tr.getAttribute('data-searchable') || tr.textContent.toLowerCase();
    tr.style.display = text.includes(q) ? '' : 'none';
  });
}

function toggleSuspiciousOnly() {
  const checked = document.getElementById('proc-suspicious-only').checked;
  document.querySelectorAll('#proc-table tbody tr').forEach(tr => {
    if (checked && tr.getAttribute('data-suspicious') === '0') {
      tr.style.display = 'none';
    } else {
      tr.style.display = '';
    }
  });
}

// ========== 工具 ==========

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function tagHTML(text, color) {
  if (!text) return '';
  const c = color || tagColor(text);
  return `<span class="tag tag-${c}">${esc(text)}</span>`;
}

function tagColor(flag) {
  const red = ['exe_deleted','exe_in_tmp','dev_tcp_reverse_shell','system_wide_preload','rootkit_suspected','fake_kernel_thread','pipe_to_shell','ld_preload_in_env','target_in_tmp'];
  const orange = ['interpreter','interpreter_with_network','interpreter_established_outbound','persistent_and_networked','webserver_spawned_shell','orphan_active_connection','raw_socket','downloads_from_network','base64_usage','impersonates_apple'];
  const yellow = ['name_exe_mismatch','exe_unreadable','target_missing','loose_permissions','world_writable','forced_command','shell_exec'];

  if (red.includes(flag)) return 'red';
  if (orange.includes(flag)) return 'orange';
  if (yellow.includes(flag)) return 'yellow';
  if (flag.startsWith('suspicious_remote_port')) return 'red';
  return 'blue';
}
