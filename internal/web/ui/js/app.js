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
    const yaraRules = (document.getElementById('yara-rules-path').value || '').trim();
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
    const hasDetails = e.details && Object.keys(e.details).length > 0;
    const tr = document.createElement('tr');
    tr.className = hasDetails ? 'evidence-expandable' : '';
    tr.innerHTML = `
      <td><span class="sev-${e.severity}">${e.severity.toUpperCase()}</span></td>
      <td>${esc(e.domain)}</td>
      <td><code>${esc(e.rule)}</code></td>
      <td>${esc(e.description)} ${hasDetails ? '<span class="evidence-chevron">&#9654;</span>' : ''}</td>
      <td><strong>+${e.score}</strong></td>`;
    tbody.appendChild(tr);

    if (hasDetails) {
      const detailTr = document.createElement('tr');
      detailTr.className = 'evidence-detail-row';
      detailTr.style.display = 'none';
      detailTr.innerHTML = `<td colspan="5"><div class="evidence-detail-panel">${renderDetails(e.details)}</div></td>`;
      tbody.appendChild(detailTr);

      tr.addEventListener('click', () => {
        const isOpen = detailTr.style.display !== 'none';
        detailTr.style.display = isOpen ? 'none' : 'table-row';
        tr.querySelector('.evidence-chevron').innerHTML = isOpen ? '&#9654;' : '&#9660;';
        tr.classList.toggle('evidence-expanded', !isOpen);
      });
    }
  });
}

function renderDetails(details) {
  let html = '<div class="detail-grid">';
  for (const [key, value] of Object.entries(details)) {
    if (value === null || value === undefined || value === '') continue;
    if (Array.isArray(value) && value.length === 0) continue;
    const displayKey = key.replace(/_/g, ' ');
    let displayValue;
    if (Array.isArray(value)) {
      if (typeof value[0] === 'object') {
        displayValue = '<pre>' + esc(JSON.stringify(value, null, 2)) + '</pre>';
      } else {
        displayValue = value.map(v => '<code>' + esc(String(v)) + '</code>').join(' ');
      }
    } else if (typeof value === 'object') {
      displayValue = '<pre>' + esc(JSON.stringify(value, null, 2)) + '</pre>';
    } else {
      displayValue = '<code>' + esc(String(value)) + '</code>';
    }
    html += `<div class="detail-key">${esc(displayKey)}</div><div class="detail-value">${displayValue}</div>`;
  }
  html += '</div>';
  return html;
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
  const orange = ['persistent_and_networked','webserver_spawned_shell','orphan_active_connection','impersonates_apple'];
  const yellow = ['target_missing','loose_permissions','world_writable','forced_command'];

  if (red.includes(flag)) return 'red';
  if (orange.includes(flag)) return 'orange';
  if (yellow.includes(flag)) return 'yellow';
  if (flag.startsWith('suspicious_remote_port')) return 'red';
  return 'blue';
}

// ========== IOC Watch ==========

let watchEventSource = null;

async function startWatch() {
  const iocsText = document.getElementById('watch-iocs').value.trim();
  if (!iocsText) { alert('请输入至少一条 IOC'); return; }

  const interval = parseInt(document.getElementById('watch-interval').value) || 3;
  const yaraRules = (document.getElementById('yara-rules-path').value || '').trim();
  const iface = (document.getElementById('watch-iface').value || '').trim();

  document.getElementById('btn-watch-start').disabled = true;
  document.getElementById('btn-watch-stop').disabled = false;
  document.getElementById('watch-status').innerHTML = '<span class="badge badge-running">监控中...</span>';
  document.querySelector('#watch-table tbody').innerHTML = '';

  try {
    const resp = await fetch('/api/watch/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iocs: iocsText, interval: interval, yara_rules: yaraRules, iface: iface }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    const result = await resp.json();
    const iocList = (result.ioc_samples || []).map(s => '<code>' + esc(s) + '</code>').join(' ');
    document.getElementById('watch-status').innerHTML =
      `<span class="badge badge-running">监控中 [${esc(result.mode || '轮询')}]</span> ${result.ioc_count} 条 IOC，间隔 ${result.interval} 秒` +
      (iocList ? `<br><span style="font-size:11px;color:var(--text2)">IOC: ${iocList}</span>` : '');

    // 开启 SSE 事件流
    startWatchStream();
  } catch (e) {
    document.getElementById('watch-status').innerHTML = `<span class="badge badge-error">启动失败: ${esc(e.message)}</span>`;
    document.getElementById('btn-watch-start').disabled = false;
    document.getElementById('btn-watch-stop').disabled = true;
  }
}

async function stopWatch() {
  try {
    await fetch('/api/watch/stop', { method: 'POST' });
  } catch (_) {}
  if (watchEventSource) { watchEventSource.close(); watchEventSource = null; }
  document.getElementById('btn-watch-start').disabled = false;
  document.getElementById('btn-watch-stop').disabled = true;
  document.getElementById('watch-status').innerHTML = '<span class="badge badge-done">监控已停止</span>';
}

function startWatchStream() {
  if (watchEventSource) watchEventSource.close();
  watchEventSource = new EventSource('/api/watch/stream');

  watchEventSource.onmessage = function(e) {
    try {
      const evt = JSON.parse(e.data);
      appendWatchEvent(evt);
    } catch (_) {}
  };

  let lastStatusKey = '';
  watchEventSource.addEventListener('status', function(e) {
    try {
      const st = JSON.parse(e.data);
      // 只在状态真正变化时更新 DOM，避免疯狂刷新
      const key = `${st.scans}:${st.last_conns}:${st.events}:${st.last_hits}:${st.last_err}`;
      if (key === lastStatusKey) return;
      lastStatusKey = key;

      const modeLabel = st.mode ? ` [${esc(st.mode)}]` : '';
      let html = `<span class="badge badge-running">监控中${modeLabel}</span> 扫描 #${st.scans} | ${st.last_conns} 条连接 | 本轮匹配 ${st.last_hits || 0} | 累计命中 ${st.events}`;
      if (st.last_conns === 0 && st.scans > 0) {
        html += '<br><span style="color:var(--red);font-weight:600">未采集到任何连接，请检查权限 (sudo)</span>';
      }
      if (st.last_err) {
        html += `<br><span style="color:var(--orange)">${esc(st.last_err)}</span>`;
      }
      document.getElementById('watch-status').innerHTML = html;
    } catch (_) {}
  });

  watchEventSource.addEventListener('done', function(e) {
    watchEventSource.close();
    watchEventSource = null;
    document.getElementById('btn-watch-start').disabled = false;
    document.getElementById('btn-watch-stop').disabled = true;
    document.getElementById('watch-status').innerHTML = '<span class="badge badge-done">监控结束</span>';
  });

  watchEventSource.onerror = function() {
    // SSE 断开——可能是服务器关闭或网络问题
  };
}

function appendWatchEvent(evt) {
  const tbody = document.querySelector('#watch-table tbody');
  const tr = document.createElement('tr');
  if (evt.severity === 'critical' || evt.severity === 'high') tr.className = 'suspicious';

  const proc = evt.process ? evt.process.name : (evt.connection?.process_name || '—');
  const remote = evt.connection ? `${evt.connection.remote_address}:${evt.connection.remote_port}` : '—';
  const time = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '—';
  const pid = evt.connection?.pid || 0;
  const resolveTag = evt.pid_resolve_state === 'deferred' ? ' <span class="tag tag-orange">deferred</span>' :
                     evt.pid_resolve_state === 'unresolved' ? ' <span class="tag tag-blue">unresolved</span>' : '';
  const srcLabel = (evt.source_stage || '').replace(/_/g, ' ');
  const evidenceHtml = (evt.evidence || []).map(e =>
    `<span class="tag tag-${e.severity === 'high' ? 'red' : e.severity === 'medium' ? 'orange' : 'blue'}">+${e.score} ${esc(e.description)}</span>`
  ).join(' ');

  tr.innerHTML = `
    <td>${esc(time)}</td>
    <td><span class="sev-${evt.severity}">${(evt.severity||'').toUpperCase()}</span></td>
    <td><strong>${esc(evt.ioc?.value)}</strong></td>
    <td>${pid}${resolveTag}</td>
    <td>${esc(proc)}</td>
    <td>${esc(remote)}</td>
    <td><strong>${evt.score || 0}</strong></td>
    <td>${esc(srcLabel)}</td>
    <td>${evidenceHtml}</td>`;
  tbody.prepend(tr); // 新事件在最上面
}

// ========== YARA 独立扫描 ==========

async function runYaraScan() {
  const rulesPath = document.getElementById('yara-rules-path').value.trim();
  const status = document.getElementById('yara-status');

  if (!rulesPath) { alert('请输入 YARA 规则路径'); return; }

  document.getElementById('btn-yara-scan').disabled = true;
  status.innerHTML = '<span class="badge badge-running">采集进程并扫描中...</span>';

  try {
    const resp = await fetch('/api/yara/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rules_path: rulesPath }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    const result = await resp.json();

    status.innerHTML = `<span class="badge badge-done">扫描完成</span> 加载 ${result.rule_count} 条规则，识别 ${result.target_count} 个目标，命中 ${result.hit_count} 条`;
    renderYaraHits(result.hits || []);
  } catch (e) {
    status.innerHTML = `<span class="badge badge-error">扫描失败: ${esc(e.message)}</span>`;
  } finally {
    document.getElementById('btn-yara-scan').disabled = false;
  }
}

function renderYaraHits(hits) {
  const tbody = document.querySelector('#yara-table tbody');
  tbody.innerHTML = '';
  if (hits.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted" style="text-align:center;padding:20px">无匹配结果</td></tr>';
    return;
  }
  hits.forEach(h => {
    const tr = document.createElement('tr');
    const sev = h.severity_hint || 'info';
    tr.innerHTML = `
      <td><strong>${esc(h.rule)}</strong></td>
      <td title="${esc(h.target_path)}">${esc(h.target_path)}</td>
      <td>${esc(h.target_type || 'file')}</td>
      <td>${h.linked_pid || '—'}</td>
      <td>${(h.strings || []).map(s => '<code>' + esc(s) + '</code>').join(' ')}</td>
      <td><span class="sev-${sev}">${sev.toUpperCase()}</span></td>`;
    tbody.appendChild(tr);
  });
}

// ========== 文件浏览器 ==========

let fbTargetInput = '';
let fbCurrentPath = '/';
let fbCwdLoaded = false;

async function openFileBrowser(inputId) {
  fbTargetInput = inputId;
  const currentVal = document.getElementById(inputId).value.trim();
  if (currentVal) {
    fbCurrentPath = currentVal;
  } else if (!fbCwdLoaded) {
    try {
      const resp = await fetch('/api/fs/cwd');
      const data = await resp.json();
      if (data.cwd) fbCurrentPath = data.cwd;
      fbCwdLoaded = true;
    } catch (_) {}
  }
  document.getElementById('file-browser-modal').style.display = 'flex';
  fbNavigate(fbCurrentPath);
}

function closeFileBrowser() {
  document.getElementById('file-browser-modal').style.display = 'none';
}

async function fbNavigate(path) {
  fbCurrentPath = path;
  document.getElementById('fb-current-path').textContent = path;
  const el = document.getElementById('fb-entries');
  el.innerHTML = '<p class="muted">加载中...</p>';

  try {
    const resp = await fetch('/api/fs/browse?path=' + encodeURIComponent(path));
    if (!resp.ok) throw new Error(await resp.text());
    const data = await resp.json();
    fbCurrentPath = data.path;
    document.getElementById('fb-current-path').textContent = data.path;

    let html = '';
    const dirs = (data.entries || []).filter(e => e.is_dir);
    const files = (data.entries || []).filter(e => !e.is_dir);

    dirs.forEach(e => {
      const fullPath = data.path === '/' ? '/' + e.name : data.path + '/' + e.name;
      html += `<div class="fb-entry fb-dir" data-path="${esc(fullPath)}" data-action="navigate">
        <span class="fb-icon">📁</span> ${esc(e.name)}
      </div>`;
    });
    files.forEach(e => {
      const fullPath = data.path === '/' ? '/' + e.name : data.path + '/' + e.name;
      const size = e.size > 1048576 ? (e.size/1048576).toFixed(1)+'MB' : e.size > 1024 ? (e.size/1024).toFixed(1)+'KB' : e.size+'B';
      html += `<div class="fb-entry fb-file" data-path="${esc(fullPath)}" data-action="select">
        <span class="fb-icon">📄</span> ${esc(e.name)} <span class="fb-size">${size}</span>
      </div>`;
    });

    el.innerHTML = html || '<p class="muted">空目录</p>';

    // 事件委托：避免 inline handler 的 XSS 风险
    el.querySelectorAll('[data-action="navigate"]').forEach(div => {
      div.addEventListener('dblclick', () => fbNavigate(div.getAttribute('data-path')));
    });
    el.querySelectorAll('[data-action="select"]').forEach(div => {
      div.addEventListener('click', () => fbSelectFile(div.getAttribute('data-path')));
    });
  } catch (e) {
    el.innerHTML = `<p class="muted">错误: ${esc(e.message)}</p>`;
  }
}

function fbGoUp() {
  const parts = fbCurrentPath.split('/').filter(p => p);
  parts.pop();
  fbNavigate('/' + parts.join('/'));
}

function fbSelectCurrent() {
  document.getElementById(fbTargetInput).value = fbCurrentPath;
  closeFileBrowser();
}

function fbSelectFile(path) {
  document.getElementById(fbTargetInput).value = path;
  closeFileBrowser();
}
