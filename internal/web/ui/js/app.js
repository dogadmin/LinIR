// LinIR GUI - 前端逻辑
let resultData = null;
let analysisData = null;
let apiToken = window.__LINIR_TOKEN__ || '';

function authHeaders(extra) {
  const h = { 'Authorization': 'Bearer ' + apiToken };
  if (extra) Object.assign(h, extra);
  return h;
}

function authURL(url) {
  const sep = url.includes('?') ? '&' : '?';
  return url + sep + 'token=' + encodeURIComponent(apiToken);
}

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
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: body,
    });
    if (!resp.ok) throw new Error(await resp.text());
    resultData = await resp.json();
    renderAll(resultData);
    status.className = 'badge badge-done';
    status.textContent = '采集完成';
    enableExportButtons();
  } catch (e) {
    status.className = 'badge badge-error';
    status.textContent = '采集失败';
    alert('采集失败: ' + e.message);
  } finally {
    btn.disabled = false;
  }
}

function exportJSON() {
  const data = analysisData || resultData;
  if (!data) return;
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const hostname = data.host?.hostname || resultData?.host?.hostname || 'report';
  a.download = 'linir-' + hostname + '.json';
  a.click();
  URL.revokeObjectURL(url);
}

async function exportCSV() {
  try {
    const resp = await fetch('/api/export/csv', { headers: authHeaders() });
    if (!resp.ok) throw new Error(await resp.text());
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const disposition = resp.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="?([^"]+)"?/);
    a.download = match ? match[1] : 'linir-csv.zip';
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    alert('CSV 导出失败: ' + e.message);
  }
}

function enableExportButtons() {
  document.getElementById('btn-export').disabled = false;
  document.getElementById('btn-export-csv').disabled = false;
}

// 页面加载时检查是否已有数据
window.addEventListener('load', async () => {
  try {
    const resp = await fetch('/api/result', { headers: authHeaders() });
    if (resp.ok) {
      const data = await resp.json();
      if (data && data.version) {
        resultData = data;
        renderAll(data);
        document.getElementById('status').className = 'badge badge-done';
        document.getElementById('status').textContent = '已有数据';
        enableExportButtons();
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
      <td><span class="sev-${esc(e.severity)}">${e.severity.toUpperCase()}</span></td>
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
      headers: authHeaders({ 'Content-Type': 'application/json' }),
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
    await fetch('/api/watch/stop', { method: 'POST', headers: authHeaders() });
  } catch (_) {}
  if (watchEventSource) { watchEventSource.close(); watchEventSource = null; }
  document.getElementById('btn-watch-start').disabled = false;
  document.getElementById('btn-watch-stop').disabled = true;
  document.getElementById('watch-status').innerHTML = '<span class="badge badge-done">监控已停止</span>';
}

function startWatchStream() {
  if (watchEventSource) watchEventSource.close();
  watchEventSource = new EventSource(authURL('/api/watch/stream'));

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
    <td><span class="sev-${esc(evt.severity)}">${(evt.severity||'').toUpperCase()}</span></td>
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
      headers: authHeaders({ 'Content-Type': 'application/json' }),
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
      <td><span class="sev-${esc(sev)}">${sev.toUpperCase()}</span></td>`;
    tbody.appendChild(tr);
  });
}

// ========== 三维分析 ==========

async function startAnalysis() {
  const btn = document.getElementById('btn-analysis');
  const status = document.getElementById('status');
  btn.disabled = true;
  status.className = 'badge badge-running';
  status.textContent = '三维分析中...';

  try {
    const yaraRules = (document.getElementById('yara-rules-path').value || '').trim();
    const body = {
      with_retained: true,
      with_triggerable: true,
      timeline: true,
    };
    if (yaraRules) body.yara_rules = yaraRules;

    const resp = await fetch('/api/analysis', {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(body),
    });
    if (!resp.ok) throw new Error(await resp.text());
    analysisData = await resp.json();

    // Render runtime part using existing functions
    if (analysisData.runtime) {
      resultData = analysisData.runtime;
      renderAll(resultData);
    }

    // Render three-state panels
    renderRetained(analysisData.retained);
    renderTriggerable(analysisData.triggerable);
    renderTimeline(analysisData.timeline);

    status.className = 'badge badge-done';
    status.textContent = '分析完成';
    enableExportButtons();
  } catch (e) {
    status.className = 'badge badge-error';
    status.textContent = '分析失败';
    alert('分析失败: ' + e.message);
  } finally {
    btn.disabled = false;
  }
}

function renderRetained(r) {
  const el = document.getElementById('retained-content');
  if (!r) { el.innerHTML = '<p class="muted">未采集</p>'; return; }

  let html = `<div class="integrity-group"><h3>概况</h3>
    <div class="integrity-item">时间窗口: <strong>${esc(r.window)}</strong></div>
    <div class="integrity-item">可信度: <strong>${esc(r.confidence)}</strong></div>
  </div>`;

  // File timeline
  if (r.file_timeline && r.file_timeline.length > 0) {
    html += `<div class="integrity-group"><h3>文件时间线 (${r.file_timeline.length})</h3>`;
    html += '<div class="table-wrap" style="max-height:300px;overflow:auto"><table><thead><tr><th>路径</th><th>修改时间</th><th>大小</th><th>权限</th><th>关键目录</th><th>标记</th></tr></thead><tbody>';
    r.file_timeline.forEach(f => {
      const flags = (f.risk_flags || []);
      const cls = flags.length > 0 ? ' class="suspicious"' : '';
      html += `<tr${cls}>
        <td title="${esc(f.path)}">${esc(f.path)}</td>
        <td>${new Date(f.mod_time).toLocaleString()}</td>
        <td>${f.size}</td>
        <td>${esc(f.mode)}</td>
        <td>${esc(f.key_dir)}</td>
        <td>${flags.map(f => tagHTML(f)).join(' ')}</td></tr>`;
    });
    html += '</tbody></table></div></div>';
  }

  // Persistence changes
  if (r.persistence_changes && r.persistence_changes.length > 0) {
    html += `<div class="integrity-group"><h3>持久化变更 (${r.persistence_changes.length})</h3>`;
    r.persistence_changes.forEach(c => {
      const flags = (c.risk_flags || []).map(f => tagHTML(f)).join(' ');
      html += `<div class="integrity-item warn"><strong>[${esc(c.change_type)}]</strong> ${esc(c.type)} ${esc(c.path)} → ${esc(c.target)} ${flags}</div>`;
    });
    html += '</div>';
  }

  // Artifacts
  if (r.artifacts && r.artifacts.length > 0) {
    html += `<div class="integrity-group"><h3>残留痕迹 (${r.artifacts.length})</h3>`;
    r.artifacts.forEach(a => {
      const cls = a.type === 'deleted_exe' ? 'danger' : 'warn';
      html += `<div class="integrity-item ${cls}"><strong>[${esc(a.type)}]</strong> ${esc(a.path)} — ${esc(a.reason)}</div>`;
    });
    html += '</div>';
  }

  // Auth history
  if (r.auth_history && r.auth_history.length > 0) {
    html += `<div class="integrity-group"><h3>认证历史 (${r.auth_history.length})</h3>`;
    html += '<div class="table-wrap" style="max-height:300px;overflow:auto"><table><thead><tr><th>时间</th><th>类型</th><th>用户</th><th>来源IP</th><th>成功</th></tr></thead><tbody>';
    r.auth_history.forEach(e => {
      const cls = !e.success ? ' class="suspicious"' : '';
      html += `<tr${cls}>
        <td>${new Date(e.time).toLocaleString()}</td>
        <td>${esc(e.type)}</td>
        <td>${esc(e.user)}</td>
        <td>${esc(e.remote_ip || '—')}</td>
        <td>${e.success ? '✓' : '✗'}</td></tr>`;
    });
    html += '</tbody></table></div></div>';
  }

  // Log events
  if (r.log_events && r.log_events.length > 0) {
    html += `<div class="integrity-group"><h3>日志事件 (${r.log_events.length})</h3>`;
    html += '<div class="table-wrap" style="max-height:300px;overflow:auto"><table><thead><tr><th>时间</th><th>进程</th><th>严重度</th><th>消息</th></tr></thead><tbody>';
    r.log_events.slice(0, 200).forEach(e => {
      const cls = e.severity === 'error' ? ' class="suspicious"' : '';
      html += `<tr${cls}>
        <td>${new Date(e.time).toLocaleString()}</td>
        <td>${esc(e.process)}</td>
        <td>${esc(e.severity)}</td>
        <td>${esc(e.message.substring(0, 200))}</td></tr>`;
    });
    html += '</tbody></table></div></div>';
  }

  el.innerHTML = html || '<p class="muted">无历史残留数据</p>';
}

function renderTriggerable(t) {
  const el = document.getElementById('triggerable-content');
  if (!t) { el.innerHTML = '<p class="muted">未采集</p>'; return; }

  let html = `<div class="integrity-group"><h3>概况</h3>
    <div class="integrity-item">可信度: <strong>${esc(t.confidence)}</strong></div>
  </div>`;

  const renderEntries = (title, entries) => {
    if (!entries || entries.length === 0) return '';
    let h = `<div class="integrity-group"><h3>${esc(title)} (${entries.length})</h3>`;
    h += '<div class="table-wrap" style="max-height:300px;overflow:auto"><table><thead><tr><th>类型</th><th>路径</th><th>目标</th><th>触发条件</th><th>调度</th><th>标记</th></tr></thead><tbody>';
    entries.forEach(e => {
      const flags = (e.risk_flags || []);
      const cls = flags.length > 0 ? ' class="suspicious"' : '';
      h += `<tr${cls}>
        <td>${tagHTML(e.type, 'blue')}</td>
        <td title="${esc(e.path)}">${esc(e.path)}</td>
        <td title="${esc(e.target)}">${esc(e.target)}</td>
        <td>${esc(e.trigger_condition)}</td>
        <td>${esc(e.schedule || e.next_fire || '—')}</td>
        <td>${flags.map(f => tagHTML(f)).join(' ')}</td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
  };

  html += renderEntries('自动启动项', t.autostarts);
  html += renderEntries('定时任务', t.scheduled);
  html += renderEntries('KeepAlive/重启机制', t.keepalive);

  el.innerHTML = html;
}

let timelineData = [];

function renderTimeline(events) {
  timelineData = events || [];
  const tbody = document.querySelector('#timeline-table tbody');
  tbody.innerHTML = '';

  if (timelineData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted" style="text-align:center;padding:20px">无时间线数据</td></tr>';
    return;
  }

  renderTimelineRows(timelineData);
}

function renderTimelineRows(events) {
  const tbody = document.querySelector('#timeline-table tbody');
  tbody.innerHTML = '';

  events.forEach(e => {
    const tr = document.createElement('tr');
    const sevClass = (e.severity === 'high' || e.severity === 'critical') ? 'suspicious' : '';
    if (sevClass) tr.className = sevClass;

    const scopeColors = { runtime: 'blue', retained: 'orange', triggerable: 'yellow' };
    const timeStr = e.time_type === 'synthetic' ? e.synth_label : new Date(e.time).toLocaleString();

    tr.setAttribute('data-scope', e.scope || '');
    tr.setAttribute('data-severity', e.severity || '');

    tr.innerHTML = `
      <td>${esc(timeStr)}</td>
      <td>${tagHTML(e.scope, scopeColors[e.scope] || 'blue')}</td>
      <td>${esc(e.type)}</td>
      <td title="${esc(e.object)}">${esc((e.object || '').substring(0, 60))}</td>
      <td><span class="sev-${esc(e.severity)}">${(e.severity || '').toUpperCase()}</span></td>
      <td>${esc((e.summary || '').substring(0, 100))}</td>`;
    tbody.appendChild(tr);
  });
}

function filterTimeline() {
  const scope = document.getElementById('timeline-scope-filter').value;
  const severity = document.getElementById('timeline-severity-filter').value;
  const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  const filtered = timelineData.filter(e => {
    if (scope && e.scope !== scope) return false;
    if (severity && (sevRank[e.severity] || 0) < (sevRank[severity] || 0)) return false;
    return true;
  });
  renderTimelineRows(filtered);
}

// ========== AI 分析 ==========

let aiMessages = []; // {role, content} 对话历史

async function sendAIMessage() {
  const apiKey = document.getElementById('ai-api-key').value.trim();
  const model = document.getElementById('ai-model').value;
  const input = document.getElementById('ai-input');
  const message = input.value.trim();

  if (!apiKey) { alert('请输入 MiniMax API Key'); return; }
  if (!message) return;

  // Add user message to UI
  appendAIChatBubble('user', message);
  aiMessages.push({ role: 'user', content: message });
  if (aiMessages.length > 30) aiMessages = aiMessages.slice(-30);
  input.value = '';

  document.getElementById('ai-status').innerHTML = '<span class="badge badge-running">AI 思考中...</span>';

  try {
    const resp = await fetch('/api/ai/chat', {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        api_key: apiKey,
        model: model,
        messages: aiMessages,
      }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    const data = await resp.json();

    appendAIChatBubble('assistant', data.reply);
    aiMessages.push({ role: 'assistant', content: data.reply });
    if (aiMessages.length > 30) aiMessages = aiMessages.slice(-30);

    document.getElementById('ai-status').innerHTML = '';
  } catch (e) {
    document.getElementById('ai-status').innerHTML = `<span class="badge badge-error">错误: ${esc(e.message)}</span>`;
  }
}

async function runAIAnalyze() {
  const apiKey = document.getElementById('ai-api-key').value.trim();
  const model = document.getElementById('ai-model').value;

  if (!apiKey) { alert('请输入 MiniMax API Key'); return; }

  const userPrompt = '综合分析这台主机的安全状态（一键分析）';
  appendAIChatBubble('user', userPrompt);
  aiMessages.push({ role: 'user', content: userPrompt });
  document.getElementById('ai-status').innerHTML = '<span class="badge badge-running">AI 综合分析中，请稍候...</span>';

  try {
    const resp = await fetch('/api/ai/analyze', {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ api_key: apiKey, model: model }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    const data = await resp.json();

    appendAIChatBubble('assistant', data.reply);
    aiMessages.push({ role: 'assistant', content: data.reply });
    if (aiMessages.length > 30) aiMessages = aiMessages.slice(-30);

    document.getElementById('ai-status').innerHTML = '<span class="badge badge-done">分析完成</span>';
  } catch (e) {
    document.getElementById('ai-status').innerHTML = `<span class="badge badge-error">分析失败: ${esc(e.message)}</span>`;
  }
}

const aiPresets = {
  '入侵判定': '基于采集数据，判断这台主机是否被入侵。直接给结论（是/否/疑似），列出关键依据。',
  '后门排查': '排查是否存在后门。重点检查：异常持久化项、可疑自启动服务、异常 cron 任务、SSH authorized_keys 异常、隐藏进程。直接列出发现。',
  '横向移动': '分析是否存在横向移动迹象。检查：异常 SSH 连接、内网扫描行为、异常认证记录、可疑网络连接。',
  '数据外泄': '分析是否存在数据外泄风险。检查：异常外联连接、可疑传输行为、异常进程网络活动、DNS 隧道迹象。',
  '持久化分析': '深入分析所有持久化机制。对每个有风险标记的持久化项给出判断：是否恶意、风险等级、建议处置方式。',
  '处置建议': '基于当前发现，给出完整的应急处置方案。包括：立即处置步骤、需要保全的证据、后续加固建议。按优先级排序。',
};

function aiPreset(name) {
  const prompt = aiPresets[name];
  if (!prompt) return;
  document.getElementById('ai-input').value = prompt;
  sendAIMessage();
}

function clearAIChat() {
  aiMessages = [];
  document.getElementById('ai-messages').innerHTML = '';
  document.getElementById('ai-status').innerHTML = '';
}

function appendAIChatBubble(role, content) {
  const container = document.getElementById('ai-messages');
  const div = document.createElement('div');

  if (role === 'user') {
    div.style.cssText = 'margin-bottom:12px;padding:8px 12px;background:var(--bg3);border-radius:6px;color:var(--text);white-space:pre-wrap;word-break:break-word;';
    div.innerHTML = '<strong style="color:var(--accent)">You:</strong> ' + esc(content);
  } else {
    div.style.cssText = 'margin-bottom:12px;padding:8px 12px;background:rgba(79,140,255,.08);border-left:3px solid var(--accent);border-radius:6px;color:var(--text);white-space:pre-wrap;word-break:break-word;';
    div.innerHTML = '<strong style="color:var(--green)">AI:</strong> ' + renderAIMarkdown(content);
  }

  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function renderAIMarkdown(text) {
  // Simple markdown: **bold**, `code`, ```block```, headers, lists
  let html = esc(text);
  // Code blocks
  html = html.replace(/```([\s\S]*?)```/g, '<pre style="background:var(--bg);padding:8px;border-radius:4px;overflow-x:auto;margin:8px 0">$1</pre>');
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code style="background:var(--bg);padding:2px 4px;border-radius:3px">$1</code>');
  // Bold
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  // Headers
  html = html.replace(/^### (.+)$/gm, '<strong style="font-size:14px;color:var(--accent)">$1</strong>');
  html = html.replace(/^## (.+)$/gm, '<strong style="font-size:15px;color:var(--accent)">$1</strong>');
  html = html.replace(/^# (.+)$/gm, '<strong style="font-size:16px;color:var(--accent)">$1</strong>');
  // List items
  html = html.replace(/^- (.+)$/gm, '&bull; $1');
  html = html.replace(/^\d+\. (.+)$/gm, '<span style="color:var(--accent)">$&</span>');
  return html;
}

// Enter key sends message
document.addEventListener('keydown', function(e) {
  if (e.target.id === 'ai-input' && e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendAIMessage();
  }
});

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
      const resp = await fetch('/api/fs/cwd', { headers: authHeaders() });
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
    const resp = await fetch(authURL('/api/fs/browse?path=' + encodeURIComponent(path)));
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
