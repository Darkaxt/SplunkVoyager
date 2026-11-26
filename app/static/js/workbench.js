/* Investigations GUI */
const WB = (() => {
  const $ = s => document.querySelector(s);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  async function api(url, body, method) {
    const opt = body === undefined ? {method: method || 'GET'} :
      {method: method || 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)};
    const r = await fetch(url, opt);
    const ct = r.headers.get('content-type') || '';
    const data = ct.includes('json') ? await r.json() : await r.text();
    if (!r.ok) throw new Error((data && data.message) || `HTTP ${r.status}`);
    return data;
  }
  const fmt = t => t ? String(t).replace('T', ' ') : '';
  const badge = s => `<span class="badge ${esc(s)}">${esc(s)}</span>`;

  // ---------------------------------------------------------------- list page
  function listPage() {
    async function load() {
      const list = await api('/api/inv');
      $('#inv-list').innerHTML = list.length ? list.map(i => `
        <a class="card2" href="/investigations/${esc(i.slug)}">
          <div style="font-weight:600;font-size:15px">${esc(i.name)}</div>
          <div class="mono muted" style="margin-top:4px">${esc(i.earliest)} → ${esc(i.latest)}${i.instance ? ' · ' + esc(i.instance) : ''}</div>
          <div class="sub" style="margin-top:6px">${i.jobs_total} job${i.jobs_total === 1 ? '' : 's'}${i.jobs_running ? ` · <span style="color:#8cc8f5">${i.jobs_running} running</span>` : ''} · created ${esc(fmt(i.created))}</div>
          ${i.notes ? `<div class="sub" style="margin-top:4px">${esc(i.notes)}</div>` : ''}
        </a>`).join('') : '<div class="empty">None yet.</div>';
    }
    $('#n-create').onclick = async () => {
      $('#n-err').textContent = '';
      try {
        const inv = await api('/api/inv', {name: $('#n-name').value, earliest: $('#n-earliest').value,
          latest: $('#n-latest').value, notes: $('#n-notes').value, instance: $('#n-inst') ? $('#n-inst').value : ''});
        location.href = `/investigations/${inv.slug}`;
      } catch (e) { $('#n-err').textContent = e.message; }
    };
    load();
  }

  // ---------------------------------------------------------------- settings page
  function settingsPage(instances, def) {
    const tbl = $('#inst-table');
    const row = (i = {}) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><input type="radio" name="inst-def"></td>
        <td><input type="text" class="i-name" placeholder="(from the URL)" value="${esc(i.name || '')}"></td>
        <td><input type="text" class="i-base" placeholder="https://splunk.example.com" value="${esc(i.base || '')}"></td>
        <td style="width:90px"><input type="text" class="i-locale" placeholder="en-US" value="${esc(i.locale || '')}"></td>
        <td><input type="text" class="i-app" placeholder="(default app)" value="${esc(i.app || '')}"></td>
        <td><button class="danger i-del" title="Remove">✕</button></td>`;
      tr.querySelector('input[type=radio]').checked = !!i.name && i.name === def;
      tr.querySelector('.i-del').onclick = () => tr.remove();
      tbl.appendChild(tr);
    };
    (instances.length ? instances : [{}]).forEach(row);
    if (!tbl.querySelector('input[type=radio]:checked')) tbl.querySelector('input[type=radio]').checked = true;
    $('#inst-add').onclick = () => row();
    $('#s-save').onclick = async () => {
      $('#s-msg').textContent = '';
      const rows = [...tbl.querySelectorAll('tr')].slice(1);
      const insts = rows.map(r => ({name: r.querySelector('.i-name').value, base: r.querySelector('.i-base').value,
        locale: r.querySelector('.i-locale').value, app: r.querySelector('.i-app').value}));
      const di = rows.findIndex(r => r.querySelector('input[type=radio]').checked);
      try {
        const s = await api('/api/settings', {instances: insts, max_jobs: $('#s-max').value, voyager_url: $('#s-vurl').value,
          default_instance: di >= 0 ? (insts[di].name.trim() || '') : ''});
        // names are filled in from the URL when left empty: pick the default again by position
        if (di >= 0 && !insts[di].name.trim() && s.instances[di])
          await api('/api/settings', {default_instance: s.instances[di].name});
        $('#s-msg').textContent = 'Saved. Reinstall the userscript if you added or changed a URL.';
        tbl.querySelectorAll('tr').forEach((r, k) => { if (k && s.instances[k - 1]) r.querySelector('.i-name').value = s.instances[k - 1].name; });
      } catch (e) { $('#s-msg').textContent = e.message; }
    };
  }

  // ---------------------------------------------------------------- investigation page
  function invPage(slug) {
    const base = `/api/inv/${slug}`;
    const openLogs = new Set();
    let last = null;

    $('#inv-delete').onclick = async () => {
      if (!confirm('Delete this investigation? Its jobs are stopped and all its exports, reports and graphs are removed. This cannot be undone.')) return;
      $('#inv-delete').disabled = true;
      try { await api(base, {}, 'DELETE'); location.href = '/investigations'; }
      catch (e) { alert(e.message); $('#inv-delete').disabled = false; }
    };

    // range editor
    $('#edit-range').onclick = e => { e.preventDefault(); $('#range-editor').style.display = ''; };
    $('#r-cancel').onclick = () => { $('#range-editor').style.display = 'none'; };
    $('#r-save').onclick = async () => {
      const inv = await api(base, {earliest: $('#r-earliest').value, latest: $('#r-latest').value}, 'PATCH');
      $('#inv-range').textContent = `${inv.earliest} → ${inv.latest}`;
      ['#na-earliest', '#na-latest', '#em-earliest', '#em-latest'].forEach((s, i) =>
        $(s).placeholder = i % 2 ? inv.latest : inv.earliest);
      $('#range-editor').style.display = 'none';
    };

    // network analysis form
    const naFields = () => Object.fromEntries([...document.querySelectorAll('.na-f')].map(i => [i.dataset.k, i.value.trim()]));
    const naBody = () => ({base: $('#na-base').value, extract: $('#na-extract').value, fields: naFields(),
      earliest: $('#na-earliest').value.trim(), latest: $('#na-latest').value.trim(), chunk: $('#na-chunk').value,
      title: $('#na-title').value});
    let tPrev;
    const preview = () => { clearTimeout(tPrev); tPrev = setTimeout(async () => {
      if (!$('#na-base').value.trim()) { $('#na-spl').textContent = '-'; return; }
      try { $('#na-spl').textContent = (await api('/api/network/preview', naBody())).spl; }
      catch (e) { $('#na-spl').textContent = e.message; }
    }, 250); };
    ['#na-base', '#na-extract'].forEach(s => $(s).addEventListener('input', preview));
    document.querySelectorAll('.na-f').forEach(i => i.addEventListener('input', preview));
    $('#na-run').onclick = async () => {
      $('#na-err').textContent = '';
      $('#na-run').disabled = true;
      try { await api(`${base}/network`, naBody()); refresh(); }
      catch (e) { $('#na-err').textContent = e.message; }
      finally { $('#na-run').disabled = false; }
    };

    // entity mapper form
    const emOpts = () => ({earliest: $('#em-earliest').value.trim(), latest: $('#em-latest').value.trim(),
      include: $('#em-include').value, max_events: $('#em-max').value, bin: $('#em-bin').value, group: $('#em-group').value,
      reset_range: $('#em-reset').checked});
    async function mapValues(values, btn) {
      $('#em-err').textContent = '';
      if (btn) btn.disabled = true;
      try { await api(`${base}/entities`, {values, ...emOpts()}); refresh(); if (btn) btn.textContent = 'queued'; }
      catch (e) { $('#em-err').textContent = e.message; if (btn) { btn.disabled = false; } }
    }
    $('#em-run').onclick = () => mapValues($('#em-values').value.split('\n').map(s => s.trim()).filter(Boolean), $('#em-run'))
      .then(() => { $('#em-run').disabled = false; $('#em-run').textContent = 'Search and map'; $('#em-values').value = ''; });
    $('#em-rebuild').onclick = async () => {
      $('#em-err').textContent = '';
      try { await api(`${base}/entities/build`, {bin: $('#em-bin').value, group: $('#em-group').value}); refresh(); }
      catch (e) { $('#em-err').textContent = e.message; }
    };

    // findings
    function findingsHtml(inv) {
      const mapped = new Set((inv.entities.seeds || []).map(s => s.value.toLowerCase()));
      const runs = inv.network.filter(n => n.findings || n.report);
      if (!runs.length) return `<div class="empty">${inv.network.length ? 'Waiting for the network analysis to finish.' : 'Run a network analysis to see attack sources and callbacks here.'}</div>`;
      return runs.map(n => {
        const f = n.findings || {};
        const cats = Object.entries(f.categories || {}).filter(([k, v]) => v && !['not_attack', 'undetermined'].includes(k));
        const mapBtn = v => mapped.has(String(v).toLowerCase()) ? '<span class="muted">mapped</span>' :
          `<button data-map="${esc(v)}">Map</button>`;
        const chk = v => mapped.has(String(v).toLowerCase()) ? '' : `<input type="checkbox" class="sel" value="${esc(v)}">`;
        const src = (f.sources || []).slice(0, 50), cb = (f.callbacks || []).slice(0, 50);
        return `<div class="nrun" style="margin-bottom:18px">
          <div class="toolbar"><div><b>${esc(n.title)}</b> ${badge(n.status)}
            ${cats.map(([k, v]) => `<span class="badge cat">${esc(k)} ${v}</span>`).join('')}</div>
            <div>${n.report ? `<a class="b" target="_blank" href="/inv/${slug}/files/${esc(n.report)}">Open report</a>` : ''}
              ${n.can_reanalyse ? `<button data-reanalyse="${esc(n.job)}" title="Run Payload Analyzer again on this export (after updating it). Splunk isn't queried.">Re-analyse</button>` : ''}
              <button class="map-sel">Map selected</button></div></div>
          <div class="grid2" style="margin-top:6px">
            <div><h3>Attack sources (${(f.sources || []).length})</h3>
              ${src.length ? `<table class="t"><tr><th></th><th>Address</th><th class="right">Requests</th><th>Categories</th><th>Active</th><th></th></tr>
              ${src.map(s => `<tr><td>${chk(s.value)}</td><td class="mono">${esc(s.value)}</td><td class="right">${s.requests.toLocaleString()}</td>
                <td>${s.categories.map(c => `<span class="badge cat">${esc(c)}</span>`).join('')}</td>
                <td class="mono nowrap muted">${esc(s.first || '')}${s.last && s.last !== s.first ? '<br>' + esc(s.last) : ''}</td><td>${mapBtn(s.value)}</td></tr>`).join('')}</table>` : '<div class="empty">None.</div>'}</div>
            <div><h3>Callbacks and embedded hosts (${(f.callbacks || []).length})</h3>
              ${cb.length ? `<table class="t"><tr><th></th><th>Value</th><th>Kind</th><th>Categories</th><th></th></tr>
              ${cb.map(c => `<tr><td>${chk(c.value)}</td><td class="mono ellip" title="${esc(c.value)}">${esc(c.value)}</td>
                <td class="muted">${esc(c.kind)}${c.internal ? ' · internal' : ''}</td>
                <td>${c.categories.map(x => `<span class="badge cat">${esc(x)}</span>`).join('')}</td><td>${mapBtn(c.value)}</td></tr>`).join('')}</table>` : '<div class="empty">None.</div>'}</div>
          </div></div>`;
      }).join('');
    }
    $('#nf').addEventListener('click', async e => {
      const ra = e.target.closest('[data-reanalyse]');
      if (ra) {
        ra.disabled = true;
        try { await api(`${base}/network/${ra.dataset.reanalyse}/reanalyze`, {}); refresh(); }
        catch (err) { alert(err.message); ra.disabled = false; }
        return;
      }
      const b = e.target.closest('[data-map]');
      if (b) return mapValues([b.dataset.map], b);
      const s = e.target.closest('.map-sel');
      if (s) {
        const vals = [...s.closest('.nrun').querySelectorAll('.sel:checked')].map(c => c.value);
        if (vals.length) mapValues(vals, s);
      }
    });

    // entity state
    function entityHtml(inv) {
      const e = inv.entities;
      let h = e.seeds.length ? e.seeds.map(s => `<span class="pill mono" title="searched ${esc(s.earliest)} → ${esc(s.latest || 'now')}">${esc(s.value)}
        <span class="muted">${esc(s.earliest)} → ${esc(s.latest || 'now')}</span></span>`).join('') : '<div class="empty">Nothing yet.</div>';
      if (e.graph) h += `<div class="actions" style="margin-top:6px"><a class="b" target="_blank" href="/inv/${slug}/files/${esc(e.graph)}">Open graph</a>
        ${e.csv ? `<a class="b" href="/inv/${slug}/files/${esc(e.csv)}">All entities (CSV)</a>` : ''}</div>`;
      $('#em-rebuild').disabled = !e.seeds.length;
      return h;
    }

    // jobs
    function jobsHtml(inv) {
      if (!inv.jobs.length) return '<div class="empty">No jobs yet.</div>';
      return `<table class="t"><tr><th>Job</th><th>Status</th><th>Step</th><th>Started</th><th>Ended</th><th></th></tr>` +
        inv.jobs.map(j => {
          const running = ['running', 'waiting', 'queued'].includes(j.status);
          const stepName = j.steps[Math.min(j.step, j.steps.length - 1)] || '';
          const pr = j.progress ? `<div class="bar"><i style="width:${(100 * j.progress.done / j.progress.total).toFixed(1)}%"></i></div>
            <div class="muted" style="font-size:11.5px">${j.progress.done}/${j.progress.total} Splunk windows</div>` : '';
          return `<tr><td><b>${esc(j.title)}</b><div class="muted mono" style="font-size:11.5px">${esc(j.kind)} · ${esc(j.id)}</div>
              ${j.error ? `<div class="err">${esc(j.error)}</div>` : ''}</td>
            <td>${badge(j.status)}</td>
            <td>${j.status === 'done' ? `<span class="muted">${j.steps.length} steps</span>` : `${Math.min(j.step + 1, j.steps.length)}/${j.steps.length} ${esc(stepName)}`}${pr}</td>
            <td class="mono nowrap muted">${esc(fmt(j.started))}</td><td class="mono nowrap muted">${esc(fmt(j.ended))}</td>
            <td class="nowrap">
              ${running ? `<button class="danger" data-act="stop" data-j="${esc(j.id)}">Stop</button>` : ''}
              ${['failed', 'interrupted', 'stopped'].includes(j.status) ? `<button data-act="resume" data-j="${esc(j.id)}">Resume</button>` : ''}
              <button data-log="${esc(j.id)}">${openLogs.has(j.id) ? 'Hide log' : 'Log'}</button>
              ${!running ? `<button class="danger" data-act="delete" data-j="${esc(j.id)}" title="Remove this job and its network results">✕</button>` : ''}
            </td></tr>
            ${openLogs.has(j.id) ? `<tr><td colspan="6"><pre class="log" id="log-${esc(j.id)}">${esc(j.log || '')}</pre></td></tr>` : ''}`;
        }).join('') + '</table>';
    }
    $('#jobs').addEventListener('click', async e => {
      const l = e.target.closest('[data-log]');
      if (l) { openLogs.has(l.dataset.log) ? openLogs.delete(l.dataset.log) : openLogs.add(l.dataset.log); render(last); return; }
      const a = e.target.closest('[data-act]');
      if (!a) return;
      if (a.dataset.act === 'delete' && !confirm('Remove this job and its results?')) return;
      a.disabled = true;
      try { await api(`${base}/jobs/${a.dataset.j}/${a.dataset.act}`, {}); } catch (err) { alert(err.message); }
      refresh();
    });

    function render(inv) {
      if (!inv) return;
      last = inv;
      // keep log scroll positions
      const scroll = {};
      document.querySelectorAll('pre.log').forEach(p => { scroll[p.id] = [p.scrollTop, p.scrollHeight - p.clientHeight - p.scrollTop < 20]; });
      $('#em-state').innerHTML = entityHtml(inv);
      const sel = new Set([...document.querySelectorAll('#nf .sel:checked')].map(c => c.value));
      $('#nf').innerHTML = findingsHtml(inv);
      document.querySelectorAll('#nf .sel').forEach(c => { if (sel.has(c.value)) c.checked = true; });
      $('#nf-sub').textContent = inv.network.length ? `${inv.network.length} run${inv.network.length > 1 ? 's' : ''}` : '';
      $('#jobs').innerHTML = jobsHtml(inv);
      document.querySelectorAll('pre.log').forEach(p => {
        const s = scroll[p.id];
        p.scrollTop = !s || s[1] ? p.scrollHeight : s[0];
      });
    }
    let busy = false;
    async function refresh() {
      if (busy) return;
      busy = true;
      try {
        const inv = await api(base);
        // full logs for the open ones
        await Promise.all(inv.jobs.filter(j => openLogs.has(j.id)).map(async j => { j.log = await api(`${base}/jobs/${j.id}/log?tail=400`); }));
        render(inv);
      } catch (e) { /* keep last view */ }
      finally { busy = false; }
    }
    refresh();
    setInterval(refresh, 3000);
  }

  return {listPage, invPage, settingsPage};
})();
