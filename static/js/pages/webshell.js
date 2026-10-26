(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }

  /* ================= WEBSHELL ================= */
  function pageWebshell() {
    $('#wp-body').html('<div class="wp-loading">Loading...</div>');
    if (!S.sites) {
      post('get_sites', {}, function (r) { S.sites = r.data || []; pageWebshell(); });
      return;
    }
    post('webshell_results', {}, function (r) {
      if (!r.status) { $('#wp-body').html('<div class="wp-note">' + esc(r.msg || 'error') + '</div>'); return; }
      var sc = r.scan || {};
      var lvl = { 3: ['High', 'var(--wp-red)'], 2: ['Medium', 'var(--wp-orange)'], 1: ['Low', 'var(--wp-blue)'] };
      var h = '<div class="wp-card">';
      h += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">' +
        '<select class="wp-in" id="ws-site" style="width:220px"><option value="">All PHP sites</option>' +
        (S.sites || []).map(function (x) { return '<option value="' + esc(x.name) + '">' + esc(x.name) + '</option>'; }).join('') +
        '</select>' +
        '<span class="wp-btn primary" id="ws-scan">' + (sc.running ? 'Scanning...' : 'Scan now') + '</span>' +
        '<span style="color:var(--wp-text3)" id="ws-state">' + wsState(sc, r) + '</span></div>';
      var files = r.files || [];
      h += '<table class="wp-tbl"><thead><tr><th style="width:70px">Risk</th><th>File</th><th style="width:140px">Site</th>' +
        '<th style="width:220px">Why</th><th style="width:140px">Modified</th><th style="width:190px">Operate</th></tr></thead><tbody>' +
        (files.length ? files.map(function (f, i) {
          var L = lvl[f.level] || lvl[1];
          return '<tr><td><span style="color:' + L[1] + ';font-weight:600">' + L[0] + '</span></td>' +
            '<td class="ell" title="' + esc(f.file) + '" style="font-family:ui-monospace,Menlo,monospace;font-size:12px">' + esc(f.file) + '</td>' +
            '<td class="ell">' + esc(f.site) + '</td>' +
            '<td class="ell" title="' + esc(f.hits.map(function (x) { return x.desc + ' (line ' + x.line + ')'; }).join('\n')) + '">' +
              esc(f.hits[0].desc) + (f.hits.length > 1 ? ' +' + (f.hits.length - 1) : '') + '</td>' +
            '<td>' + fmtTime(f.mtime) + '</td>' +
            '<td><span class="wp-lnk ws-view" data-i="' + i + '">View</span> <span style="color:var(--wp-border)">|</span> ' +
            '<span class="wp-lnk ws-quar" data-i="' + i + '" style="color:var(--wp-red)">Quarantine</span> <span style="color:var(--wp-border)">|</span> ' +
            '<span class="wp-lnk ws-ign" data-i="' + i + '">Safe</span></td></tr>';
        }).join('') : '<tr><td colspan="6" class="wp-empty">' + (r.time ? 'No suspicious files found' : 'No scan yet — click Scan now') + '</td></tr>') +
        '</tbody></table>';
      var q = r.quarantine || [];
      if (q.length) {
        h += '<div class="wp-mod-sec" style="margin-top:18px"><div class="wp-mod-sec-t">Quarantine</div>' +
          '<table class="wp-tbl"><thead><tr><th>Original path</th><th style="width:150px">Moved</th><th style="width:160px">Operate</th></tr></thead><tbody>' +
          q.map(function (x) {
            return '<tr><td class="ell" style="font-family:ui-monospace,Menlo,monospace;font-size:12px">' + esc(x.file) + '</td>' +
              '<td>' + fmtTime(x.time) + '</td><td><span class="wp-lnk ws-restore" data-id="' + esc(x.id) + '">Restore</span> ' +
              '<span style="color:var(--wp-border)">|</span> <span class="wp-lnk ws-purge" data-id="' + esc(x.id) + '" style="color:var(--wp-red)">Delete</span></td></tr>';
          }).join('') + '</tbody></table></div>';
      }
      h += '<ul class="wp-notes">' +
        '<li>Static signatures only — files are read, never executed. A hit is a lead to check, not a verdict.</li>' +
        '<li><b>Quarantine</b> moves the file out of the web root (restorable). <b>Safe</b> hides it until its content changes.</li>' +
        '<li>Scans every PHP site by default; pick a site to scan just that one (any project type).</li></ul></div>';
      $('#wp-body').html(h);

      $('#ws-scan').on('click', function () {
        post('webshell_scan', { siteName: $('#ws-site').val() || '' }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) pollWebshell();
        });
      });
      $('.ws-view').on('click', function () {
        var f = files[$(this).data('i')];
        post('webshell_view', { file: f.file }, function (rr) {
          if (!rr.status) return layer.msg(rr.msg, { icon: 2 });
          W.open({ type: 1, title: esc(f.file), area: ['900px', '600px'],
            content: '<div style="padding:14px"><div style="margin-bottom:10px;font-size:12px">' +
              f.hits.map(function (x) { return '<div><b>' + esc(x.desc) + '</b> — line ' + x.line + '</div>'; }).join('') +
              '</div><pre style="white-space:pre-wrap;word-break:break-all;font-size:12px;background:#f7f8fa;padding:12px;border-radius:6px;max-height:460px;overflow:auto">' +
              esc(rr.body) + (rr.truncated ? '\n… (truncated)' : '') + '</pre></div>' });
        });
      });
      $('.ws-quar').on('click', function () {
        var f = files[$(this).data('i')];
        W.confirm('Move ' + esc(f.file) + ' to quarantine? The site loses this file until restored.', { title: 'Quarantine' }, function (i) {
          layer.close(i);
          post('webshell_quarantine', { file: f.file }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) pageWebshell(); });
        });
      });
      $('.ws-ign').on('click', function () {
        post('webshell_ignore', { file: files[$(this).data('i')].file }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) pageWebshell(); });
      });
      $('.ws-restore').on('click', function () {
        post('webshell_restore', { id: $(this).data('id') }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) pageWebshell(); });
      });
      $('.ws-purge').on('click', function () {
        var id = $(this).data('id');
        W.confirm('Delete this file permanently? This cannot be undone.', { title: 'Delete' }, function (i) {
          layer.close(i);
          post('webshell_delete', { id: id }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) pageWebshell(); });
        });
      });
      if (sc.running) pollWebshell();
    });
  }
  function wsState(sc, r) {
    if (sc.running) return 'Scanned ' + num(sc.scanned) + ' files, ' + num(sc.found) + ' suspicious so far...';
    if (sc.error) return '<span style="color:var(--wp-red)">' + esc(sc.error) + '</span>';
    if (r && r.time) return 'Last scan ' + fmtTime(r.time) + ' — ' + num(r.scanned) + ' files checked';
    return '';
  }
  function pollWebshell() {
    if (S.timer) clearInterval(S.timer);
    S.timer = setInterval(function () {
      if (S.tab !== 'webshell') { clearInterval(S.timer); S.timer = null; return; }
      post('webshell_status', {}, function (r) {
        var sc = r.scan || {};
        $('#ws-state').html(wsState(sc));
        if (!sc.running) { clearInterval(S.timer); S.timer = null; pageWebshell(); }
      });
    }, 2000);
  }
  function fmtTime(t) {
    if (!t) return '-';
    var d = new Date(t * 1000), p = function (x) { return (x < 10 ? '0' : '') + x; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }


  // exports
  W.fmtTime = fmtTime;
  W.pageWebshell = pageWebshell;
  W.pollWebshell = pollWebshell;
  W.wsState = wsState;
})(window.WAFPRO = window.WAFPRO || {});
