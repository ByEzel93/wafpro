(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function applyGSub() { return W.applyGSub.apply(this, arguments); }
  function esc() { return W.esc.apply(this, arguments); }
  function icoWarn() { return W.icoWarn.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }
  function row() { return W.row.apply(this, arguments); }
  function statusSel() { return W.statusSel.apply(this, arguments); }
  function sw() { return W.sw.apply(this, arguments); }

  function pageGlobal() {
    $('#wp-body').html('<div class="wp-loading">Loading...</div>');
    post('get_config', {}, function (c) {
      if (!c.status) { $('#wp-body').html('<div class="wp-note">' + esc(c.msg || 'error') + '</div>'); return; }
      post('get_methods', {}, function (m) {
        post('get_hdr_limits', {}, function (hl) {
          post('spider_status', {}, function (sp) {
            post('malicious_status', {}, function (ml) {
              post('list_get', { list_name: 'sensitive' }, function (senList) {
                post('idc_status', {}, function (idc) {
                  S.idcStatus = idc;
                  renderGlobal(c, m, hl, sp, ml, senList);
                });
              });
            });
          });
        });
      });
    });
  }

  // one grouped card: shown only when its sub-tab (or All) is active
  function gcard(group, ico, title, inner) {
    return '<div class="wp-gc" data-g="' + group + '">' +
      '<div class="wp-card" style="max-width:820px;margin-top:14px"><div class="wp-card-h">' +
      ico + '<span class="t">' + title + '</span></div>' + inner + '</div></div>';
  }

  // section header + feature cards, so each setting reads as its own row
  function gsec(group, text) {
    return '<div class="wp-gc" data-g="' + group + '"><div class="wp-gsec">' + text + '</div></div>';
  }
  function fcard(group, title, desc, controls, body, hero) {
    var head = '<div style="display:flex;align-items:center;gap:20px">' +
      '<div class="wp-fc-l"><div class="wp-fc-t">' + title + '</div>' +
      (desc ? '<div class="wp-fc-d">' + desc + '</div>' : '') + '</div>' +
      '<div class="wp-fc-r">' + (controls || '') + '</div></div>';
    return '<div class="wp-gc" data-g="' + group + '">' +
      '<div class="wp-fc' + (hero ? ' hero' : '') + (body ? ' wp-fc-col' : '') + '">' +
      head + (body ? '<div class="wp-fc-body">' + body + '</div>' : '') + '</div></div>';
  }

  function renderGlobal(c, m, hl, sp, ml, senList) {
    var e = c.engine || {};
    S.gSub = S.gSub || 'all';
    var SUBS = [['all', 'All'], ['cc', 'CC defense'], ['access', 'Access filter'],
                ['vuln', 'Website vulnerability defense'], ['sensitive', 'Sensitive words']];

    var h = '<div class="wp-subtabs" id="g-subs">' + SUBS.map(function (x) {
      return '<span class="wp-subtab' + (x[0] === S.gSub ? ' on' : '') + '" data-g="' + x[0] + '">' + x[1] + '</span>';
    }).join('') + '</div>';
    h += '<div id="g-cards" style="max-width:1080px">';

    if (!e.wired) {
      h += '<div class="wp-gc" data-g="all"><div class="wp-note" style="margin-top:12px">' + icoWarn() +
        ' The engine is not wired into nginx, so nothing here is enforced yet.</div></div>';
    }

    /* ===== Global ===== */
    h += gsec('all', 'Global');
    h += fcard('all', 'Protection switch', 'All protection is off when this switch is off.',
      sw('g-open', c.open) +
      '<span class="wp-btn" id="g-export">Export</span>' +
      '<span class="wp-btn" id="g-import">Import</span>' +
      '<span class="wp-btn" id="g-restore">Restore defaults</span>', '', true);
    h += fcard('all', 'Engine wired into nginx',
      'Installs our lua into nginx. Tested before apply, rolled back on failure.',
      sw('g-wired', e.wired));
    h += fcard('all', 'Engine status', engineStatusText(e, c.health),
      (e.installed && !e.current
        ? '<span class="wp-btn primary" id="g-engine-update">Update engine</span>' : '') +
      '<span class="wp-btn" id="g-selftest">Simulated attack</span>');

    /* ===== CC defense ===== */
    h += gsec('cc', 'CC defense');
    h += fcard('cc', 'Request defence (auto-ban)',
      'An IP that trips too many rules is blocked outright for a while. Banned IPs show under Blockade.',
      '<span class="wp-btn" id="g-save-ab">Set rule</span>',
      '<div style="display:flex;flex-wrap:wrap;gap:16px;align-items:center">' +
        '<span>Ban after <input class="wp-in" id="g-retry" type="number" style="width:70px" value="' + (c.retry || 0) +
        '"> trips within <input class="wp-in" id="g-retry-cycle" type="number" style="width:70px" value="' + (c.retry_cycle || 60) + '"> s</span>' +
        '<span>Ban duration <input class="wp-in" id="g-retry-time" type="number" style="width:80px" value="' + (c.retry_time || 600) + '"> s</span>' +
      '</div>');
    h += fcard('cc', 'Static file protection',
      'CC does not count static files (JS, CSS, images, fonts) by default — a page pulls many. Turn on only if static traffic is being abused.',
      sw('g-static', c.static_protect));
    var mhave = ml && ml.have;
    h += fcard('cc', 'Malicious IP feed',
      'Public abuse feeds (botnets, repeat attackers). When on, blocked on every site. ' +
      (mhave ? num(ml.count) + ' ranges, updated ' + esc(ml.updated) : '<span style="color:var(--wp-red)">not downloaded</span>'),
      sw('g-mal', ml && ml.open) + '<span class="wp-btn" id="g-mal-update">' + (mhave ? 'Synchronize' : 'Download') + '</span>');
    var idc = S.idcStatus || {};
    h += fcard('cc', 'Datacenter (IDC) IPs',
      'Cloud provider address space for the per-site IDC interception switch. ' +
      (idc.have ? num(idc.count) + ' ranges from ' + esc((idc.sources || []).join(', ')) + ', updated ' + esc(idc.updated)
                : '<span style="color:var(--wp-red)">not downloaded — IDC interception does nothing</span>'),
      '<span class="wp-btn" id="g-idc">' + (idc.have ? 'Synchronize' : 'Download') + '</span>');
    h += fcard('cc', 'Escalating bans',
      'An IP banned again within a day is banned for longer each time (ban time &times; times banned, up to 24 hours).',
      sw('g-escalate', c.ban_escalate !== false));
    var have = sp && sp.have;
    h += fcard('cc', 'Verified crawlers',
      'Backs the Fake spider switch on each site. ' +
      (have ? '<b>' + num(sp.count) + '</b> ranges from ' + esc((sp.sources || []).join(', ')) + ', updated ' + esc(sp.updated)
            : '<span style="color:var(--wp-red)">not downloaded — Fake spider does nothing</span>'),
      '<span class="wp-btn" id="g-spider">' + (have ? 'Synchronize' : 'Download') + '</span>');

    /* ===== Access filter ===== */
    h += gsec('access', 'Access filter');
    h += fcard('access', 'Logging', 'Write blocks to /www/wwwlogs/wafpro/.',
      'Keep <input class="wp-in" id="g-logsave" type="number" style="width:64px" value="' + (c.log_save || 30) + '"> days' +
      sw('g-log', c.log) + '<span class="wp-btn" id="g-save-log">Save</span>');
    h += fcard('access', 'Behind CDN',
      'Read the visitor IP from X-Forwarded-For. Only if a proxy really sits in front — otherwise IPs can be spoofed.',
      sw('g-cdn', c.cdn));
    var allM = (m && m.all) || [];
    var onM = {}; ((m && m.data) || []).forEach(function (x) { onM[x] = 1; });
    h += fcard('access', 'Allowed HTTP methods', 'Anything unchecked is refused. GET cannot be turned off.',
      '<span class="wp-btn primary" id="g-save-m">Save</span>',
      '<div style="display:flex;flex-wrap:wrap;gap:16px">' + allM.map(function (x) {
        return '<label style="display:flex;align-items:center;gap:6px;cursor:pointer">' +
          '<input type="checkbox" class="g-m" value="' + x + '"' + (onM[x] ? ' checked' : '') +
          (x === 'GET' ? ' disabled' : '') + '>' + x + '</label>';
      }).join('') + '</div>');
    h += fcard('access', 'Request shape limits',
      'Parameter and header floods: no real client sends thousands of fields.',
      '<span class="wp-btn primary" id="g-save-shape">Save</span>',
      '<div style="display:flex;flex-wrap:wrap;gap:20px">' +
        '<label style="display:flex;align-items:center;gap:8px">Max parameters (query or form)' +
        '<input class="wp-in" id="g-max-params" type="number" style="width:90px" value="' + (c.max_params || 8000) + '"></label>' +
        '<label style="display:flex;align-items:center;gap:8px">Max headers' +
        '<input class="wp-in" id="g-max-headers" type="number" style="width:90px" value="' + (c.max_headers || 800) + '"></label>' +
      '</div>');
    var lims = (hl && hl.data) || [];
    h += fcard('access', 'Header size limits', 'Requests with a header longer than this are refused.',
      '<span class="wp-btn primary" id="g-save-h">Save</span>',
      '<div style="display:flex;flex-wrap:wrap;gap:20px">' + lims.map(function (x) {
        return '<label style="display:flex;align-items:center;gap:8px">' + esc(x.h) +
          '<input class="wp-in g-h" data-h="' + esc(x.h) + '" type="number" style="width:90px" value="' + x.max + '"> B</label>';
      }).join('') + '</div>');

    /* ===== Website vulnerability defense ===== */
    h += gsec('vuln', 'Website vulnerability defense');
    var rcRow = function (id, label, val) {
      return '<label style="display:flex;align-items:center;gap:8px">' +
        '<span style="width:130px;color:var(--wp-text2)">' + label + '</span>' + statusSel(id, val) + '</label>';
    };
    h += fcard('vuln', 'Response codes', 'What blocked visitors receive, per protection type.',
      '<span class="wp-btn primary" id="g-save">Save</span>',
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px 30px">' +
        rcRow('g-s-get', 'SQL/XSS query', c.get_status) + rcRow('g-s-post', 'SQL/XSS body', c.post_status) +
        rcRow('g-s-cookie', 'Cookie', c.cookie_status) + rcRow('g-s-ua', 'User-Agent', c.ua_status) +
        rcRow('g-s-scan', 'Scanner paths', c.scan_status) + rcRow('g-s-cc', 'CC defense', c.cc_status) +
        rcRow('g-s-black', 'Blacklist / ban', c.black_status) + rcRow('g-s-method', 'Bad method', c.method_status) +
        rcRow('g-s-header', 'Oversized header', c.header_status) +
        rcRow('g-s-php2shell', 'PHP2Shell / form-data', c.php2shell_status) +
        rcRow('g-s-custom', 'Custom rule (block)', c.custom_status) +
      '</div>');
    var mpIn = function (id, label, val, unit) {
      return '<label style="display:flex;align-items:center;gap:8px"><span style="width:170px;color:var(--wp-text2)">' + label +
        '</span><input class="wp-in" id="' + id + '" type="number" min="1" style="width:90px" value="' + val + '"> ' +
        '<span class="wp-unit">' + (unit || '') + '</span></label>';
    };
    h += fcard('vuln', 'PHP2Shell guard limits',
      'CVE-2026-109618 / 109619 are reached through PHP&apos;s multipart parser. These bounds apply on every site ' +
      'with the PHP2Shell guard on (WebSite &rsaquo; Modify). <b>Updating PHP is the only complete fix</b> — ' +
      'the Simulated attack check lists any unpatched PHP on this server.',
      '<span class="wp-btn primary" id="g-save-mp">Save</span>',
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px 30px">' +
        mpIn('g-mp-parts', 'Max parts per request', c.mp_max_parts || 500) +
        mpIn('g-mp-headers', 'Max headers per part', c.mp_max_headers || 16) +
        mpIn('g-mp-depth', 'Max field nesting a[b][c]', c.mp_max_depth || 10, 'levels') +
        mpIn('g-mp-empty', 'Max empty file fields', c.mp_max_empty || 50) +
      '</div>');
    h += fcard('vuln', 'Filter rule sets',
      'The regular expressions behind the GET / POST / Cookie / User-Agent / Scanner filters and the N-day virtual patches. ' +
      'Turn single rules off when one misfires on your site, or add your own.',
      '<span class="wp-btn primary" id="g-rulesets">Edit rules</span>');
    h += fcard('vuln', 'Block &amp; verification pages',
      'The page a blocked visitor sees (for 4xx responses; 444 just closes the connection), and the browser check page.',
      sw('g-blockpage', c.block_page !== false) +
      '<span class="wp-btn" id="g-edit-block">Edit block page</span>' +
      '<span class="wp-btn" id="g-edit-challenge">Edit check page</span>');

    /* ===== Sensitive words ===== */
    h += gsec('sensitive', 'Sensitive words');
    var words = (senList && senList.data) || [];
    h += fcard('sensitive', 'Sensitive words',
      'A request is blocked if any appears in its URL, query string or form body. Plain text or regex.',
      '', '<div style="display:flex;gap:8px;margin-bottom:12px">' +
        '<input class="wp-in" id="g-sen-in" placeholder="word or regex, e.g. (?i)union\\s+select" style="flex:1">' +
        '<span class="wp-btn primary" id="g-sen-add">Add</span></div>' +
      '<table class="wp-tbl"><thead><tr><th>Word / pattern</th><th style="width:80px">Operate</th></tr></thead><tbody>' +
      (words.length ? words.map(function (x) {
        return '<tr><td style="font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all">' + esc(x.value) + '</td>' +
          '<td><a href="javascript:;" class="g-sen-del" data-i="' + x.index + '" style="color:var(--wp-green)">Delete</a></td></tr>';
      }).join('') : '<tr><td colspan="2" style="padding:20px;text-align:center;color:var(--wp-text3)">No sensitive words yet.</td></tr>') +
      '</tbody></table>');

    h += '</div>';
    $('#wp-body').html(h);
    applyGSub();

    $('#g-subs .wp-subtab').on('click', function () {
      S.gSub = $(this).data('g');
      $('#g-subs .wp-subtab').removeClass('on'); $(this).addClass('on');
      applyGSub();
    });

    /* ---- handlers ---- */
    function wire(on) { post('engine_wire', { open: on ? 1 : 0 }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); route(); }); }
    $('#g-wired').on('change', function () { wire($(this).is(':checked')); });
    function saveCore(extra) {
      var cfg = { open: $('#g-open').is(':checked'), log: $('#g-log').is(':checked'),
        log_save: parseInt($('#g-logsave').val() || 30, 10), cdn: $('#g-cdn').is(':checked'),
        static_protect: $('#g-static').is(':checked') };
      post('save_config', { config: JSON.stringify($.extend(cfg, extra || {})) },
        function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); });
    }
    $('#g-open,#g-cdn,#g-static').on('change', function () { saveCore(); });
    $('#g-save-log').on('click', function () { saveCore(); });
    $('#g-save-ab').on('click', function () {
      saveCore({ retry: parseInt($('#g-retry').val() || 0, 10),
                 retry_cycle: parseInt($('#g-retry-cycle').val() || 60, 10),
                 retry_time: parseInt($('#g-retry-time').val() || 600, 10) });
    });
    $('#g-save').on('click', function () {
      saveCore({ get_status: +$('#g-s-get').val(), post_status: +$('#g-s-post').val(),
        cookie_status: +$('#g-s-cookie').val(), ua_status: +$('#g-s-ua').val(),
        scan_status: +$('#g-s-scan').val(), cc_status: +$('#g-s-cc').val(),
        black_status: +$('#g-s-black').val(), method_status: +$('#g-s-method').val(),
        header_status: +$('#g-s-header').val(), php2shell_status: +$('#g-s-php2shell').val(),
        custom_status: +$('#g-s-custom').val() });
    });
    $('#g-save-mp').on('click', function () {
      saveCore({ mp_max_parts: +$('#g-mp-parts').val(), mp_max_headers: +$('#g-mp-headers').val(),
                 mp_max_depth: +$('#g-mp-depth').val(), mp_max_empty: +$('#g-mp-empty').val() });
    });
    $('#g-blockpage').on('change', function () { saveCore({ block_page: $(this).is(':checked') }); });
    $('#g-edit-block').on('click', function () { pageEditor('block'); });
    $('#g-edit-challenge').on('click', function () { pageEditor('challenge'); });
    $('#g-selftest').on('click', function () { selfTestDialog(''); });
    $('#g-rulesets').on('click', function () { ruleSetDialog('get'); });
    $('#g-escalate').on('change', function () { saveCore({ ban_escalate: $(this).is(':checked') }); });
    $('#g-save-shape').on('click', function () {
      saveCore({ max_params: +$('#g-max-params').val(), max_headers: +$('#g-max-headers').val() });
    });
    $('#g-idc').on('click', function () {
      var $b = $(this).text('...');
      post('idc_update', {}, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) route(); else $b.text('Synchronize'); });
    });
    $('#g-engine-update').on('click', function () {
      var ld = layer.msg('Updating engine...', { icon: 16, time: 0, shade: 0.3 });
      post('engine_update', {}, function (rr) { layer.close(ld); layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); route(); });
    });
    $('#g-save-m').on('click', function () {
      var ms = ['GET'];
      $('.g-m:checked').each(function () { if (this.value !== 'GET') ms.push(this.value); });
      post('save_methods', { methods: JSON.stringify(ms) }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); });
    });
    $('#g-save-h').on('click', function () {
      var out = [];
      $('.g-h').each(function () { out.push({ h: $(this).data('h'), max: parseInt($(this).val() || 0, 10) }); });
      post('save_hdr_limits', { limits: JSON.stringify(out) }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); });
    });
    $('#g-mal').on('change', function () {
      var on = $(this).is(':checked');
      post('malicious_toggle', { open: on ? 1 : 0 }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (!rr.status) $('#g-mal').prop('checked', !on); });
    });
    $('#g-mal-update').on('click', function () { var $b = $(this).text('...'); post('malicious_update', {}, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) route(); else $b.text('Synchronize'); }); });
    $('#g-spider').on('click', function () { var $b = $(this).text('...'); post('spider_update', {}, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) route(); else $b.text('Synchronize'); }); });

    function senAdd() {
      var v = ($('#g-sen-in').val() || '').trim(); if (!v) return;
      post('list_add', { list_name: 'sensitive', value: v }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) route(); });
    }
    $('#g-sen-add').on('click', senAdd);
    $('#g-sen-in').on('keydown', function (ev) { if (ev.keyCode === 13) senAdd(); });
    $('#g-cards').on('click', '.g-sen-del', function () {
      post('list_del', { list_name: 'sensitive', index: $(this).data('i') }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) route(); });
    });

    $('#g-export').on('click', function () {
      post('export_config', {}, function (rr) {
        if (!rr.status) return layer.msg(rr.msg || 'error', { icon: 2 });
        var blob = new Blob([JSON.stringify(rr.data, null, 2)], { type: 'application/json' });
        var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = rr.filename || 'wafpro-config.json';
        document.body.appendChild(a); a.click(); document.body.removeChild(a); layer.msg('Config exported', { icon: 1 });
      });
    });
    $('#g-import').on('click', function () {
      var inp = document.createElement('input'); inp.type = 'file'; inp.accept = '.json,application/json';
      inp.onchange = function () {
        var f = inp.files[0]; if (!f) return;
        var rd = new FileReader();
        rd.onload = function () { post('import_config', { data: rd.result }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) route(); }); };
        rd.readAsText(f);
      };
      inp.click();
    });
    $('#g-restore').on('click', function () {
      layer.confirm('Restore every WAF Pro setting to defaults? This cannot be undone.', { icon: 3, title: 'Restore defaults' }, function (i) {
        layer.close(i);
        post('restore_config', {}, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) route(); });
      });
    });
  }

  function engineStatusText(e, hl) {
    var out = [];
    (e.conflicts || []).forEach(function (x) {
      out.push('<span style="color:var(--wp-red)">Conflict: ' + esc(x) + ' — only one lua WAF can run.</span>');
    });
    if (!e.installed) out.push('<span style="color:var(--wp-red)">Engine files missing — reinstall the plugin.</span>');
    else if (!e.current) out.push('<span style="color:var(--wp-orange)">The running engine is older than this plugin — click Update engine.</span>');
    if (e.wired && hl) {
      if (!hl.alive) out.push('<span style="color:var(--wp-red)">No heartbeat from nginx workers' +
        (hl.heartbeat_age ? ' for ' + hl.heartbeat_age + ' s' : '') + ' — check the nginx error log.</span>');
      else if (!hl.in_sync) out.push('<span style="color:var(--wp-orange)">Workers run rules v' + hl.running_version +
        ', panel saved v' + hl.rule_version + ' — catching up.</span>');
      else out.push('<span style="color:var(--wp-green)">&#10004; Enforcing the latest settings (rules v' + hl.rule_version +
        ', engine ' + esc(hl.engine_version) + ').</span>');
    } else if (!e.wired) {
      out.push('Not wired: settings are saved but not enforced.');
    }
    return out.join('<br>');
  }

  /* ---------- filter rule sets ---------- */
  var RULE_SETS = [
    ['get', 'GET-param filter', 'Matched against the decoded query string.'],
    ['post', 'POST filter', 'Matched against urlencoded form bodies.'],
    ['cookie', 'Cookie filter', 'Matched against the Cookie header.'],
    ['ua', 'User-Agent filter', 'Matched against the User-Agent header.'],
    ['scan', 'Scanner', 'Matched against the request path.'],
    ['nday', 'N-day exploits', 'Virtual patches for public CVEs; matched against the decoded request line and form body.']
  ];
  function ruleSetDialog(name) {
    post('rule_get', { rule_name: name }, function (r) {
      if (!r.status) return layer.msg(r.msg || 'error', { icon: 2 });
      var cur = RULE_SETS.filter(function (x) { return x[0] === name; })[0];
      var h = '<div class="wp-modal">' +
        '<div class="wp-subtabs">' + RULE_SETS.map(function (x) {
          return '<span class="wp-subtab rs-tab' + (x[0] === name ? ' on' : '') + '" data-k="' + x[0] + '">' + x[1] + '</span>';
        }).join('') + '</div><div class="wp-mod-body">' +
        '<div style="display:flex;gap:8px;margin-bottom:12px">' +
          '<input class="wp-in" id="rs-rule" placeholder="Regular expression (PCRE, case-insensitive)" style="flex:2">' +
          '<input class="wp-in" id="rs-ps" placeholder="Description" style="flex:1">' +
          '<span class="wp-btn primary" id="rs-add">Add</span></div>' +
        '<table class="wp-tbl"><thead><tr><th>Rule</th><th style="width:260px">Description</th>' +
        '<th style="width:70px">Status</th><th style="width:70px">Operate</th></tr></thead><tbody>' +
        ((r.data || []).length ? r.data.map(function (x) {
          return '<tr><td style="font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all">' + esc(x.rule) + '</td>' +
            '<td>' + esc(x.ps) + '</td>' +
            '<td><label class="wp-sw"><input type="checkbox" class="rs-on" data-i="' + x.index + '"' + (x.open ? ' checked' : '') +
            '><span class="sl"></span></label></td>' +
            '<td><span class="wp-lnk rs-del" data-i="' + x.index + '">Delete</span></td></tr>';
        }).join('') : '<tr><td colspan="4" class="wp-empty">No rules</td></tr>') +
        '</tbody></table><ul class="wp-notes"><li>' + cur[2] + '</li>' +
        '<li>A rule fires on a match anywhere in the subject; anchor with ^ and $ to be precise. Changes apply in a couple of seconds.</li></ul>' +
        '</div></div>';
      S.srSwitching = true; layer.closeAll('page'); S.srSwitching = false;
      layer.open({ type: 1, title: 'Filter rule sets', area: ['960px', '640px'], content: h, success: function () {
        $('.rs-tab').on('click', function () { ruleSetDialog($(this).data('k')); });
        $('#rs-add').on('click', function () {
          post('rule_add', { rule_name: name, rule: ($('#rs-rule').val() || '').trim(), ps: ($('#rs-ps').val() || '').trim() },
            function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) ruleSetDialog(name); });
        });
        $('.rs-on').on('change', function () {
          post('rule_toggle', { rule_name: name, index: $(this).data('i'), open: this.checked ? 1 : 0 },
            function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); });
        });
        $('.rs-del').on('click', function () {
          var i = $(this).data('i');
          layer.confirm('Delete this rule?', { title: 'Delete rule' }, function (k) {
            layer.close(k);
            post('rule_del', { rule_name: name, index: i }, function (rr) {
              layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) ruleSetDialog(name);
            });
          });
        });
      } });
    });
  }

  // Edit the block / browser-check page served by the engine
  function pageEditor(kind) {
    post('get_page', { kind: kind }, function (r) {
      if (!r.status) return layer.msg(r.msg || 'error', { icon: 2 });
      var tips = kind === 'block'
        ? 'Placeholders: <b>{rule}</b> <b>{ip}</b> <b>{time}</b> <b>{status}</b> <b>{id}</b>'
        : 'Must contain <b>{script}</b> — that is the check itself.';
      var h = '<div class="wp-modal"><div class="wp-mod-body">' +
        '<div style="color:var(--wp-text3);font-size:12px;margin-bottom:8px">' + tips + '</div>' +
        '<textarea class="wp-in" id="pe-html" style="width:100%;height:400px;font-family:ui-monospace,Menlo,monospace;font-size:12px">' +
        esc(r.html) + '</textarea></div>' +
        '<div class="wp-mod-foot"><span class="wp-btn" id="pe-default">Restore default</span>' +
        '<span class="wp-btn" id="pe-cancel">Cancel</span><span class="wp-btn primary" id="pe-save">Save</span></div></div>';
      var idx = layer.open({ type: 1, title: kind === 'block' ? 'Block page' : 'Browser check page',
        area: ['820px', '600px'], content: h });
      $('#pe-cancel').on('click', function () { layer.close(idx); });
      $('#pe-default').on('click', function () { $('#pe-html').val(r['default']); });
      $('#pe-save').on('click', function () {
        post('save_page', { kind: kind, html: $('#pe-html').val() }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) layer.close(idx);
        });
      });
    });
  }

  /* ---------- Simulated attack (self-test) ----------
     The stock WAF lists attack links to click; this sends real attack-shaped
     requests to each site through nginx and reports which rule stopped them. */
  function selfTestDialog(site) {
    var idx = layer.open({ type: 1, title: 'Simulated attack', area: ['900px', '640px'],
      content: '<div class="wp-modal"><div class="wp-mod-body" id="st-body">' +
        '<div class="wp-loading">Sending test requests to ' + (site ? esc(site) : 'every protected site') + '...</div></div></div>' });
    post('self_test', { siteName: site || '' }, function (r) {
      if (!r.status) { $('#st-body').html('<div class="wp-note">' + esc(r.msg || 'error') + '</div>'); return; }
      var h = '';
      var bad = (r.php || []).filter(function (p) { return !p.php2shell_safe; });
      if (bad.length) {
        h += '<div class="wp-note" style="margin-bottom:12px;color:var(--wp-red)">' + icoWarn() +
          ' PHP2Shell (CVE-2026-109618/109619): unpatched PHP on this server — ' + bad.map(function (p) {
            return esc(p.version) + (p.fixed_in ? ' (fixed in ' + esc(p.fixed_in) + ')' : ' (no fix for this branch — upgrade)');
          }).join(', ') + '. The WAF guard reduces the risk; updating PHP removes it.</div>';
      } else if ((r.php || []).length) {
        h += '<div class="wp-note" style="margin-bottom:12px">' + '&#10004; PHP on this server carries the PHP2Shell fix: ' +
          r.php.map(function (p) { return esc(p.version); }).join(', ') + '.</div>';
      }
      (r.sites || []).forEach(function (s) {
        h += '<div class="wp-mod-sec"><div class="wp-mod-sec-t">' + esc(s.site) +
          ' <span style="text-transform:none;font-weight:400;color:var(--wp-text3)">' + esc(s.scheme + '://' + s.host) + '</span> ' +
          (s.ok ? '<span style="color:var(--wp-green)">&#10004; protected</span>' : '<span style="color:var(--wp-red)">&#10008; gaps found</span>') +
          '</div><table class="wp-tbl"><thead><tr><th>Test</th><th style="width:70px">HTTP</th>' +
          '<th style="width:200px">Stopped by</th><th style="width:150px">Result</th></tr></thead><tbody>' +
          s.tests.map(function (t) {
            var res = t.pass === null ? '<span style="color:var(--wp-text3)">protection off</span>'
              : t.pass ? '<span style="color:var(--wp-green)">&#10004; ' + (t.baseline ? 'passed through' : 'blocked') + '</span>'
              : '<span style="color:var(--wp-red)">&#10008; ' + (t.baseline ? 'wrongly blocked' : 'NOT blocked') + '</span>';
            return '<tr><td>' + esc(t.label) + '</td><td>' + (t.status || 'closed') + '</td>' +
              '<td>' + esc(t.rule_name || '-') + '</td><td>' + res + '</td></tr>';
          }).join('') + '</tbody></table></div>';
      });
      if (!(r.sites || []).length) h += '<div class="wp-empty">No site with a domain to test.</div>';
      h += '<ul class="wp-notes"><li>Requests go from this server through nginx with a one-time secret header, so they are ' +
        'judged like a stranger&apos;s but never get this server banned. They appear in the logs with <b>wafpro_test=</b> in the URL.</li></ul>';
      $('#st-body').html(h);
    });
    return idx;
  }


  // exports
  W.RULE_SETS = RULE_SETS;
  W.engineStatusText = engineStatusText;
  W.fcard = fcard;
  W.gcard = gcard;
  W.gsec = gsec;
  W.pageEditor = pageEditor;
  W.pageGlobal = pageGlobal;
  W.renderGlobal = renderGlobal;
  W.ruleSetDialog = ruleSetDialog;
  W.selfTestDialog = selfTestDialog;
})(window.WAFPRO = window.WAFPRO || {});
