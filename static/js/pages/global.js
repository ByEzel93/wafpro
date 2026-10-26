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

  /* ---------------- Global: one table, like the stock WAF ----------------
     Name | Description | Resp | Status | OPT. A protection runs only when its
     switch here AND the site's own switch (WebSite > Modify) are on; a few
     rows (Non-browser, From-data, HTTP package) switch a protection on for
     every site instead. OPT opens the row's settings. */
  var RESP_CODES = [[200, '(200) Normal'], [404, '(404) File does not exist'], [403, '(403) Access denied'],
                    [444, '(444) Close connection'], [500, '(500) Application error'],
                    [502, '(502) Connection timed out'], [503, '(503) Server unavailable']];

  function saveCfg(patch, done) {
    post('save_config', { config: JSON.stringify(patch) }, function (rr) {
      layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
      if (rr.status && done) done();
    });
  }

  // the rows; resp = config key of the response code, sw = config key of the
  // switch (or a function for the special ones), ops = OPT buttons
  function globalRows(c, extra) {
    var mal = extra.mal || {}, sp = extra.sp || {}, idc = extra.idc || {};
    return [
      { name: 'CC defense', desc: 'Defense against CC attacks. The initial rule is what a new site starts with.',
        resp: 'cc_status', sw: 'm_cc', ops: [['Initial rule', ccRuleDialog]] },
      { name: 'Request defense', desc: 'Malicious request blocking threshold: an IP that trips too many rules is banned for a while.',
        resp: 'black_status', sw: function (on) { saveCfg({ retry: on ? (c.retry || 6) : 0 }, route); }, on: c.retry > 0,
        ops: [['Initial rule', toleranceDialog]] },
      { name: 'IP whitelist', desc: 'All rules are invalid for the IP whitelist.', ops: [['Conf', gotoList('ip_white')]] },
      { name: 'IP blacklist', desc: 'Ban access to the IP of all websites.', resp: 'black_status', ops: [['Conf', gotoList('ip_black')]] },
      { name: 'URL whitelist', desc: 'Most rules are invalid for URL whitelist.', ops: [['Conf', gotoList('url_white')]] },
      { name: 'URL blacklist', desc: 'Prohibit access to the specified URL.', resp: 'black_status', ops: [['Conf', gotoList('url_black')]] },
      { name: 'UA whitelist', desc: 'User-Agent whitelist in the initialization phase.', ops: [['Conf', gotoList('ua_white')]] },
      { name: 'UA blacklist', desc: 'User-Agent blacklist in the initialization phase.', resp: 'ua_status', ops: [['Conf', gotoList('ua_black')]] },
      { name: 'Spider pond', desc: 'Verified search-crawler IPs from the crawlers\' own published lists' +
          (sp.have ? ' (' + num(sp.count) + ' ranges).' : ' — not downloaded yet.'),
        sw: 'm_spider', ops: [['Conf', spiderDialog], ['Sync', function () { syncList('spider_update'); }]] },
      { name: 'Non-browser', desc: 'Intercept non-browser requests, this switch will apply to all websites.',
        sw: 'browser_all' },
      { name: 'HTTP filter', desc: 'Request type filtering / request header filtering / request shape limits.',
        resp: 'method_status', ops: [['Conf', function () { httpFilterDialog(extra.methods, extra.hdr); }]] },
      { name: 'GET-param filter', desc: 'SQL injection and XSS attacks in the URI and URI parameters.',
        resp: 'get_status', sw: 'm_get', ops: [['Rule', function () { ruleSetDialog('get'); }], ['Resp', blockPage]] },
      { name: 'UA filter', desc: 'Usually used to filter browsers, spiders and some automatic scanners.',
        resp: 'ua_status', sw: 'm_ua', ops: [['Rule', function () { ruleSetDialog('ua'); }], ['Resp', blockPage]] },
      { name: 'POST filter', desc: 'Filter common SQL injection and XSS attacks in POST parameters (form and JSON).',
        resp: 'post_status', sw: 'm_post', ops: [['Rule', function () { ruleSetDialog('post'); }], ['Resp', blockPage]] },
      { name: 'Cookie filter', desc: 'Filter penetration attacks initiated by cookies.',
        resp: 'cookie_status', sw: 'm_cookie', ops: [['Rule', function () { ruleSetDialog('cookie'); }], ['Resp', blockPage]] },
      { name: 'Scanner', desc: 'Filter penetration testing of common scan testing tools.',
        resp: 'scan_status', sw: 'm_scan', ops: [['Conf', function () { ruleSetDialog('scan'); }]] },
      { name: 'N-day exploits', desc: 'Virtual patches for public CVEs (PHP-CGI, ThinkPHP, PHPUnit, Ignition, Spring, Struts, F5...).',
        resp: 'get_status', sw: 'm_nday', ops: [['Conf', function () { ruleSetDialog('nday'); }]] },
      { name: 'From-data', desc: 'Form-data protocol parameter transfer specification, applied to all websites.',
        resp: 'php2shell_status', sw: 'form_all' },
      { name: 'PHP2Shell guard', desc: 'Known triggers of CVE-2026-109618/109619 in PHP uploads. Updating PHP is the real fix.',
        resp: 'php2shell_status', sw: 'm_php2shell', ops: [['Conf', function () { php2shellDialog(c); }]] },
      { name: 'HTTP package', desc: 'Block oversized request bodies (uploads excluded) on every website.',
        resp: 'header_status', sw: 'http_all', ops: [['Conf', function () { httpPackageDialog(c); }]] },
      { name: 'Content replace', desc: 'Replace set sensitive text in the pages of every website.',
        ops: [['Conf', function () { W.siteRules('*', 'repl'); }]] },
      { name: 'URL keyword', desc: 'Intercept illegal words from the URL.', resp: 'black_status',
        ops: [['Conf', gotoList('url_keyword')]] },
      { name: 'Illegal word', desc: 'Block words or phrases in the URL and request body.', resp: 'black_status',
        ops: [['Conf', function () { wordListDialog('sensitive', 'Illegal word block', 'Illegal word or regex'); }]] },
      { name: 'API defense', desc: 'API interface defense: allowed methods and per-IP rate for API paths, on every website.',
        ops: [['Conf', function () { W.siteRules('*', 'api'); }]] },
      { name: 'Malicious IP feed', desc: 'Public abuse feeds (botnets, repeat attackers)' +
          (mal.have ? ' — ' + num(mal.count) + ' ranges, updated ' + esc(mal.updated) + '.' : ' — not downloaded yet.'),
        resp: 'black_status', sw: function (on, $cb) {
          post('malicious_toggle', { open: on ? 1 : 0 }, function (rr) {
            layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (!rr.status) $cb.prop('checked', !on);
          });
        }, on: !!mal.open, ops: [['Sync', function () { syncList('malicious_update'); }]] },
      { name: 'IDC list', desc: 'Cloud / datacenter address space for the per-site IDC interception switch' +
          (idc.have ? ' — ' + num(idc.count) + ' ranges.' : ' — not downloaded yet.'),
        ops: [['Sync', function () { syncList('idc_update'); }]] },
      { name: 'Static file protection', desc: 'Count static files (JS, CSS, images) toward CC. Off by default — a page pulls many.',
        sw: 'static_protect' },
      { name: 'Block page', desc: 'The page a blocked visitor sees for 4xx responses, and the browser check page.',
        sw: 'block_page', ops: [['Resp', blockPage], ['Check page', function () { pageEditor('challenge'); }]] },
      { name: 'Logging', desc: 'Write blocks to /www/wwwlogs/wafpro/, kept for ' + (c.log_save || 30) + ' days.',
        sw: 'log', ops: [['Conf', function () { logDialog(c); }]] }
    ];
  }

  function renderGlobal(c, m, hl, sp, ml, senList) {
    var e = c.engine || {};
    var rows = globalRows(c, { mal: ml, sp: sp, idc: S.idcStatus, methods: m, hdr: hl });
    S.gRows = rows;

    var h = '<div class="wp-card wp-g-head">' +
      '<div class="wp-g-item"><span class="wp-g-lbl">Firewall switch</span>' + sw('g-open', c.open) + '</div>' +
      '<div class="wp-g-item"><span class="wp-g-lbl">Engine wired into nginx</span>' + sw('g-wired', e.wired) + '</div>' +
      '<div class="wp-g-state">' + engineStatusText(e, c.health) + '</div>' +
      '<div class="wp-g-acts">' +
        (e.installed && !e.current ? '<span class="wp-btn primary" id="g-engine-update">Update engine</span>' : '') +
        '<span class="wp-btn" id="g-export">Export</span><span class="wp-btn" id="g-import">Import</span>' +
        '<span class="wp-btn" id="g-restore">Restore defaults</span></div></div>';

    h += '<div class="wp-card"><div class="wp-site-box"><table class="wp-site-tbl wp-g-tbl"><thead><tr>' +
      '<th style="width:170px">Name</th><th>Description</th><th style="width:90px;text-align:center">Resp</th>' +
      '<th style="width:80px;text-align:center">Status</th><th class="r" style="width:150px">OPT</th></tr></thead><tbody>' +
      rows.map(function (r, i) {
        var on = typeof r.sw === 'string' ? c[r.sw] === true : r.on;
        return '<tr data-i="' + i + '"><td class="site">' + esc(r.name) + '</td>' +
          '<td style="white-space:normal;color:#606266">' + r.desc + '</td>' +
          '<td style="text-align:center">' + (r.resp ? '<span class="wp-lnk g-resp">' + (c[r.resp] || '-') + '</span>' : '<span style="color:#c0c4cc">--</span>') + '</td>' +
          '<td style="text-align:center">' + (r.sw ? '<label class="wp-sw wp-sw-sm"><input type="checkbox" class="g-sw"' +
            (on ? ' checked' : '') + '><span class="sl"></span></label>' : '<span style="color:#c0c4cc">--</span>') + '</td>' +
          '<td class="r">' + (r.ops || []).map(function (o, j) {
            return (j ? '<span class="sep"></span>' : '') + '<span class="wp-lnk g-op" data-j="' + j + '">' + o[0] + '</span>';
          }).join('') + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<ul class="wp-site-tips">' +
      '<li>Inheritance: the CC initial rule is what a new website starts with; use <b>Apply to all sites</b> in it to update existing ones.</li>' +
      '<li>A protection runs only when it is on here <b>and</b> on the website (WebSite &rsaquo; Modify).</li>' +
      '<li>Priority: IP whitelist &gt; IP blacklist &gt; UA whitelist &gt; UA blacklist &gt; URL whitelist &gt; URL blacklist &gt; ' +
      'URL keyword &gt; Spider &gt; Region &gt; UA &gt; Scanner &gt; N-day &gt; GET &gt; Cookie &gt; POST &gt; Non-browser &gt; CC &gt; Traffic limit</li>' +
      '</ul></div>';
    $('#wp-body').html(h);

    $('#wp-body').on('click', '.g-resp', function () {
      var r = rows[$(this).closest('tr').data('i')];
      respDialog(r.name, r.resp, c[r.resp]);
    });
    $('#wp-body').on('change', '.g-sw', function () {
      var r = rows[$(this).closest('tr').data('i')], on = this.checked;
      if (typeof r.sw === 'function') return r.sw(on, $(this));
      var p = {}; p[r.sw] = on;
      saveCfg(p);
      c[r.sw] = on;
    });
    $('#wp-body').on('click', '.g-op', function () {
      var r = rows[$(this).closest('tr').data('i')];
      r.ops[$(this).data('j')][1]();
    });

    $('#g-open').on('change', function () { saveCfg({ open: this.checked }); });
    $('#g-wired').on('change', function () {
      var on = this.checked;
      post('engine_wire', { open: on ? 1 : 0 }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); route(); });
    });
    $('#g-engine-update').on('click', function () {
      var ld = layer.msg('Updating engine...', { icon: 16, time: 0, shade: 0.3 });
      post('engine_update', {}, function (rr) { layer.close(ld); layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); route(); });
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

  /* ---------------- row dialogs ---------------- */
  function gDialog(title, w, body, onSave, saveText) {
    var idx = layer.open({
      type: 1, title: title, area: [w + 'px', 'auto'], closeBtn: 1, btn: [saveText || 'Save', 'Cancel'],
      content: '<div class="wp-modal wp-g-dlg">' + body + '</div>',
      yes: function () { onSave(function () { layer.close(idx); }); }
    });
    return idx;
  }
  function fRow(label, ctl, hint) {
    return '<div class="wp-g-row"><div class="wp-g-rl">' + label + '</div><div class="wp-g-rc">' + ctl +
      (hint ? '<div class="wp-g-hint">' + hint + '</div>' : '') + '</div></div>';
  }
  function nIn(id, v, w) { return '<input class="wp-in" id="' + id + '" type="number" min="0" style="width:' + (w || 90) + 'px" value="' + v + '">'; }

  function respDialog(name, key, cur) {
    gDialog('Set response code [' + esc(name) + ']', 380,
      fRow('Response', '<select class="wp-in" id="g-rc" style="width:220px">' + RESP_CODES.map(function (x) {
        return '<option value="' + x[0] + '"' + (x[0] === +cur ? ' selected' : '') + '>' + x[1] + '</option>';
      }).join('') + '</select>'),
      function (close) { var p = {}; p[key] = +$('#g-rc').val(); saveCfg(p, function () { close(); route(); }); }, 'Apply');
  }

  function ccRuleDialog() {
    post('get_config', {}, function (c) {
      var keyOpts = [['ip', 'IP'], ['url', 'URL with param'], ['path', 'URL without param'], ['ipua', 'IP+UA']];
      var body =
        fRow('Mode', '<select class="wp-in" id="cc-mode" style="width:220px">' +
          '<option value="block"' + (c.cc_def_mode !== 'challenge' ? ' selected' : '') + '>General mode</option>' +
          '<option value="challenge"' + (c.cc_def_mode === 'challenge' ? ' selected' : '') + '>Enhanced mode</option></select>',
          'Enhanced: a client over the limit must pass browser verification (JavaScript) instead of being blocked; ' +
          'verified browsers get 4x the allowance.') +
        fRow('Request', '<div class="wp-g-radios">' + keyOpts.map(function (k) {
          return '<label><input type="radio" name="cc-key" value="' + k[0] + '"' + ((c.cc_def_key || 'ip') === k[0] ? ' checked' : '') + '> ' + k[1] + '</label>';
        }).join('') + '</div>', 'What one client is counted by. IP+UA separates many people behind one office/NAT address.') +
        fRow('Cycle', nIn('cc-cycle', c.cc_def_cycle) + ' <span class="wp-unit">Sec</span>') +
        fRow('Frequency', nIn('cc-limit', c.cc_def_limit) + ' <span class="wp-unit">Time(s)</span>') +
        fRow('Block Time', nIn('cc-block', c.cc_def_block) + ' <span class="wp-unit">Sec</span>') +
        fRow('Automatic mode', sw('cc-auto', c.cc_auto) +
          '<div class="wp-g-hint">When on, enhanced mode switches on by itself when a website takes more than ' +
          nIn('cc-auto-limit', c.cc_auto_limit, 80) + ' requests within ' + nIn('cc-auto-cycle', c.cc_auto_cycle, 70) +
          ' seconds, and switches back off after ' + nIn('cc-auto-hold', c.cc_auto_hold, 70) + ' seconds.</div>') +
        fRow('', '<label class="wp-g-chk"><input type="checkbox" id="cc-all"> Apply to all sites (overwrites each site\'s CC rule)</label>') +
        '<ul class="wp-site-tips"><li>The setting here is the initial value, which will be inherited when a new site is added.</li>' +
        '<li>Please do not set too strict CC rules, so as not to affect the normal user experience.</li></ul>';
      gDialog('CC defense — initial rule', 640, body, function (close) {
        var p = { cc_def_mode: $('#cc-mode').val(), cc_def_key: $('input[name=cc-key]:checked').val(),
                  cc_def_cycle: +$('#cc-cycle').val(), cc_def_limit: +$('#cc-limit').val(), cc_def_block: +$('#cc-block').val(),
                  cc_auto: $('#cc-auto').is(':checked'), cc_auto_limit: +$('#cc-auto-limit').val(),
                  cc_auto_cycle: +$('#cc-auto-cycle').val(), cc_auto_hold: +$('#cc-auto-hold').val() };
        var all = $('#cc-all').is(':checked');
        saveCfg(p, function () {
          if (!all) return close();
          post('cc_apply_all', {}, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); close(); });
        });
      });
    });
  }

  function toleranceDialog() {
    post('get_config', {}, function (c) {
      gDialog('Set tolerance for malicious requests', 560,
        fRow('Cycle', nIn('tl-cycle', c.retry_cycle) + ' <span class="wp-unit">Sec</span>') +
        fRow('Frequency', nIn('tl-retry', c.retry) + ' <span class="wp-unit">Times</span>') +
        fRow('Block Time', nIn('tl-time', c.retry_time) + ' <span class="wp-unit">Sec</span>') +
        fRow('Escalate', sw('tl-esc', c.ban_escalate !== false),
          'A repeat offender is banned longer each time (block time × times banned today, max 24h).') +
        '<ul class="wp-site-tips"><li>Accumulated malicious requests exceeding Frequency within Cycle seconds block the IP for Block Time.</li>' +
        '<li>Frequency 0 turns the auto-ban off.</li></ul>',
        function (close) {
          saveCfg({ retry_cycle: +$('#tl-cycle').val(), retry: +$('#tl-retry').val(), retry_time: +$('#tl-time').val(),
                    ban_escalate: $('#tl-esc').is(':checked') }, function () { close(); route(); });
        });
    });
  }

  function httpFilterDialog(m, hl) {
    var allM = (m && m.all) || [], onM = {};
    ((m && m.data) || []).forEach(function (x) { onM[x] = 1; });
    var lims = (hl && hl.data) || [];
    post('get_config', {}, function (c) {
      var body = '<div class="wp-g-sec">Request type filtering</div>' +
        '<div class="wp-g-radios">' + allM.map(function (x) {
          return '<label><input type="checkbox" class="hf-m" value="' + x + '"' + (onM[x] ? ' checked' : '') +
            (x === 'GET' ? ' disabled' : '') + '> ' + x + '</label>';
        }).join('') + '</div><div class="wp-g-hint">Unchecked methods are refused. GET cannot be turned off.</div>' +
        '<div class="wp-g-sec">Request header filtering</div>' +
        '<table class="wp-site-tbl" id="hf-tbl"><thead><tr><th>Header</th><th style="width:140px">Max length (B)</th><th class="r" style="width:70px"></th></tr></thead><tbody>' +
        lims.map(function (x) {
          return '<tr><td class="hf-h">' + esc(x.h) + '</td><td><input class="wp-in hf-v" type="number" style="width:110px" value="' + x.max + '"></td>' +
            '<td class="r"><span class="wp-lnk hf-del">Delete</span></td></tr>';
        }).join('') + '</tbody></table>' +
        '<div style="display:flex;gap:8px;margin-top:8px"><input class="wp-in" id="hf-new-h" placeholder="Please enter the header name">' +
        '<input class="wp-in" id="hf-new-v" type="number" placeholder="Length" style="width:110px">' +
        '<span class="wp-btn" id="hf-add">Add</span></div>' +
        '<div class="wp-g-sec">Request shape limits</div>' +
        fRow('Max parameters', nIn('hf-params', c.max_params, 100), 'Query string or form fields in one request.') +
        fRow('Max headers', nIn('hf-headers', c.max_headers, 100));
      var idx = gDialog('HTTP request filtering', 640, body, function (close) {
        var ms = ['GET'];
        $('.hf-m:checked').each(function () { if (this.value !== 'GET') ms.push(this.value); });
        var lim = [];
        $('#hf-tbl tbody tr').each(function () { lim.push({ h: $(this).find('.hf-h').text(), max: +$(this).find('.hf-v').val() }); });
        post('save_methods', { methods: JSON.stringify(ms) }, function (r1) {
          post('save_hdr_limits', { limits: JSON.stringify(lim) }, function (r2) {
            saveCfg({ max_params: +$('#hf-params').val(), max_headers: +$('#hf-headers').val() }, function () {
              if (!r1.status || !r2.status) layer.msg((r1.status ? r2 : r1).msg, { icon: 2 });
              close(); route();
            });
          });
        });
      });
      $('#hf-tbl').on('click', '.hf-del', function () { $(this).closest('tr').remove(); });
      $('#hf-add').on('click', function () {
        var hname = ($('#hf-new-h').val() || '').trim().toLowerCase(), v = +$('#hf-new-v').val();
        if (!hname || !v) return layer.msg('Enter a header name and a length', { icon: 0 });
        $('#hf-tbl tbody').append('<tr><td class="hf-h">' + esc(hname) + '</td><td><input class="wp-in hf-v" type="number" style="width:110px" value="' + v + '"></td>' +
          '<td class="r"><span class="wp-lnk hf-del">Delete</span></td></tr>');
        $('#hf-new-h,#hf-new-v').val('');
      });
      return idx;
    });
  }

  function php2shellDialog(c) {
    gDialog('PHP2Shell guard limits', 560,
      fRow('Max parts', nIn('mp-parts', c.mp_max_parts), 'multipart parts per request') +
      fRow('Max headers per part', nIn('mp-headers', c.mp_max_headers)) +
      fRow('Max field nesting', nIn('mp-depth', c.mp_max_depth), 'a[b][c]... levels') +
      fRow('Max empty file fields', nIn('mp-empty', c.mp_max_empty)) +
      '<ul class="wp-site-tips"><li>CVE-2026-109618 / 109619 are reached through PHP\'s multipart parser; these bounds remove the known triggers.</li>' +
      '<li>Updating PHP (8.2.35, 8.3.36, 8.4.27, 8.5.12 or newer) is the only complete fix — Simulated attack lists any unpatched PHP.</li></ul>',
      function (close) {
        saveCfg({ mp_max_parts: +$('#mp-parts').val(), mp_max_headers: +$('#mp-headers').val(),
                  mp_max_depth: +$('#mp-depth').val(), mp_max_empty: +$('#mp-empty').val() }, close);
      });
  }

  function httpPackageDialog(c) {
    gDialog('HTTP package', 480,
      fRow('Max body', nIn('hp-kb', c.body_max_all) + ' <span class="wp-unit">KB</span>',
        'Applies to every website without its own limit (WebSite › Modify). Uploads are excluded.'),
      function (close) { saveCfg({ body_max_all: +$('#hp-kb').val() }, function () { close(); route(); }); });
  }

  function logDialog(c) {
    gDialog('Logging', 420, fRow('Keep logs', nIn('lg-days', c.log_save) + ' <span class="wp-unit">days</span>'),
      function (close) { saveCfg({ log_save: +$('#lg-days').val() }, function () { close(); route(); }); });
  }

  function spiderDialog() {
    post('spider_status', {}, function (sp) {
      gDialog('Spider pond', 520,
        fRow('Ranges', '<b>' + num(sp.count || 0) + '</b>' + (sp.updated ? ' <span class="wp-unit">updated ' + esc(sp.updated) + '</span>' : '')) +
        fRow('Sources', esc((sp.sources || []).join(', '))) +
        '<ul class="wp-site-tips"><li>Each crawler\'s own published IP list. A client calling itself one of these crawlers from any other IP is a fake spider.</li>' +
        '<li>Sync downloads the lists again.</li></ul>',
        function (close) { close(); syncList('spider_update'); }, 'Sync now');
    });
  }

  function syncList(action) {
    var ld = layer.msg('Downloading...', { icon: 16, time: 0, shade: 0.3 });
    post(action, {}, function (rr) { layer.close(ld); layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) route(); });
  }

  function gotoList(key) {
    return function () { S.listKey = key; S.listQ = ''; S.listPage = 1; S.tab = 'lists'; W.renderTabs(); route(); };
  }
  function blockPage() { pageEditor('block'); }

  // a small list editor (Illegal word): add / delete regex entries
  function wordListDialog(listName, title, ph) {
    post('list_get', { list_name: listName }, function (r) {
      var items = r.data || [];
      var body = '<div style="display:flex;gap:8px;margin-bottom:10px"><input class="wp-in" id="wl-in" placeholder="' + esc(ph) + '" style="flex:1">' +
        '<span class="wp-btn primary" id="wl-add">Add</span></div>' +
        '<table class="wp-site-tbl"><thead><tr><th>Word / pattern</th><th class="r" style="width:80px">OPT</th></tr></thead><tbody>' +
        (items.length ? items.map(function (x) {
          return '<tr><td style="white-space:normal;word-break:break-all">' + esc(x.value) + '</td>' +
            '<td class="r"><span class="wp-lnk wl-del" data-i="' + x.index + '">Delete</span></td></tr>';
        }).join('') : '<tr><td colspan="2" class="wp-empty">Empty</td></tr>') + '</tbody></table>' +
        '<ul class="wp-site-tips"><li>Please do not fill in randomly: all prohibited words should be complete words.</li></ul>';
      layer.closeAll('page');
      var idx = layer.open({ type: 1, title: title, area: ['600px', '520px'], content: '<div class="wp-modal wp-g-dlg">' + body + '</div>' });
      $('#wl-add').on('click', function () {
        var v = ($('#wl-in').val() || '').trim(); if (!v) return;
        post('list_add', { list_name: listName, value: v }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) wordListDialog(listName, title, ph);
        });
      });
      $('.wl-del').on('click', function () {
        post('list_del', { list_name: listName, index: $(this).data('i') }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) wordListDialog(listName, title, ph);
        });
      });
      return idx;
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
  W.pageEditor = pageEditor;
  W.pageGlobal = pageGlobal;
  W.renderGlobal = renderGlobal;
  W.ruleSetDialog = ruleSetDialog;
  W.selfTestDialog = selfTestDialog;
  W.RESP_CODES = RESP_CODES;
  W.blockPage = blockPage;
  W.ccRuleDialog = ccRuleDialog;
  W.fRow = fRow;
  W.gDialog = gDialog;
  W.globalRows = globalRows;
  W.gotoList = gotoList;
  W.httpFilterDialog = httpFilterDialog;
  W.httpPackageDialog = httpPackageDialog;
  W.logDialog = logDialog;
  W.nIn = nIn;
  W.php2shellDialog = php2shellDialog;
  W.respDialog = respDialog;
  W.saveCfg = saveCfg;
  W.spiderDialog = spiderDialog;
  W.syncList = syncList;
  W.toleranceDialog = toleranceDialog;
  W.wordListDialog = wordListDialog;
})(window.WAFPRO = window.WAFPRO || {});
