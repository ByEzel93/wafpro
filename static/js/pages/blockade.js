(function (W) {
  // generated wiring: names declared in other modules
  var API = W.API;
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function pickDate() { return W.pickDate.apply(this, arguments); }
  function icoCalendar() { return W.icoCalendar.apply(this, arguments); }
  function todayStr() { return W.todayStr.apply(this, arguments); }

  /* ================= BLOCKADE (3 card tabs, as in aaPanel 8) ================= */
  var BL_SUBS = [
    { id: 'intercept', t: 'Interception record' },
    { id: 'ipblock', t: 'IP blocking record' },
    { id: 'rulehit', t: 'Rule hit record' }
  ];
  function pageBlockade() {
    S.blSub = S.blSub || 'intercept';
    var h = '<div class="wp-subtabs">' + BL_SUBS.map(function (x) {
      return '<span class="wp-subtab' + (x.id === S.blSub ? ' on' : '') + '" data-s="' + x.id + '">' + x.t + '</span>';
    }).join('') + '</div>';
    h += '<div class="wp-card" style="border-top-left-radius:0"><div id="wp-bl-body"><div class="wp-loading">Loading...</div></div></div>';
    $('#wp-body').html(h);
    $('.wp-subtab').on('click', function () {
      S.blSub = $(this).data('s');
      $('.wp-subtab').removeClass('on'); $(this).addClass('on');
      if (S.timer) { clearInterval(S.timer); S.timer = null; }
      routeBlockade();
    });
    routeBlockade();
  }
  function routeBlockade() {
    if (S.blSub === 'intercept') return blIntercept();
    if (S.blSub === 'ipblock') return blIpBlock();
    if (S.blSub === 'rulehit') return blRuleHit();
  }

  /* ---- shared bits ---- */
  function icoSearch() {
    return '<svg class="wp-ico" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/></svg>';
  }
  // toolbar: buttons on the left, the search box on the right
  function toolbar(btns, q, id) {
    return '<div class="wp-bl-bar">' + btns.map(function (b) {
      return '<span class="wp-btn' + (b.primary ? ' primary' : '') + '" id="' + b.id + '">' + b.t + '</span>';
    }).join('') +
      '<div class="wp-site-search"><input class="wp-in" id="' + id + '" placeholder="Domain name/IP/URL/User-Agent/Region" value="' +
      esc(q || '') + '"><span class="wp-site-search-i" id="' + id + '-go">' + icoSearch() + '</span></div></div>';
  }
  function bindSearch(id, fn) {
    $('#' + id).on('keydown', function (e) { if (e.keyCode === 13) fn($(this).val() || ''); });
    $('#' + id + '-go').on('click', function () { fn($('#' + id).val() || ''); });
  }
  function ipCell(ip, loc) {
    return loc === 'Unknown' && /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|f[cd])/i.test(ip) ? 'Intranet' : esc(loc);
  }
  function opsCell(list) {
    return '<td class="wp-ops">' + list.map(function (x) {
      return '<span class="wp-lnk ' + x.c + '" data-i="' + x.i + '">' + x.t + '</span>';
    }).join('<span class="wp-ops-sep">|</span>') + '</td>';
  }
  function reply(rr, then) {
    layer.msg((rr && rr.msg) || 'No response', { icon: (rr && rr.status) ? 1 : 2 });
    if (rr && rr.status && then) then();
  }
  function download(rr) {
    if (!rr || !rr.status) { layer.msg((rr && rr.msg) || 'Export failed', { icon: 2 }); return; }
    layer.msg(rr.rows + ' rows exported', { icon: 1 });
    window.open(API + 'download_export&filename=' + encodeURIComponent(rr.filename));
  }
  function reEsc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function unesc(s) { return $('<div>').html(s || '').text(); }

  // Add to IP blacklist, optionally the whole /24 (the stock "pull the
  // entire IP section" option)
  function blockIp(ip) {
    var v4 = /^\d+\.\d+\.\d+\.\d+$/.test(ip);
    layer.open({
      type: 1, title: 'Add to IP blacklist', area: ['420px', 'auto'], btn: ['Confirm', 'Cancel'],
      content: '<div class="wp-g-dlg"><div>Add <b>' + esc(ip) + '</b> to the IP blacklist? Every request from it is dropped from now on.</div>' +
        (v4 ? '<label class="wp-g-chk" style="margin-top:12px"><input type="checkbox" id="wp-bl-seg"> Do you pull the entire IP section? (' +
          esc(ip.replace(/\.\d+$/, '.0/24')) + ')</label>' : '') + '</div>',
      yes: function (i) {
        var seg = $('#wp-bl-seg').is(':checked');
        layer.close(i);
        post('list_add', { list_name: 'ip_black', value: seg ? ip.replace(/\.\d+$/, '.0/24') : ip,
          remark: 'Blockade' }, function (rr) { reply(rr); });
      }
    });
  }
  // White URL: the path only, anchored and escaped — the list holds regexes
  function whiteUrl(url) {
    var u = (unesc(url) || '').split('?')[0];
    if (!u || u === '/') {
      layer.msg('The URI of the current IP is the root directory, and false alarm operations cannot be performed!', { icon: 2 });
      return;
    }
    layer.confirm('After adding to the URL whitelist, this URL will no longer be defended. Do you want to continue the operation?' +
      '<div style="margin-top:8px;color:#909399;word-break:break-all">' + esc(u) + '</div>',
      { icon: 3, title: 'Add to URL whitelist' }, function (i) {
        layer.close(i);
        post('list_add', { list_name: 'url_white', value: '^' + reEsc(u), remark: 'Blockade' }, function (rr) { reply(rr); });
      });
  }
  function siteSelect(id, withAll) {
    return '<select class="wp-in" id="' + id + '" style="width:100%">' + (withAll ? '<option value="">All</option>' : '') +
      (S.blSites || []).map(function (x) { return '<option value="' + esc(x) + '">' + esc(x) + '</option>'; }).join('') +
      '</select>';
  }

  /* ---------- el-pagination: ‹ 1 2 … 9 ›  [10 / page]  Goto [ ]  Total N ---------- */
  function pager(cur, pages, total, id, size) {
    var h = '<div class="wp-site-pager" id="' + id + '"><span class="pg nav' + (cur <= 1 ? ' dis' : '') + '" data-p="prev">&#8249;</span>';
    var last = 0;
    for (var i = 1; i <= pages; i++) {
      if (i <= 1 || i > pages - 1 || Math.abs(i - cur) <= 2) {
        if (last && i - last > 1) h += '<span class="pg dis">…</span>';
        h += '<span class="pg' + (i === cur ? ' cur' : '') + '" data-p="' + i + '">' + i + '</span>';
        last = i;
      }
    }
    h += '<span class="pg nav' + (cur >= pages ? ' dis' : '') + '" data-p="next">&#8250;</span>';
    if (size) {
      h += '<select class="wp-in pg-size">' + [10, 20, 50, 100].map(function (k) {
        return '<option value="' + k + '"' + (k === size ? ' selected' : '') + '>' + k + ' / page</option>';
      }).join('') + '</select>';
    }
    h += '<span class="lbl">Goto</span><input class="wp-in goto" value="' + cur + '">' +
      '<span class="lbl total">Total ' + num(total) + '</span></div>';
    return h;
  }
  // fn(page) on navigation; onSize(size) when the page size changes
  function bindPager(id, pages, fn, onSize) {
    var $p = $('#' + id);
    $p.find('.pg[data-p]').on('click', function () {
      var p = $(this).data('p');
      var cur = parseInt($p.find('.pg.cur').data('p'), 10) || 1;
      if (p === 'prev') p = Math.max(cur - 1, 1);
      else if (p === 'next') p = Math.min(cur + 1, pages);
      fn(parseInt(p, 10));
    });
    $p.find('.goto').on('keydown', function (e) {
      if (e.keyCode !== 13) return;
      var p = parseInt($(this).val(), 10);
      if (p >= 1 && p <= pages) fn(p);
    });
    $p.find('.pg-size').on('change', function () { if (onSize) onSize(parseInt($(this).val(), 10)); });
  }

  /* ---- query-date: All / Today / Yesterday / a picked day ---- */
  function dateBar() {
    var d = S.blDate || 'all', named = d === 'all' || d === 'today' || d === 'yesterday';
    return '<div class="wp-bl-date"><div class="wp-seg-btn" id="wp-bl-date">' +
      [['all', 'All'], ['today', 'Today'], ['yesterday', 'Yesterday']].map(function (x) {
        return '<span class="' + (d === x[0] ? 'on' : '') + '" data-d="' + x[0] + '">' + x[1] + '</span>';
      }).join('') + '</div>' +
      '<span class="wp-btn wp-bl-pick' + (named ? '' : ' on') + '" id="wp-bl-pick">' + icoCalendar() +
      (named ? 'Select date' : esc(d)) + '</span></div>';
  }
  function dateLabel(d) {
    return d === 'all' ? 'All' : d === 'today' ? todayStr() : d === 'yesterday' ? W.dayStr(-1) : d;
  }

  /* ================= Interception record ================= */
  function blIntercept() {
    S.blDate = S.blDate || 'all';
    S.blSize = S.blSize || 10;
    var h = toolbar([{ id: 'wp-bl-export', t: 'Export' }, { id: 'wp-bl-clear', t: 'Clear log' }], S.blQ, 'wp-bl-q');
    h += '<div id="wp-bl-result"><div class="wp-loading">Loading...</div></div>';
    $('#wp-bl-body').html(h);

    bindSearch('wp-bl-q', function (q) { S.blQ = q; loadIntercept(1); });
    $('#wp-bl-export').on('click', function () {
      post('export_logs', { date: S.blDate, q: S.blQ || '' }, download);
    });
    $('#wp-bl-clear').on('click', clearSiteLog);
    loadIntercept(1);
  }
  function clearSiteLog() {
    post('get_log_dates', {}, function (r) {
      S.blSites = r.sites || [];
      layer.open({
        type: 1, title: 'Clear log', area: ['440px', 'auto'], btn: ['Confirm', 'Cancel'],
        content: '<div class="wp-g-dlg"><div class="wp-g-row"><div class="wp-g-rl">Site</div><div class="wp-g-rc">' +
          siteSelect('wp-bl-csite', true) + '</div></div>' +
          '<div style="color:#909399;font-size:12px;padding-left:134px">Clear the log records of the selected site, do you want to continue?</div></div>',
        yes: function (i) {
          var site = $('#wp-bl-csite').val() || '';
          layer.close(i);
          post('clear_logs', { siteName: site, date: 'all' }, function (rr) { reply(rr, function () { loadIntercept(1); }); });
        }
      });
    });
  }

  function loadIntercept(p) {
    $('#wp-bl-result').html('<div class="wp-loading">Loading...</div>');
    post('get_logs', { date: S.blDate, q: S.blQ || '', p: p, size: S.blSize }, function (r) {
      if (!r.status) { $('#wp-bl-result').html('<div class="wp-empty">' + esc(r.msg || 'error') + '</div>'); return; }
      S.blRows = r.data || [];
      var h = dateBar() +
        '<div class="wp-match"><div class="wp-match-n">Match result: ' + num(r.total) + '</div>' +
        '<div class="wp-match-s">Query time: ' + esc(dateLabel(S.blDate)) + (S.blQ ? ' · keyword: ' + esc(S.blQ) : '') + '</div>' +
        '<div class="wp-match-s">*Note: Each IP triggers a repeat-only rule (bans, blacklist, verification) once per 10 seconds in this log; ' +
        'other blocks are recorded every time.</div></div>';
      h += '<div class="wp-site-box"><table class="wp-site-tbl"><thead><tr>' +
        '<th>Start time</th><th>User IP</th><th>Domain name</th><th>Type</th><th>URL address</th>' +
        '<th>Status</th><th>IP location</th><th>Filter</th><th class="r">Operate</th></tr></thead><tbody>';
      h += S.blRows.length ? S.blRows.map(function (x, i) {
        return '<tr><td>' + x.time + '</td><td>' + x.ip + '</td>' +
          '<td class="ell" title="' + x.site + '">' + x.site + '</td><td>' + x.method + '</td>' +
          '<td class="ell wp-bl-url" title="' + x.url + '">' + x.url + '</td>' +
          '<td class="red">Intercepted</td>' +
          '<td class="ell">' + ipCell(unesc(x.ip), unesc(x.location)) + '</td>' +
          '<td class="ell" title="' + x.filter_name + '">' + x.filter_name + '</td>' +
          opsCell([{ c: 'bl-ip', i: i, t: 'Block IP' }, { c: 'bl-url', i: i, t: 'White URL' }, { c: 'bl-det', i: i, t: 'Details' }]) + '</tr>';
      }).join('') : '<tr><td colspan="9" class="wp-empty">No Data</td></tr>';
      h += '</tbody></table></div>';
      h += pager(r.p, r.pages, r.total, 'wp-bl-pg', S.blSize);
      $('#wp-bl-result').html(h);

      bindPager('wp-bl-pg', r.pages, loadIntercept, function (k) { S.blSize = k; loadIntercept(1); });
      bindDateBar(function () { loadIntercept(1); });
      $('.bl-ip').on('click', function () { blockIp(unesc(S.blRows[$(this).data('i')].ip)); });
      $('.bl-url').on('click', function () { whiteUrl(S.blRows[$(this).data('i')].url); });
      $('.bl-det').on('click', function () { interceptDetail(S.blRows[$(this).data('i')]); });
    });
  }
  function bindDateBar(reload) {
    $('#wp-bl-date span').on('click', function () {
      S.blDate = $(this).data('d'); reload();
    });
    $('#wp-bl-pick').on('click', function () {
      pickDate(this, {
        value: /^\d{4}-/.test(S.blDate) ? S.blDate : '', max: todayStr(),
        done: function (v) { S.blDate = v || 'all'; reload(); }
      });
    });
  }

  // how dangerous a filter is, for the Risk value line
  var RISK_HIGH = /^(sqli|xss|cmdi|lfi|get|post|cookie|nday|upload-ext|php-path|php2shell|form-data|custom)/;
  var RISK_MID = /^(scan|user-agent|ua-black|url-keyword|url-black|deny-ext|deny-path|dir-scan|fake-spider|malicious-ip|weak-password|header|method|http-package)/;
  function riskOf(type) {
    var t = unesc(type);
    return RISK_HIGH.test(t) ? '<span class="red">High</span>' : RISK_MID.test(t) ? '<span style="color:#e6a23c">Medium</span>' : 'Low';
  }
  function detLine(k, v, extra) {
    return '<div class="wp-det-row"><div class="wp-det-k">' + k + '</div><div class="wp-det-v">' +
      (v === '' || v == null ? '<span style="color:#c0c4cc">Empty</span>' : v) + (extra || '') + '</div></div>';
  }
  function interceptDetail(x) {
    layer.open({
      type: 1, title: 'Details [' + unesc(x.ip) + ']', area: ['680px', 'auto'], maxHeight: 600,
      content: '<div class="wp-g-dlg wp-det">' +
        detLine('Time', x.time) + detLine('Attack IP', x.ip + ' <span style="color:#909399">(' + ipCell(unesc(x.ip), unesc(x.location)) + ')</span>') +
        detLine('Type', x.method) + detLine('Filter', x.filter_name) +
        detLine('URI address', x.url, ' <span class="wp-lnk" id="wp-det-white" style="margin-left:8px">White URL</span>') +
        detLine('Filter rule', x.rx ? '<code class="wp-det-code">' + x.rx + '</code>' : '') +
        detLine('Incoming value', x.rule ? '<code class="wp-det-code">' + x.rule + '</code>' : '') +
        detLine('Risk value', riskOf(x.type)) +
        detLine('User-Agent', x.ua) + '</div>',
      success: function () { $('#wp-det-white').on('click', function () { whiteUrl(x.url); }); }
    });
  }

  /* ================= IP blocking record ================= */
  function blIpBlock() {
    S.banSize = S.banSize || 10;
    var h = toolbar([{ id: 'wp-ban-export', t: 'Export' }, { id: 'wp-ban-clear', t: 'Clear log' },
      { id: 'wp-ban-all', t: 'Unblock all' }], S.banQ, 'wp-ban-q');
    h += '<div id="wp-ban-result"><div class="wp-loading">Loading...</div></div>';
    $('#wp-bl-body').html(h);
    bindSearch('wp-ban-q', function (q) { S.banQ = q; loadBans(1); });
    $('#wp-ban-export').on('click', function () { post('ban_export', { q: S.banQ || '' }, download); });
    $('#wp-ban-clear').on('click', function () {
      layer.confirm('Clear all blocked log records, but blocked IPs will not be unblocked!', { icon: 3, title: 'Clear log' }, function (i) {
        layer.close(i);
        post('ban_clear', {}, function (rr) { reply(rr, function () { loadBans(1); }); });
      });
    });
    $('#wp-ban-all').on('click', function () {
      layer.confirm('Do you want to unblock all IPs from the firewall?', { icon: 3, title: 'Unblock IP address' }, function (i) {
        layer.close(i);
        post('unban_all', {}, function (rr) { reply(rr, function () { setTimeout(function () { loadBans(1); }, 400); }); });
      });
    });
    loadBans(1);
  }
  function loadBans(p) {
    S.banPage = p;
    post('ban_records', { q: S.banQ || '', p: p, size: S.banSize }, function (r) {
      if (!r.status) { $('#wp-ban-result').html('<div class="wp-empty">' + esc(r.msg || 'error') + '</div>'); return; }
      S.banRows = r.data || [];
      var h = '<div class="wp-match"><div class="wp-match-n">Match result: ' + num(r.total) + '</div>' +
        '<div class="wp-match-s">Currently blocking: ' + num(r.live) + ' · temporary bans from auto-ban, CC and traffic limits; ' +
        'IPs blocked by hand live in Black/White list › IP blacklist.</div></div>';
      h += '<div class="wp-site-box"><table class="wp-site-tbl"><thead><tr>' +
        '<th>Start time</th><th>User IP</th><th>Site</th><th>URL address</th><th>Reason for blocking</th>' +
        '<th>Time</th><th>Status</th><th>IP location</th><th class="r">Operate</th></tr></thead><tbody>';
      h += S.banRows.length ? S.banRows.map(function (x, i) {
        var ops = [{ c: 'ban-url', i: i, t: 'White URL' }, { c: 'ban-ip', i: i, t: 'Block IP' }];
        if (x.blocking) ops.push({ c: 'ban-un', i: i, t: 'Unblock IP' });
        ops.push({ c: 'ban-det', i: i, t: 'Details' });
        return '<tr><td>' + fmtTime(x.start) + '</td><td>' + esc(x.ip) + '</td>' +
          '<td class="ell">' + esc(x.site || '-') + '</td>' +
          '<td class="ell" title="' + esc(x.uri) + '">' + esc(x.uri || '-') + '</td>' +
          '<td>' + esc(x.reason) + (x.hits ? ' <span style="color:#909399">×' + x.hits + '</span>' : '') + '</td>' +
          '<td>' + x.secs + 's</td>' +
          '<td' + (x.blocking ? ' class="red wp-left" data-until="' + x.until + '"' : '') + '>' +
          (x.blocking ? 'Blocking (' + fmtLeft(x.left) + ')' : 'Expired') + '</td>' +
          '<td class="ell">' + ipCell(x.ip, x.location) + '</td>' + opsCell(ops) + '</tr>';
      }).join('') : '<tr><td colspan="9" class="wp-empty">No Data</td></tr>';
      h += '</tbody></table></div>' + pager(r.p, r.pages, r.total, 'wp-ban-pg', S.banSize);
      $('#wp-ban-result').html(h);

      bindPager('wp-ban-pg', r.pages, loadBans, function (k) { S.banSize = k; loadBans(1); });
      $('.ban-url').on('click', function () { whiteUrl(esc(S.banRows[$(this).data('i')].uri)); });
      $('.ban-ip').on('click', function () { blockIp(S.banRows[$(this).data('i')].ip); });
      $('.ban-un').on('click', function () {
        var ip = S.banRows[$(this).data('i')].ip;
        layer.confirm('Do you want to unblock IP [' + esc(ip) + '] from the firewall', { icon: 3, title: 'Unblock IP address' }, function (i) {
          layer.close(i);
          post('unban', { ip: ip }, function (rr) { reply(rr, function () { setTimeout(function () { loadBans(S.banPage); }, 400); }); });
        });
      });
      $('.ban-det').on('click', function () {
        var x = S.banRows[$(this).data('i')];
        layer.open({
          type: 1, title: 'Details [' + x.ip + ']', area: ['620px', 'auto'],
          content: '<div class="wp-g-dlg wp-det">' + detLine('Start time', fmtTime(x.start)) +
            detLine('Unblock time', fmtTime(x.until)) + detLine('User IP', esc(x.ip) + ' (' + ipCell(x.ip, x.location) + ')') +
            detLine('Site', esc(x.site)) + detLine('URL address', esc(x.uri)) +
            detLine('Reason for blocking', esc(x.reason)) + detLine('Blocks before the ban', x.hits ? String(x.hits) : '') +
            detLine('Time', x.secs + 's') + detLine('Status', x.blocking ? '<span class="red">Blocking</span>' : 'Expired') + '</div>'
        });
      });

      // tick the countdowns locally instead of re-polling the table
      if (S.timer) { clearInterval(S.timer); S.timer = null; }
      if (r.live) {
        S.timer = setInterval(function () {
          $('.wp-left').each(function () {
            var left = $(this).data('until') - Math.floor(Date.now() / 1000);
            $(this).text(left > 0 ? 'Blocking (' + fmtLeft(left) + ')' : 'Expired');
            if (left <= 0) $(this).removeClass('red wp-left');
          });
        }, 1000);
      }
    });
  }
  function fmtTime(t) {
    var d = new Date(t * 1000), p = function (x) { return (x < 10 ? '0' : '') + x; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
      p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }
  function fmtLeft(s) {
    if (s <= 0) return 'expired';
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
    return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
  }

  /* ================= Rule hit record ================= */
  function blRuleHit() {
    S.hitSize = S.hitSize || 10;
    var h = toolbar([{ id: 'wp-hit-clear', t: 'Clear log' }, { id: 'wp-hit-type', t: 'Configure record type' }], S.hitQ, 'wp-hit-q');
    h += '<div id="wp-hit-result"><div class="wp-loading">Loading...</div></div>';
    $('#wp-bl-body').html(h);
    bindSearch('wp-hit-q', function (q) { S.hitQ = q; loadHits(1); });
    $('#wp-hit-clear').on('click', function () {
      layer.confirm('Note: Rule hit records cannot be restored after being cleared!', { icon: 3, title: 'Clear rule hit records' }, function (i) {
        layer.close(i);
        post('rulehit_clear', {}, function (rr) { reply(rr, function () { loadHits(1); }); });
      });
    });
    $('#wp-hit-type').on('click', recordTypeDialog);
    loadHits(1);
  }
  function recordTypeDialog() {
    var t = S.hitType || 'all';
    layer.open({
      type: 1, title: 'Configure record type', area: ['400px', 'auto'], btn: ['Save', 'Cancel'],
      content: '<div class="wp-g-dlg"><div style="display:flex;gap:24px">' +
        '<label class="wp-g-chk"><input type="checkbox" id="wp-ht-i"' + (t === 'all' || t === 'intercept' ? ' checked' : '') + '> Intercept</label>' +
        '<label class="wp-g-chk"><input type="checkbox" id="wp-ht-r"' + (t === 'all' || t === 'release' ? ' checked' : '') + '> Release</label></div>' +
        '<div style="color:#909399;font-size:12px;margin-top:12px">*Note: Check the logs that need to be recorded. ' +
        'Custom rules write a row when they intercept or release (allow) a request — at most once per IP and rule every 30 seconds.</div></div>',
      yes: function (i) {
        var a = $('#wp-ht-i').is(':checked'), b = $('#wp-ht-r').is(':checked');
        var v = a && b ? 'all' : a ? 'intercept' : b ? 'release' : 'none';
        layer.close(i);
        post('save_config', { config: JSON.stringify({ rulehit_type: v }) }, function (rr) {
          reply(rr, function () { S.hitType = v; });
        });
      }
    });
  }
  function loadHits(p) {
    post('rulehit_logs', { q: S.hitQ || '', p: p, size: S.hitSize, act: S.hitAct || '' }, function (r) {
      if (!r.status) { $('#wp-hit-result').html('<div class="wp-empty">' + esc(r.msg || 'error') + '</div>'); return; }
      S.hitType = r.record_type;
      var rows = r.data || [];
      var h = '<div class="wp-bl-date"><div class="wp-seg-btn" id="wp-hit-act">' +
        [['', 'All'], ['intercept', 'Intercept'], ['release', 'Release']].map(function (x) {
          return '<span class="' + ((S.hitAct || '') === x[0] ? 'on' : '') + '" data-a="' + x[0] + '">' + x[1] + '</span>';
        }).join('') + '</div><span class="wp-match-s" style="margin-left:12px">Recording: ' +
        ({ all: 'Intercept + Release', intercept: 'Intercept only', release: 'Release only', none: 'Nothing (off)' })[r.record_type] +
        '</span></div>';
      h += '<div class="wp-site-box"><table class="wp-site-tbl"><thead><tr>' +
        '<th>Start time</th><th>Status</th><th>Hit rule</th><th>Domain name</th><th>Access IP</th><th>Region</th><th>URL address</th>' +
        '</tr></thead><tbody>';
      h += rows.length ? rows.map(function (x) {
        return '<tr><td>' + esc(x.time_s) + '</td>' +
          '<td' + (x.act === 'intercept' ? ' class="red">Intercept' : ' style="color:var(--wp-green)">Release') + '</td>' +
          '<td class="ell">' + esc(x.name) + '</td><td class="ell">' + esc(x.site) + '</td>' +
          '<td>' + esc(x.ip) + '</td><td class="ell">' + ipCell(x.ip, x.location) + '</td>' +
          '<td class="ell" title="' + esc(x.uri) + '">' + esc((x.method ? x.method + ' ' : '') + x.uri) + '</td></tr>';
      }).join('') : '<tr><td colspan="7" class="wp-empty">No Data</td></tr>';
      h += '</tbody></table></div>' + pager(r.p, r.pages, r.total, 'wp-hit-pg', S.hitSize);
      $('#wp-hit-result').html(h);
      bindPager('wp-hit-pg', r.pages, loadHits, function (k) { S.hitSize = k; loadHits(1); });
      $('#wp-hit-act span').on('click', function () { S.hitAct = $(this).data('a') || ''; loadHits(1); });
    });
  }

  // exports
  W.BL_SUBS = BL_SUBS;
  W.bindPager = bindPager;
  W.blIntercept = blIntercept;
  W.blIpBlock = blIpBlock;
  W.blRuleHit = blRuleHit;
  W.fmtLeft = fmtLeft;
  W.loadIntercept = loadIntercept;
  W.pageBlockade = pageBlockade;
  W.pager = pager;
  W.routeBlockade = routeBlockade;
})(window.WAFPRO = window.WAFPRO || {});
