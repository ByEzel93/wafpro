(function (W) {
  // generated wiring: names declared in other modules
  var API = W.API;
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function renderTabs() { return W.renderTabs.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }

  /* ================= BLOCKADE (3 sub-tabs, like the Pro UI) ================= */
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
      routeBlockade();
    });
    routeBlockade();
  }
  function routeBlockade() {
    if (S.blSub === 'intercept') return blIntercept();
    if (S.blSub === 'ipblock') return blIpBlock();
    if (S.blSub === 'rulehit') return blRuleHit();
  }

  /* ---- Blockade > Interception record ---- */
  function blIntercept() {
    S.blDate = S.blDate || 'all';
    var h = '<div class="wp-bl-bar">' +
      '<div class="wp-search"><input class="wp-in" id="wp-bl-q" placeholder="Domain name/IP/URL/User-Agent/Region" value="' + esc(S.blQ || '') + '">' +
      '<span class="wp-search-i">&#9906;</span></div>' +
      '<span class="wp-btn primary" id="wp-bl-search">Search</span>' +
      '<span class="wp-btn" id="wp-bl-export">Export</span>' +
      '<span class="wp-btn" id="wp-bl-clear">Clear log</span>' +
      '<div class="wp-seg" id="wp-bl-date" style="margin-left:auto">' +
      ['all', 'today', 'yesterday'].map(function (d) {
        return '<span class="' + (S.blDate === d ? 'on' : '') + '" data-d="' + d + '">' +
          (d === 'all' ? 'All' : d === 'today' ? 'Today' : 'Yesterday') + '</span>';
      }).join('') + '</div>' +
      '<select class="wp-in" id="wp-bl-day" style="width:150px"><option value="">Select Date</option></select>' +
      '</div>';
    h += '<div id="wp-bl-result"><div class="wp-loading">Loading...</div></div>';
    $('#wp-bl-body').html(h);

    post('get_log_dates', {}, function (r) {
      $('#wp-bl-day').append((r.dates || []).map(function (d) {
        return '<option value="' + esc(d) + '"' + (S.blDate === d ? ' selected' : '') + '>' + esc(d) + '</option>';
      }).join(''));
    });
    $('#wp-bl-search').on('click', function () { S.blQ = $('#wp-bl-q').val() || ''; loadIntercept(1); });
    $('#wp-bl-q').on('keydown', function (e) { if (e.keyCode === 13) { S.blQ = $(this).val() || ''; loadIntercept(1); } });
    $('#wp-bl-date span').on('click', function () {
      S.blDate = $(this).data('d');
      $('#wp-bl-date span').removeClass('on'); $(this).addClass('on');
      $('#wp-bl-day').val('');
      loadIntercept(1);
    });
    $('#wp-bl-day').on('change', function () {
      var v = $(this).val();
      if (v) { S.blDate = v; $('#wp-bl-date span').removeClass('on'); loadIntercept(1); }
    });
    $('#wp-bl-export').on('click', function () {
      post('export_logs', { date: S.blDate, q: S.blQ || '' }, function (rr) {
        if (!rr.status) { layer.msg(rr.msg || 'Export failed', { icon: 2 }); return; }
        layer.msg(rr.rows + ' rows exported', { icon: 1 });
        window.open(API + 'download_export&filename=' + encodeURIComponent(rr.filename));
      });
    });
    $('#wp-bl-clear').on('click', function () {
      layer.confirm('Delete the intercept log files for the current date filter?<br>This cannot be undone.',
        { icon: 3, title: 'Clear log' }, function (i) {
          layer.close(i);
          post('clear_logs', { date: S.blDate }, function (rr) {
            layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); loadIntercept(1);
          });
        });
    });
    loadIntercept(1);
  }

  function loadIntercept(p) {
    $('#wp-bl-result').html('<div class="wp-loading">Loading...</div>');
    post('get_logs', { date: S.blDate, q: S.blQ || '', p: p, size: 10 }, function (r) {
      if (!r.status) { $('#wp-bl-result').html('<div class="wp-empty">' + esc(r.msg || 'error') + '</div>'); return; }
      S.blRows = r.data || [];
      var h = '<div class="wp-match"><div class="wp-match-n">Match result: ' + num(r.total) + '</div>' +
        '<div class="wp-match-s">Query time: ' + (S.blDate === 'all' ? 'All' : S.blDate) +
        (S.blQ ? ' · keyword: ' + esc(S.blQ) : '') + '</div></div>';
      h += '<table class="wp-tbl"><thead><tr>' +
        '<th style="width:140px">Start time</th><th style="width:120px">User IP</th>' +
        '<th style="width:130px">Domain name</th><th style="width:56px">Type</th>' +
        '<th>URL address</th><th style="width:86px">Status</th>' +
        '<th style="width:130px">IP location</th><th style="width:130px">Filter</th>' +
        '<th style="width:150px">Operate</th></tr></thead><tbody>';
      h += S.blRows.length ? S.blRows.map(function (x, i) {
        return '<tr><td>' + x.time + '</td><td>' + x.ip + '</td>' +
          '<td class="ell" title="' + x.site + '">' + x.site + '</td>' +
          '<td>' + x.method + '</td>' +
          '<td class="ell" title="' + x.url + '">' + x.url + '</td>' +
          '<td><span class="wp-chip red">Intercepted</span></td>' +
          '<td class="ell" title="' + x.location + '">' + x.location + '</td>' +
          '<td class="ell" title="' + x.filter_name + '">' + x.filter_name + '</td>' +
          '<td class="wp-ops"><span class="wp-lnk bl-ip" data-i="' + i + '">Block IP</span>' +
          '<span class="wp-ops-sep">|</span><span class="wp-lnk bl-url" data-i="' + i + '">White URL</span>' +
          '<span class="wp-ops-sep">|</span><span class="wp-lnk bl-det" data-i="' + i + '">Details</span></td></tr>';
      }).join('') : '<tr><td colspan="9" class="wp-empty">No records match the filter</td></tr>';
      h += '</tbody></table>';
      h += pager(r.p, r.pages, r.total, 'wp-bl-pg');
      $('#wp-bl-result').html(h);

      bindPager('wp-bl-pg', r.pages, loadIntercept);
      $('.bl-ip').on('click', function () {
        var x = S.blRows[$(this).data('i')];
        layer.confirm('Add <b>' + x.ip + '</b> to the IP blacklist?<br>' +
          '<span style="color:#9aa1ab;font-size:12px">It will appear under <b>Black/White list › IP blacklist</b> ' +
          'and every request from it is dropped from now on.</span>',
          { icon: 3, title: 'Block IP' }, function (i2) {
            layer.close(i2);
            post('list_add', { list_name: 'ip_black', value: x.ip }, function (rr) {
              // report what actually happened — never assume success
              layer.msg((rr && rr.msg) || 'No response', { icon: (rr && rr.status) ? 1 : 2 });
            });
          });
      });
      $('.bl-url').on('click', function () {
        var x = S.blRows[$(this).data('i')];
        var u = ($('<div>').html(x.url).text() || '').split('?')[0];
        layer.confirm('Add <b>' + esc(u) + '</b> to the URL whitelist?<br>' +
          '<span style="color:#9aa1ab;font-size:12px">Requests to it will skip filtering — check it is not attacker-controlled.</span>',
          { icon: 3, title: 'White URL' }, function (i2) {
            layer.close(i2);
            post('list_add', { list_name: 'url_white', value: u }, function (rr) {
              layer.msg((rr && rr.msg) || 'No response', { icon: (rr && rr.status) ? 1 : 2 });
            });
          });
      });
      $('.bl-det').on('click', function () {
        var x = S.blRows[$(this).data('i')];
        layer.open({
          type: 1, title: 'Intercept detail', area: ['640px', '400px'],
          content: '<div class="wp-modal" style="padding:18px 22px;overflow:auto;line-height:2;word-break:break-all">' +
            detRow('Start time', x.time) + detRow('User IP', x.ip) + detRow('IP location', x.location) +
            detRow('Domain name', x.site) + detRow('Type', x.method) + detRow('URL address', x.url) +
            detRow('Status', 'Intercepted') + detRow('Filter', x.filter_name) +
            detRow('Rule', '<code style="font-size:12px">' + x.rule + '</code>') +
            detRow('User-Agent', x.ua) + '</div>'
        });
      });
    });
  }
  function detRow(k, v) {
    return '<div style="display:flex;gap:10px;padding:3px 0">' +
      '<div style="width:110px;color:#9aa1ab;flex:none;text-align:right">' + k + '</div>' +
      '<div style="color:#1f2329">' + (v || '-') + '</div></div>';
  }

  /* ---- shared pager ---- */
  function pager(cur, pages, total, id) {
    var h = '<div class="wp-pager" id="' + id + '">';
    h += '<span class="wp-btn pg" data-p="prev">&#8249;</span>';
    var list = [];
    for (var i = 1; i <= pages; i++) {
      if (i <= 2 || i > pages - 2 || Math.abs(i - cur) <= 2) list.push(i);
      else if (list[list.length - 1] !== '...') list.push('...');
    }
    list.forEach(function (i) {
      h += (i === '...') ? '<span style="color:var(--wp-text3);padding:0 4px">…</span>'
        : '<span class="wp-btn pg' + (i === cur ? ' primary' : '') + '" data-p="' + i + '" style="min-width:32px;justify-content:center">' + i + '</span>';
    });
    h += '<span class="wp-btn pg" data-p="next">&#8250;</span>';
    h += '<span style="color:var(--wp-text2);margin-left:6px">Total ' + num(total) + '</span></div>';
    return h;
  }
  function bindPager(id, pages, fn) {
    $('#' + id + ' .pg').on('click', function () {
      var p = $(this).data('p');
      var cur = parseInt($('#' + id + ' .primary').data('p'), 10) || 1;
      if (p === 'prev') p = Math.max(cur - 1, 1);
      else if (p === 'next') p = Math.min(cur + 1, pages);
      fn(parseInt(p, 10));
    });
  }

  /* ---- Blockade > Rule hit record ---- */
  function blRuleHit() {
    $('#wp-bl-body').html('<div class="wp-loading">Loading...</div>');
    post('rule_hits', {}, function (r) {
      if (!r.status) { $('#wp-bl-body').html('<div class="wp-empty">error</div>'); return; }
      var h = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">';
      h += '<div><div class="wp-sub-t">Hits by filter (all time: ' + num(r.total) + ')</div>' +
        '<table class="wp-tbl"><thead><tr><th>Filter</th><th style="width:90px">Hits</th></tr></thead><tbody>' +
        (r.rules.length ? r.rules.map(function (x) {
          return '<tr><td>' + esc(x.name) + '</td><td style="color:' + (x.count ? 'var(--wp-red)' : 'var(--wp-text3)') +
            ';font-weight:600">' + num(x.count) + '</td></tr>';
        }).join('') : '<tr><td colspan="2" class="wp-empty">No data</td></tr>') + '</tbody></table></div>';
      h += '<div><div class="wp-sub-t">Hits by site</div>' +
        '<table class="wp-tbl"><thead><tr><th>Site</th><th>Filter</th><th style="width:80px">Hits</th></tr></thead><tbody>' +
        (r.per_site.length ? r.per_site.map(function (x) {
          return '<tr><td class="ell">' + esc(x.site) + '</td><td>' + esc(x.name) + '</td>' +
            '<td style="color:var(--wp-red);font-weight:600">' + num(x.count) + '</td></tr>';
        }).join('') : '<tr><td colspan="3" class="wp-empty">No data</td></tr>') + '</tbody></table></div>';
      h += '</div>';
      $('#wp-bl-body').html(h);
    });
  }

  /* ---- Blockade > IP blocking record ---- */
  function blIpBlock() {
    $('#wp-bl-body').html('<div class="wp-loading">Loading...</div>');
    post('bans', {}, function (r) {
      if (!r.status) { $('#wp-bl-body').html('<div class="wp-note">' + esc(r.msg || 'error') + '</div>'); return; }
      var ips = r.data || [];
      var h = '<div class="wp-note-sm">These are <b>temporary</b> blocks the engine applies by itself: an IP lands here ' +
        'after tripping <b>' + r.retry + '</b> rules within <b>' + r.retry_cycle + 's</b>, or by exceeding ' +
        '<b>CC defense</b>, and leaves on its own when the time runs out.<br>' +
        'IPs you block by hand live in <b>Black/White list › IP blacklist</b> and stay until you remove them.</div>';
      h += '<div style="display:flex;align-items:center;margin-bottom:12px">' +
        '<div class="wp-sub-t" style="margin:0">Currently blocked IPs (' + ips.length + ')</div>' +
        '<span class="wp-lnk" id="wp-goto-black" style="margin-left:12px">Go to IP blacklist &#8250;</span>' +
        (ips.length ? '<span class="wp-btn" id="wp-clean-drop" style="margin-left:auto">Unblock all</span>' : '') +
        '</div>';
      h += '<table class="wp-tbl"><thead><tr><th style="width:150px">IP</th><th style="width:190px">IP location</th>' +
        '<th style="width:150px">Tripped</th><th style="width:110px">Expires in</th>' +
        '<th>Site</th><th style="width:90px">Operate</th></tr></thead><tbody>';
      h += ips.length ? ips.map(function (x) {
        return '<tr><td style="color:var(--wp-text);font-weight:600">' + esc(x.ip) + '</td>' +
          '<td class="wp-geo" data-ip="' + esc(x.ip) + '">-</td>' +
          '<td>' + esc(x.rule) + ' <span style="color:var(--wp-text3)">&times;' + x.hits + '</span></td>' +
          '<td class="wp-left" data-until="' + x.until + '">' + fmtLeft(x.left) + '</td>' +
          '<td>' + esc(x.site) + '</td>' +
          '<td><span class="wp-lnk wp-unban" data-ip="' + esc(x.ip) + '">Unblock</span></td></tr>';
      }).join('') : '<tr><td colspan="6" class="wp-empty">No IP is currently blocked.</td></tr>';
      h += '</tbody></table>';
      $('#wp-bl-body').html(h);
      resolveGeo();

      // tick the countdown locally instead of re-polling the whole table
      if (S.timer) clearInterval(S.timer);
      if (ips.length) {
        S.timer = setInterval(function () {
          var live = 0;
          $('.wp-left').each(function () {
            var left = $(this).data('until') - Math.floor(Date.now() / 1000);
            if (left > 0) { live++; $(this).text(fmtLeft(left)); }
            else $(this).text('expired');
          });
          if (!live) { clearInterval(S.timer); S.timer = null; blIpBlock(); }
        }, 1000);
      }

      $('#wp-goto-black').on('click', function () {
        S.listKey = 'ip_black'; S.tab = 'lists'; renderTabs(); route();
      });
      $('.wp-unban').on('click', function () {
        var ip = $(this).data('ip');
        post('unban', { ip: ip }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) setTimeout(blIpBlock, 400);
        });
      });
      $('#wp-clean-drop').on('click', function () {
        layer.confirm('Unblock every currently blocked IP?', { icon: 3, title: 'Clear blocklist' }, function (i) {
          layer.close(i);
          post('unban_all', {}, function (rr) {
            layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
            setTimeout(blIpBlock, 400);
          });
        });
      });
    });
  }
  function fmtLeft(s) {
    if (s <= 0) return 'expired';
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
    return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
  }
  function resolveGeo() {
    var ips = [];
    $('.wp-geo').each(function () { ips.push($(this).data('ip')); });
    if (!ips.length) return;
    post('geo_batch', { ips: JSON.stringify(ips) }, function (r) {
      if (!r.status) return;
      $('.wp-geo').each(function () {
        var g = r.data[$(this).data('ip')];
        $(this).text(g && g.country ? (g.country + (g.city ? ' / ' + g.city : '')) : 'Unknown');
      });
    });
  }


  // exports
  W.BL_SUBS = BL_SUBS;
  W.bindPager = bindPager;
  W.blIntercept = blIntercept;
  W.blIpBlock = blIpBlock;
  W.blRuleHit = blRuleHit;
  W.detRow = detRow;
  W.fmtLeft = fmtLeft;
  W.loadIntercept = loadIntercept;
  W.pageBlockade = pageBlockade;
  W.pager = pager;
  W.resolveGeo = resolveGeo;
  W.routeBlockade = routeBlockade;
})(window.WAFPRO = window.WAFPRO || {});
