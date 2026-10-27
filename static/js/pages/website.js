(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }

  /* ================= WEBSITE =================
     The aaPanel 8 WAF's site list: malicious-IP switch and search on top,
     one row per site (Site | Total interceptions | Fake spider | Using CDN |
     Smart CC defense | Crawl Protection | Waiting Room/Rate Limit |
     CC Defense | Status | Operate: Log, Set), two tips below. "Set" opens
     "Website Configuration [site]": the site's protections as one table of
     Name / Description / Status / Operate, each switch applied at once. */
  function pageWebsite() {
    $('#wp-body').html('<div class="wp-loading">Loading...</div>');
    post('get_sites', {}, function (r) {
      S.sites = r.data || [];
      S.malOpen = r.mal_open;
      S.sitePage = S.sitePage || 1; S.siteSize = S.siteSize || 10; S.siteQ = S.siteQ || '';
      var h = '<div class="wp-card wp-site-card">';
      h += '<div class="wp-site-top">' +
        '<label class="wp-site-mal">Intercept access from known malicious IPs of aaPanel ' +
        '<input type="checkbox" class="wp-cb" id="wp-mal-all"' + (r.mal_open ? ' checked' : '') + '></label>' +
        '<div class="wp-site-search"><input class="wp-in" id="wp-site-q" placeholder="Please enter site name" value="' +
        esc(S.siteQ) + '"><span class="wp-site-search-i" id="wp-site-go">' + icoSearch() + '</span></div></div>';
      h += '<div id="wp-site-table"></div>';
      h += '<ul class="wp-site-tips">' +
        '<li>CDN option: After enabling CDN for a website, the CDN button must be turned on. Otherwise, the IPs of CDN ' +
        'nodes will be intercepted.</li></ul></div>';
      $('#wp-body').html(h);
      renderSiteTable();
      function search() { S.siteQ = ($('#wp-site-q').val() || '').toLowerCase(); S.sitePage = 1; renderSiteTable(); }
      $('#wp-site-q').on('input', search);
      $('#wp-site-go').on('click', search);
      $('#wp-mal-all').on('change', function () {
        var on = this.checked;
        post('malicious_toggle', { open: on ? 1 : 0 }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (!rr.status) $('#wp-mal-all').prop('checked', !on);
        });
      });
    });
  }

  function siteFiltered() {
    return S.sites.filter(function (s) {
      if (!S.siteQ) return true;
      return (s.name + ' ' + (s.domains || []).join(' ')).toLowerCase().indexOf(S.siteQ) !== -1;
    });
  }

  function icoSearch() {
    return '<svg class="wp-ico" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>';
  }
  function qmark(tip) { return '<span class="wp-qm" data-pop="' + popHtml(tip) + '">?</span>'; }

  /* ---------- hover popovers (the stock n-popover / n-tooltip) ----------
     Any element with data-pop shows that HTML below it while hovered. */
  function bindPops($root) {
    $root.on('mouseenter', '[data-pop]', function () {
      $('.wp-pop').remove();
      var r = this.getBoundingClientRect();
      var $p = $('<div class="wp-pop">' + $(this).attr('data-pop') + '</div>').appendTo(document.body);
      var left = Math.min(r.left, window.innerWidth - $p.outerWidth() - 10);
      $p.css({ left: Math.max(left, 10) + 'px', top: (r.bottom + 8) + 'px' });
      $p.find('.wp-pop-arrow').css('left', Math.max(r.left - left + r.width / 2 - 5, 8) + 'px');
    });
    $root.on('mouseleave', '[data-pop]', function () { $('.wp-pop').remove(); });
  }
  function popHtml(inner) { return esc('<span class="wp-pop-arrow"></span>' + inner); }
  function timesPop(n) { return popHtml('Interception times: ' + num(n) + ' times'); }
  function hitLabel(rule) { return W.ruleLabel ? W.ruleLabel(rule) : rule; }

  function renderSiteTable() {
    var all = siteFiltered();
    var pages = Math.max(Math.ceil(all.length / S.siteSize), 1);
    if (S.sitePage > pages) S.sitePage = pages;
    var rows = all.slice((S.sitePage - 1) * S.siteSize, S.sitePage * S.siteSize);

    var h = '<div class="wp-site-box"><table class="wp-site-tbl"><thead><tr>' +
      '<th style="min-width:150px">Site</th><th style="width:10%">Total interceptions</th>' +
      '<th style="width:12%">Fake spider' + qmark('Intercept forged spider IPs') + '</th>' +
      '<th style="width:12%">Using CDN' + qmark('CDN: A switch for obtaining IPs when a website enables CDN.') + '</th>' +
      '<th style="width:14%">Smart CC defense' + qmark('<div style="width:500px;white-space:normal">According to website load ' +
        'conditions, automatically analyze whether an attack is in progress and tighten each visitor\'s CC allowance ' +
        'while it lasts, thereby reducing the impact on business.</div>') + '</th>' +
      '<th style="width:9%">Crawl Protection</th><th style="width:10%">Waiting Room/Rate Limit</th>' +
      '<th style="width:8%">CC Defense</th><th style="width:6%">Status</th><th class="r" style="width:100px">Operate</th>' +
      '</tr></thead><tbody>';
    h += rows.length ? rows.map(function (s) {
      var n = esc(s.name);
      var total = s.intercepts || 0;
      var byPop = popHtml((s.hits_by || []).map(function (x) {
        return '<div class="wp-pop-line">' + esc(hitLabel(x[0])) + ': ' + num(x[1]) + ' times</div>';
      }).join('') || '<div class="wp-pop-line">No interceptions today</div>');
      return '<tr>' +
        '<td class="site"><span class="wp-lnk wp-site-set" data-n="' + n + '" title="' +
          esc((s.domains || []).join(', ')) + '">' + n + '</span></td>' +
        '<td><span data-pop="' + byPop + '">' + (total > 0 ? '<span class="wp-lnk err wp-site-total" data-n="' + n + '">' +
          num(total) + '</span>' : '0') + '</span></td>' +
        '<td>' + cbx(s.name, 'fake_spider', s.fake_spider) + '</td>' +
        '<td>' + cbx(s.name, 'cdn', s.cdn) + '</td>' +
        '<td><span class="wp-cell-in">' + cbx(s.name, 'smart_cc', s.smart_cc) +
          '<span class="cnt" data-pop="' + timesPop(s.smart_hits) + '">' + num(s.smart_hits) + '</span></span></td>' +
        '<td><span class="wp-lnk wp-site-crawl' + (s.crawl ? '' : ' err') + '" data-n="' + n + '">' +
          (s.crawl ? 'Enable' : 'Disable') + '</span></td>' +
        '<td><span class="wp-lnk wp-site-wait' + (s.wait ? '' : ' err') + '" data-n="' + n + '">' +
          (s.wait ? 'Enable' : 'Disable') + '</span></td>' +
        '<td><span class="wp-cell-in">' + cbx(s.name, 'cc_open', s.cc_open) +
          '<span class="cnt" data-pop="' + timesPop(s.cc_hits) + '">' + num(s.cc_hits) + '</span></span></td>' +
        '<td><label class="wp-sw wp-sw-sm"><input type="checkbox" class="wp-site-sw" data-n="' + n + '"' +
          (s.open ? ' checked' : '') + '><span class="sl"></span></label></td>' +
        '<td class="r"><span class="wp-lnk wp-site-log" data-n="' + n + '">Log</span><span class="sep"></span>' +
        '<span class="wp-lnk wp-site-set" data-n="' + n + '">Set</span></td></tr>';
    }).join('') : '<tr><td colspan="10" class="wp-empty">' +
      (S.sites.length ? 'No site matches "' + esc(S.siteQ) + '"' : 'No Data') + '</td></tr>';
    h += '</tbody></table></div>';

    // pagination: ‹ 1 2 ›  [10 / page]  Goto [ ]  Total N
    h += '<div class="wp-site-pager"><span class="pg nav' + (S.sitePage <= 1 ? ' dis' : '') + '" data-p="prev">&#8249;</span>';
    for (var i = 1; i <= pages; i++) {
      h += '<span class="pg' + (i === S.sitePage ? ' cur' : '') + '" data-p="' + i + '">' + i + '</span>';
    }
    h += '<span class="pg nav' + (S.sitePage >= pages ? ' dis' : '') + '" data-p="next">&#8250;</span>' +
      '<select class="wp-in" id="wp-site-size">' + [10, 20, 50, 100].map(function (k) {
        return '<option value="' + k + '"' + (k === S.siteSize ? ' selected' : '') + '>' + k + ' / page</option>';
      }).join('') + '</select>' +
      '<span class="lbl">Goto</span><input class="wp-in goto" id="wp-site-goto" value="' + S.sitePage + '">' +
      '<span class="lbl total">Total ' + all.length + '</span></div>';

    var $t = $('#wp-site-table');
    $t.off().html(h);
    bindPops($t);

    $t.on('change', '.wp-site-sw', function () {
      setField($(this).data('n'), 'open', this.checked);
    });
    $t.on('change', '.wp-cbx', function () {
      var n = $(this).data('n'), f = $(this).data('f'), on = this.checked, $cb = $(this);
      if (f === 'smart_cc' && on) {
        $cb.prop('checked', false);
        W.confirm('Smart CC defense will automatically determine if there is high load or slow response. If there is ' +
          'an abnormality, each visitor\'s CC allowance is tightened until the load drops.', function (i) {
          layer.close(i); $cb.prop('checked', true); setField(n, f, true);
        });
        return;
      }
      setField(n, f, on);
    });
    $t.on('click', '.pg', function () {
      var p = $(this).data('p');
      if (p === 'prev') S.sitePage = Math.max(S.sitePage - 1, 1);
      else if (p === 'next') S.sitePage = Math.min(S.sitePage + 1, pages);
      else S.sitePage = parseInt(p, 10);
      renderSiteTable();
    });
    $t.on('change', '#wp-site-size', function () {
      S.siteSize = parseInt($(this).val(), 10); S.sitePage = 1; renderSiteTable();
    });
    $t.on('keydown', '#wp-site-goto', function (e) {
      if (e.keyCode !== 13) return;
      var p = parseInt($(this).val(), 10);
      if (p >= 1 && p <= pages) { S.sitePage = p; renderSiteTable(); }
    });
    $t.on('click', '.wp-site-total', function () { totalDialog($(this).data('n')); });
    $t.on('click', '.wp-site-log', function () { siteLogDialog($(this).data('n')); });
    $t.on('click', '.wp-site-set', function () { siteConfig($(this).data('n')); });
    $t.on('click', '.wp-site-crawl', function () { crawlDialog($(this).data('n')); });
    $t.on('click', '.wp-site-wait', function () { waitDialog($(this).data('n')); });
  }

  function cbx(name, field, on) {
    return '<input type="checkbox" class="wp-cb wp-cbx" data-n="' + esc(name) + '" data-f="' + field + '"' + (on ? ' checked' : '') + '>';
  }

  // one site field, saved at once (the stock switches have no Save button)
  function setField(name, field, value, done) {
    var v = typeof value === 'boolean' ? (value ? '1' : '0') : value;
    post('set_site_field', { siteName: name, field: field, value: v }, function (rr) {
      layer.msg(rr.status ? 'Setup successfully' : rr.msg, { icon: rr.status ? 1 : 2 });
      if (!rr.status) return;
      var s = siteRow(name);
      if (s) s[field] = typeof value === 'boolean' ? value : (/^-?\d+$/.test(String(v)) ? +v : v);
      if (done) done();
    });
  }
  function refreshList() { if (S.tab === 'website') pageWebsite(); }

  /* ---------- Total interception times [site] ---------- */
  function totalDialog(name) {
    var s = siteRow(name) || {};
    var rows = (s.hits_by || []).map(function (x) {
      return '<tr><td>' + esc(hitLabel(x[0])) + '</td><td><span class="wp-lnk err" data-pop="' + timesPop(x[1]) + '">' +
        num(x[1]) + '</span></td></tr>';
    }).join('') || '<tr><td colspan="2" class="wp-empty">No Data</td></tr>';
    W.open({
      type: 1, title: 'Total interception times [' + esc(name) + ']', area: ['480px', 'auto'],
      content: '<div class="wp-modal wp-g-dlg"><table class="wp-site-tbl"><thead><tr><th>Type</th><th>Interception times</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table>' +
        '<ul class="wp-site-tips"><li>Counted from today\'s interception log.</li></ul></div>',
      success: function (el) { bindPops($(el)); }
    });
  }

  /* ---------- Interception log [site] ---------- */
  function siteLogDialog(name) {
    post('get_logs', { siteName: name, date: 'all', p: 1, size: 5 }, function (r) {
      if (!r.status || !r.total) return layer.msg('No site logs for now', { icon: 1 });
      var st = { date: 'today', p: 1, size: 15 };
      W.open({
        type: 1, title: 'Interception log [' + esc(name) + ']', area: ['1100px', 'auto'],
        content: '<div class="wp-modal wp-g-dlg wp-slog"><div class="wp-slog-top"><span>Select date:</span>' +
          '<div class="wp-seg-btn" id="slog-date">' + [['today', 'Today'], ['yesterday', 'Yesterday'], ['all', 'All']].map(function (x) {
            return '<span class="' + (x[0] === st.date ? 'on' : '') + '" data-d="' + x[0] + '">' + x[1] + '</span>';
          }).join('') + '</div><span class="wp-btn" id="slog-pick">' + W.icoCalendar() + '<span>Select date</span></span></div>' +
          '<div id="slog-body"><div class="wp-loading">Loading...</div></div></div>',
        success: function (el) {
          var $el = $(el);
          function load() {
            post('get_logs', { siteName: name, date: st.date, p: st.p, size: st.size }, function (d) {
              var rows = d.data || [];
              var h = '<div class="wp-slog-box"><table class="wp-site-tbl"><thead><tr><th style="width:140px">Start time</th>' +
                '<th style="width:120px">User IP</th><th style="width:70px">Type</th><th>URL address</th>' +
                '<th style="width:90px">Status</th><th style="width:140px">IP attribution</th><th style="width:120px">Filter</th>' +
                '<th class="r" style="width:140px">Operate</th></tr></thead><tbody>' +
                (rows.length ? rows.map(function (x, i) {
                  return '<tr><td>' + x.time + '</td><td class="ell" title="' + x.ip + '">' + x.ip + '</td><td>' + x.method + '</td>' +
                    '<td class="ell" title="' + x.url + '">' + x.url + '</td><td>Intercepted</td>' +
                    '<td class="ell">' + (x.location || '') + '</td>' +
                    '<td class="ell" title="' + x.filter_name + '">' + x.filter_name + '</td>' +
                    '<td class="r"><span class="wp-lnk slog-white" data-i="' + i + '">White URL</span><span class="sep"></span>' +
                    '<span class="wp-lnk slog-det" data-i="' + i + '">Details</span></td></tr>';
                }).join('') : '<tr><td colspan="8" class="wp-empty">No Data</td></tr>') + '</tbody></table></div>' +
                W.pager(d.p || 1, d.pages || 1, d.total || 0, 'slog-pg', st.size);
              $el.find('#slog-body').html(h);
              $el.find('#slog-pg .pg-size').html([10, 15].map(function (k) {
                return '<option value="' + k + '"' + (k === st.size ? ' selected' : '') + '>' + k + ' / page</option>';
              }).join(''));
              W.bindPager('slog-pg', d.pages || 1, function (p) { st.p = p; load(); }, function (k) { st.size = k; st.p = 1; load(); });
              $el.find('.slog-white').on('click', function () { W.whiteUrl(rows[$(this).data('i')].url); });
              $el.find('.slog-det').on('click', function () { W.interceptDetail(rows[$(this).data('i')]); });
            });
          }
          $el.on('click', '#slog-date span', function () {
            st.date = $(this).data('d'); st.p = 1;
            $el.find('#slog-date span').removeClass('on'); $(this).addClass('on');
            $el.find('#slog-pick span').text('Select date');
            load();
          });
          $el.on('click', '#slog-pick', function () {
            W.pickDate(this, { max: W.todayStr(), done: function (v) {
              if (!v) return;
              st.date = v; st.p = 1;
              $el.find('#slog-date span').removeClass('on');
              $el.find('#slog-pick span').text(v);
              load();
            } });
          });
          load();
        }
      });
    });
  }

  /* ---------- Crawl Protection [site] / Waiting Room/Rate Limit [site] ---------- */
  function crawlDialog(name) {
    var s = siteRow(name) || {};
    W.gDialog('Crawl Protection [' + esc(name) + ']', 620,
      W.fRow('Crawl Protection', W.sw('cp-open', s.crawl)) +
      W.fRow('Limit', W.nIn('cp-limit', s.crawl_limit || 30) + ' <span class="wp-unit">requests / minute per bot</span>') +
      '<ul class="wp-site-tips">' +
      '<li><b>Effect: </b>Clients that look like bots but are not verified search engine crawlers get their own, much ' +
        'tighter request budget. Past it they are intercepted.</li>' +
      '<li><b>Impact: </b>Monitoring tools, feed readers and API clients without a browser User-Agent count as bots.</li>' +
      '<li><b>Recommendation: </b>Verified crawlers (Google, Bing, Apple...) are never limited by this.</li></ul>',
      function (close) {
        save(name, { crawl: $('#cp-open').is(':checked'), crawl_limit: +$('#cp-limit').val() || 30 }, close);
      });
  }
  function waitDialog(name) {
    var s = siteRow(name) || {};
    W.gDialog('Waiting Room/Rate Limit [' + esc(name) + ']', 700,
      W.fRow('Waiting Room Switch', W.sw('wr-open', s.wait)) +
      W.fRow('QPS exceeds', W.nIn('wr-limit', s.wait_limit || 200) + ' <span class="wp-unit">times to trigger (whole site, per second)</span>') +
      W.fRow('Identification Page', '<span class="wp-btn" id="wr-page">Edit page</span>',
        'The page visitors over the limit see. It retries by itself.') +
      '<ul class="wp-site-tips">' +
      '<li><b>Effect: </b>Enabling the waiting room can help alleviate peak load issues: past the limit, extra visitors ' +
        'get the waiting page instead of a timeout.</li>' +
      '<li><b>Impact: </b>Visitors over the limit wait a few seconds before the page loads.</li>' +
      '<li><b>Suggestion: </b>Set the limit a little above the site\'s normal peak traffic.</li></ul>',
      function (close) {
        save(name, { wait: $('#wr-open').is(':checked'), wait_limit: +$('#wr-limit').val() || 200 }, close);
      });
    $('#wr-page').on('click', function () {
      post('get_waiting_html', {}, function (r) {
        W.htmlEditDialog({ title: 'Waiting room page', html: r.html, hint: 'Shown to visitors over the rate limit (HTML).',
          save: function (html, close) {
            post('save_waiting_html', { html: html }, function (rr) {
              layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) close();
            });
          } });
      });
    });
  }
  function save(name, patch, close) {
    post('save_site_detail', { siteName: name, config: JSON.stringify(patch) }, function (rr) {
      layer.msg(rr.status ? 'Setup successfully' : rr.msg, { icon: rr.status ? 1 : 2 });
      if (!rr.status) return;
      if (close) close();
      refreshList();
    });
  }

  /* ---------- Set CC Rules [site] ---------- */
  function siteCcDialog(name, c, done) {
    var keyOpts = [['ip', 'IP'], ['url', 'URL with param'], ['path', 'URL without param'], ['ipua', 'IP+UA']];
    W.gDialog('Set CC Rules [' + esc(name) + ']', 640,
      W.fRow('Mode', '<select class="wp-in" id="sc-mode" style="width:220px">' +
        '<option value="block"' + (c.cc_mode !== 'challenge' ? ' selected' : '') + '>Standard Mode</option>' +
        '<option value="challenge"' + (c.cc_mode === 'challenge' ? ' selected' : '') + '>Enhanced Mode</option></select>',
        'Enhanced: a client over the limit must pass browser verification instead of being blocked.') +
      W.fRow('Request Type', '<div class="wp-g-radios">' + keyOpts.map(function (k) {
        return '<label><input type="radio" name="sc-key" value="' + k[0] + '"' + ((c.cc_key || 'ip') === k[0] ? ' checked' : '') +
          '> ' + k[1] + '</label>';
      }).join('') + '</div>') +
      W.fRow('Access Time', W.nIn('sc-cycle', c.cc_cycle || 60) + ' <span class="wp-unit">Sec</span>') +
      W.fRow('Access Count', W.nIn('sc-limit', c.cc_limit || 120) + ' <span class="wp-unit">Time(s)</span>',
        'Recommended value is an integer greater than 30.') +
      W.fRow('Block Time', W.nIn('sc-block', c.cc_block || 600) + ' <span class="wp-unit">Sec</span>') +
      '<ul class="wp-site-tips"><li>Settings here only apply to the current site.</li>' +
      '<li>Please do not set overly strict CC rules to avoid affecting the normal user experience.</li></ul>',
      function (close) {
        var p = { cc_mode: $('#sc-mode').val(), cc_key: $('input[name=sc-key]:checked').val(),
                  cc_cycle: +$('#sc-cycle').val(), cc_limit: +$('#sc-limit').val(), cc_block: +$('#sc-block').val() };
        post('save_site_detail', { siteName: name, config: JSON.stringify(p) }, function (rr) {
          layer.msg(rr.status ? 'Setup successfully' : rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) { close(); if (done) done(); }
        });
      }, 'Apply');
  }

  /* ---------- HTTP package [site] ---------- */
  function bodyMaxDialog(name, c, done) {
    W.gDialog('HTTP package [' + esc(name) + ']', 480,
      W.fRow('Max body', W.nIn('bm-kb', c.body_max || 0) + ' <span class="wp-unit">KB</span>',
        'Largest request body allowed, uploads excluded. 0 = no limit (the Global value applies).'),
      function (close) {
        setField(name, 'body_max', String(Math.max(+$('#bm-kb').val() || 0, 0)), function () { close(); if (done) done(); });
      }, 'Apply');
  }

  /* ---------- comma lists: Forbidden extension, Block File types, Block php exec ---------- */
  function csvDialog(name, c, o, done) {
    var items = (c[o.field] || '').split(',').map(function (x) { return x.trim(); }).filter(Boolean);
    var idx = W.open({
      type: 1, title: o.title + ' [' + esc(name) + ']', area: ['560px', 'auto'],
      content: '<div class="wp-modal wp-g-dlg"><div class="wp-csv-add"><input class="wp-in" id="csv-in" placeholder="' +
        esc(o.ph) + '"><span class="wp-btn primary" id="csv-add">Add</span></div>' +
        '<div id="csv-tbl"></div><ul class="wp-site-tips">' + o.tips.map(function (t) { return '<li>' + t + '</li>'; }).join('') +
        '</ul></div>',
      success: function (el) {
        var $el = $(el);
        function draw() {
          $el.find('#csv-tbl').html('<div class="wp-csv-box"><table class="wp-site-tbl"><thead><tr><th>' + o.col +
            '</th><th class="r" style="width:80px">Operate</th></tr></thead><tbody>' +
            (items.length ? items.map(function (x, i) {
              return '<tr><td class="ell">' + esc(x) + '</td><td class="r"><span class="wp-lnk csv-del" data-i="' + i +
                '">Delete</span></td></tr>';
            }).join('') : '<tr><td colspan="2" class="wp-empty">No Data</td></tr>') + '</tbody></table></div>');
        }
        function commit() {
          var v = o.clean(items.join(','));
          setField(name, o.field, v, function () { c[o.field] = v; items = v ? v.split(',') : []; draw(); if (done) done(); });
        }
        $el.on('click', '#csv-add', function () {
          var add = o.clean($el.find('#csv-in').val() || '');
          if (!add) return layer.msg(o.empty, { icon: 2 });
          add.split(',').forEach(function (x) { if (items.indexOf(x) === -1) items.push(x); });
          $el.find('#csv-in').val('');
          commit();
        });
        $el.on('keydown', '#csv-in', function (e) { if (e.keyCode === 13) $el.find('#csv-add').click(); });
        $el.on('click', '.csv-del', function () { items.splice($(this).data('i'), 1); commit(); });
        draw();
      }
    });
    return idx;
  }
  function cleanPaths(v) {
    return (v || '').split(',').map(function (x) { return x.trim(); }).filter(Boolean).join(',');
  }
  var CSV_LISTS = {
    php_path: { field: 'php_path', title: 'Prohibited URLs for PHP Execution', col: 'URL', ph: 'URL address, e.g. /upload/',
      empty: 'Please enter URL address.', clean: cleanPaths,
      tips: ['A .php request under one of these paths is refused, so an uploaded shell cannot execute.',
             'Generally targeted at directory URLs, e.g. /upload/ or /static/.'] },
    deny_ext: { field: 'deny_ext', title: 'Prohibited File Extensions', col: 'Extension', ph: 'File extension, without the dot (.), e.g.: sql',
      empty: 'Please enter extension.', clean: function (v) { return cleanCsv(v); },
      tips: ['Directly fill in the extension to be prohibited. For example, to prohibit access to *.sql files: sql.',
             'Needs Malicious Download Defense on, here and in Global.'] },
    upload_ext: { field: 'upload_ext', title: 'Prohibited File Types for Upload', col: 'Extension', ph: 'File extension, without the dot (.), e.g.: php',
      empty: 'Please enter extension.', clean: function (v) { return cleanCsv(v); },
      tips: ['Uploads whose file name ends in one of these are refused.',
             'Needs Malicious file upload defense on, here and in Global.'] }
  };

  /* ---------- Website Configuration [site] ---------- */
  // rows of the stock table, in its order, then ours. f: the site's switch
  // field (no f: "--"), set: what the Set / Rule button opens.
  function configRows(name, c) {
    var cnt = function (k) { return ((siteRow(name) || {}).rule_counts || {})[k] || 0; };
    var rules = function (k) { return function (done) { siteRules(name, k, true, done); }; };
    var ruleSet = function (k) { return function () { W.ruleSetDialog(k); }; };
    var csv = function (k) { return function (done) { csvDialog(name, c, CSV_LISTS[k], done); }; };
    var listPs = function (ps, k) { return ps + (cnt(k) ? ' (' + cnt(k) + ')' : ''); };
    return [
      { t: 'CC defense', f: 'cc_open', cc: true, set: function (done) { siteCcDialog(name, c, done); } },
      { t: 'SQL injection defense', f: 'sqli',
        ps: 'Detect malicious SQL statements and prevent malicious tampering of the database due to SQL injection' },
      { t: 'XSS Defense', f: 'xss',
        ps: 'Detect XSS syntax to prevent web pages from being maliciously tampered with, user information leaked, and permissions stolen' },
      { t: 'Command Execution Interception', f: 'rce',
        ps: 'Determine and block the execution of potentially dangerous commands through the syntax model, effectively ' +
          'preventing hackers from invading the server through the website' },
      { t: 'Malicious file upload defense', f: 'upload',
        ps: 'Detect malicious file uploads, prevent Trojans from being uploaded, and prevent server permissions from being lost' },
      { t: 'Malicious Download Defense', f: 'download',
        ps: 'Detect malicious downloads and prevent backup files, source code, and other critical data from being downloaded' },
      { t: 'GET filter', f: 'get', ps: 'Regex rules for attacks in the URI and its parameters', rule: ruleSet('get') },
      { t: 'POST filter', f: 'post', ps: 'Regex rules for attacks in form and JSON request bodies', rule: ruleSet('post') },
      { t: 'Malicious crawler defense', f: 'ua',
        ps: 'Detect malicious crawlers and prevent malicious crawlers from accessing the website', rule: ruleSet('ua') },
      { t: 'Cookie filter', f: 'cookie', ps: 'Filter out penetration attacks using cookies', set: ruleSet('cookie') },
      { t: 'Scanner', f: 'scan', ps: 'Filter penetration testing for common scan testing tools', set: ruleSet('scan') },
      { t: 'Custom rule interception', f: 'nday',
        ps: 'Detect known exploits (PHP code execution, framework RCE, SSRF probes) with editable rules', rule: ruleSet('nday') },
      { t: 'Fake spider', f: 'fake_spider', ps: 'Intercept forged spider IPs', set: function () { W.spiderDialog(); } },
      { t: 'CDN', f: 'cdn',
        ps: 'If the site uses CDN, the client IP can be obtained correctly after turn on (CF-Connecting-IP, then the ' +
          'X-Forwarded-For header)' },
      { t: 'Smart CC defense', f: 'smart_cc',
        ps: 'Tighten each visitor\'s CC allowance automatically while the whole site is under load' },
      { t: 'IDC interception', f: 'idc',
        ps: 'Refuse visitors from cloud / datacenter networks. Verified search crawlers still pass.' },
      { t: 'Non-browser interception', f: 'browser',
        ps: 'Page loads must run JavaScript once. Blocks scripts and scrapers; verified crawlers, APIs and assets are not affected.' },
      { t: 'From-data protocol', f: 'form_strict',
        ps: 'Reject malformed multipart/form-data bodies (no boundary, parts without Content-Disposition)' },
      { t: 'PHP2Shell guard', f: 'php_guard',
        ps: 'Block the known triggers of CVE-2026-109618/109619 in PHP uploads. Updating PHP is the real fix.' },
      { t: 'HTTP package', ps: 'Block oversized request bodies (uploads excluded): ' +
          (c.body_max ? num(c.body_max) + ' KB' : 'no limit of its own'),
        set: function (done) { bodyMaxDialog(name, c, done); } },
      { t: 'Block php exec', ps: 'Prohibit running PHP scripts at the specified URL', set: csv('php_path') },
      { t: 'Forbidden URL', ps: listPs('Prohibit access to the specified URL', 'dpath'), set: rules('dpath') },
      { t: 'Forbidden extension', ps: 'Prohibit access to the specified extension', set: csv('deny_ext') },
      { t: 'Block File types', ps: 'File types prohibited from uploading', set: csv('upload_ext') },
      { t: 'Protected URL', ps: listPs('Encrypt the URL address with custom parameters, parameter errors will be intercepted', 'purl'),
        set: rules('purl') },
      { t: 'Anti-Leech', ps: listPs('Only this site and the listed domains may embed its files', 'leech'), set: rules('leech') },
      { t: 'API interface defense', ps: listPs('Restrict the methods of API endpoints and cap requests per IP', 'api'),
        set: rules('api') },
      { t: 'URL CC defense', ps: listPs('URL defense CC rule, priority is higher than URL whitelist', 'ucc'), set: rules('ucc') },
      { t: 'URL enhancement mode', ps: listPs('Setting up a URL validation rule independently', 'uverify'), set: rules('uverify') },
      { t: 'Machine verification whitelist',
        ps: listPs('Pages that are never asked for browser verification', 'vwhite'), set: rules('vwhite') },
      { t: 'URL request type interception', ps: listPs('Set URL interception request type separately', 'umethod'),
        set: rules('umethod') },
      { t: 'Content replace', ps: listPs('Replace text in the site\'s HTML pages', 'repl'), set: rules('repl') }
    ];
  }

  function siteConfig(name) {
    post('get_site_detail', { siteName: name }, function (c) {
      if (!c.status) { layer.msg(c.msg || 'error', { icon: 2 }); return; }
      var rows = configRows(name, c);
      // the stock sentence, with this site's numbers
      function ccText() {
        return 'Request the same URI more than <span class="red">' + num(c.cc_limit || 120) + '</span> times in ' +
          '<span class="red">' + num(c.cc_cycle || 60) + '</span> second, Block IP for <span class="red">' +
          num(c.cc_block || 600) + '</span> seconds.';
      }
      function body() {
        return rows.map(function (x, i) {
          var st = x.f ? '<label class="wp-sw wp-sw-sm"><input type="checkbox" class="wc-sw" data-i="' + i + '"' + (c[x.f] ? ' checked' : '') +
            '><span class="sl"></span></label>' : '--';
          var op = x.rule ? 'Rule' : (x.set ? 'Set' : '');
          return '<tr><td>' + esc(x.t) + '</td><td class="wc-ps">' + (x.cc ? ccText() : esc(x.ps)) + '</td><td>' + st + '</td>' +
            '<td class="r">' + (op ? '<span class="wp-lnk wc-op" data-i="' + i + '">' + op + '</span>' : '') + '</td></tr>';
        }).join('');
      }
      W.open({
        type: 1, title: 'Website Configuration [' + esc(name) + ']', area: ['760px', 'auto'],
        content: '<div class="wp-modal wp-wc"><div class="wp-wc-top"><span>Website Firewall Switch</span>' +
          '<label class="wp-sw"><input type="checkbox" id="wc-open"' + (c.open ? ' checked' : '') + '><span class="sl"></span></label></div>' +
          '<div class="wp-wc-box"><table class="wp-site-tbl"><thead><tr><th style="width:140px">Name</th><th>Description</th>' +
          '<th style="width:60px">Status</th><th class="r" style="width:80px">Operate</th></tr></thead>' +
          '<tbody id="wc-body">' + body() + '</tbody></table></div>' +
          '<ul class="wp-site-tips"><li>Note: Most configurations here only apply to the current site!</li></ul></div>',
        success: function (el) {
          var $el = $(el);
          function reload() {
            post('get_site_detail', { siteName: name }, function (d) {
              if (!d.status) return;
              c = d; rows = configRows(name, c);
              $el.find('#wc-body').html(body());
            });
          }
          $el.on('change', '#wc-open', function () { setField(name, 'open', this.checked); });
          $el.on('change', '.wc-sw', function () {
            var x = rows[$(this).data('i')], on = this.checked, $cb = $(this);
            if (x.f === 'smart_cc' && on) {
              $cb.prop('checked', false);
              W.confirm('Smart CC defense will automatically determine if there is high load or slow response. If there ' +
                'is an abnormality, each visitor\'s CC allowance is tightened until the load drops.', function (i) {
                layer.close(i); $cb.prop('checked', true); setField(name, x.f, true, function () { c[x.f] = true; });
              });
              return;
            }
            setField(name, x.f, on, function () { c[x.f] = on; });
          });
          $el.on('click', '.wc-op', function () {
            var x = rows[$(this).data('i')];
            (x.rule || x.set)(reload);
          });
        },
        end: refreshList
      });
    });
  }

  // normalise "php, .jsp ,exe" -> "php,jsp,exe"; the engine matches bare, lowercase
  function cleanCsv(v) {
    return (v || '').split(',').map(function (x) {
      return x.trim().replace(/^\./, '').toLowerCase();
    }).filter(Boolean).join(',');
  }
  function modRow2(label, ctrl, hint, wide) {
    return '<div class="wp-mod-row' + (wide ? ' wide' : '') + '">' +
      '<div class="wp-mod-lbl">' + label + '</div>' +
      '<div class="wp-mod-ctl">' + ctrl + '</div>' +
      '<div class="wp-mod-hint">' + (hint || '') + '</div>' +
      '</div>';
  }

  function siteRow(name) { return (S.sites || []).filter(function (x) { return x.name === name; })[0]; }

  /* ---------- per-site rule lists (WebSite > Rules) ---------- */
  var SR_KINDS = [
    { k: 'dpath', t: 'Forbidden URL',
      note: 'Requests whose path matches one of these regular expressions are refused for this site, e.g. <b>^/install/</b> or <b>\\.git/</b>.',
      cols: ['URL pattern'], show: function (x) { return [x.rule]; },
      form: [['rule', 'URL pattern (regex)', '^/install/']] },
    { k: 'leech', t: 'Anti-Leech',
      note: 'Files with these extensions may only be embedded from this site&apos;s own domains (always allowed) and the domains listed. ' +
            'Subdomains of a listed domain are allowed too.',
      cols: ['Extensions', 'Allowed referer domains', 'Empty referer'],
      show: function (x) { return [x.exts, x.domains || '— own domains only —', x.allow_empty ? 'Allowed' : 'Blocked']; },
      form: [['exts', 'Extensions', 'jpg,png,gif,mp4'], ['domains', 'Allowed domains', 'partner.com, cdn.example.com'],
             ['allow_empty', 'Allow requests without a Referer (direct visits, apps)', 'checkbox']] },
    { k: 'purl', t: 'Protected URL',
      note: 'A path matching the pattern only works with <b>?param=value</b> appended — everyone else gets 403. ' +
            'Handy for hiding admin logins: bookmark <b>/admin-login?key=your-secret</b>.',
      cols: ['URL pattern', 'Parameter', 'Value'], show: function (x) { return [x.path, x.param, x.value]; },
      form: [['path', 'URL pattern (regex)', '^/wp-login\\.php'], ['param', 'Parameter name', 'key'],
             ['value', 'Required value (6+ chars)', 'k8Hs2pQ']] },
    { k: 'api', t: 'API defense',
      note: 'For API endpoints: restrict the HTTP methods and cap requests per IP per minute (429 when exceeded).',
      cols: ['API path', 'Allowed methods', 'Limit / min'],
      show: function (x) { return [x.path, x.methods || 'any', x.per_min ? x.per_min : 'no limit']; },
      form: [['path', 'API path pattern (regex)', '^/api/'], ['methods', 'Allowed methods', 'GET,POST'],
             ['per_min', 'Requests per IP per minute (0 = no limit)', '120']] },
    { k: 'ucc', t: 'URL CC defense',
      note: 'Set CC defense for a single URL: more than Frequency requests from one IP within Cycle seconds bans the IP. ' +
            'Checked before the URL whitelist. The recommended minimum is 30 times in 60 seconds.',
      cols: ['URL', 'Frequency', 'Cycle'], show: function (x) { return [x.path, x.limit + ' Time(s)', x.cycle + ' Sec']; },
      form: [['path', 'URL (regex, without parameters)', '^/login'], ['limit', 'Frequency', '30'], ['cycle', 'Cycle (seconds)', '60']] },
    { k: 'uverify', t: 'URL enhancement mode',
      note: 'Pages matching these URLs always require browser verification (JavaScript check), e.g. a register page: ' +
            '<b>^/register\\.html</b>. Priority: Enhanced mode &gt; URL enhancement mode &gt; standard mode.',
      cols: ['URL'], show: function (x) { return [x.path]; }, form: [['path', 'URL (regex)', '^/register']] },
    { k: 'vwhite', t: 'Machine verification whitelist',
      note: 'Pages matching these URLs are never asked for browser verification (Non-browser, CC enhanced mode). ' +
            'E.g. <b>^/admin/update</b> or <b>^/admin/[1-99]</b>.',
      cols: ['URL'], show: function (x) { return [x.path]; }, form: [['path', 'URL (regex)', '^/api/callback']] },
    { k: 'umethod', t: 'URL request type interception',
      note: 'Intercept: the URL does not allow these request types. Only release: the URL only allows these request types.',
      cols: ['URL', 'Type', 'Request type'],
      show: function (x) { return [x.path, x.mode === 'allow' ? 'Only release' : 'Intercept', x.methods]; },
      form: [['path', 'URL (regex)', '^/admin/'], ['mode', 'Type', 'select:refuse=Intercept,allow=Only release'],
             ['methods', 'Request types', 'POST,PUT']] },
    { k: 'repl', t: 'Content replace',
      note: 'Replaces text in HTML pages before they are sent (exact match, case-sensitive). Only uncompressed HTML from ' +
            'this server is rewritten; pages over 4 MB pass unchanged.',
      cols: ['Find', 'Replace with'], show: function (x) { return [x.from, x.to]; },
      form: [['from', 'Text to find', 'old text'], ['to', 'Replace with', 'new text']] }
  ];

  function siteRules(name, kind, single, done) {
    post('site_rules_get', { siteName: name }, function (r) {
      if (!r.status) { layer.msg(r.msg || 'error', { icon: 2 }); return; }
      var cur = SR_KINDS.filter(function (x) { return x.k === kind; })[0] || SR_KINDS[0];
      var h = '<div class="wp-modal">' +
        '<div class="wp-mod-head"><div class="wp-mod-site">' + (name === '*' ? 'All sites' : esc(name)) + '</div>' +
        '<div class="wp-mod-meta">' + (name === '*' ? 'Global rules, applied to every website before its own rules' :
          esc((r.domains || []).join(', '))) + '</div></div>' +
        (single ? '' : '<div class="wp-subtabs">' + SR_KINDS.map(function (x) {
          var n = (r.data[x.k] || []).length;
          return '<span class="wp-subtab sr-tab' + (x.k === cur.k ? ' on' : '') + '" data-k="' + x.k + '">' +
            x.t + (n ? ' (' + n + ')' : '') + '</span>';
        }).join('') + '</div>') +
        '<div class="wp-mod-body">' +
        '<div class="wp-mod-sec"><div class="wp-mod-sec-t">Add</div>' +
        cur.form.map(function (f) {
          if (String(f[2]).indexOf('select:') === 0) {
            return modRow2(f[1], '<select class="wp-in" id="sr-f-' + f[0] + '" style="width:200px">' +
              f[2].slice(7).split(',').map(function (o) {
                var kv = o.split('='); return '<option value="' + kv[0] + '">' + esc(kv[1]) + '</option>';
              }).join('') + '</select>', '');
          }
          if (f[2] === 'checkbox') {
            return modRow2('', '<label style="display:flex;gap:8px;align-items:center;cursor:pointer">' +
              '<input type="checkbox" id="sr-f-' + f[0] + '" checked> ' + f[1] + '</label>', '');
          }
          return modRow2(f[1], '<input class="wp-in wp-wide" id="sr-f-' + f[0] + '" placeholder="' + esc(f[2]) + '">', '', true);
        }).join('') +
        modRow2('', '<span class="wp-btn primary" id="sr-add">Add</span>', '') + '</div>' +
        '<table class="wp-tbl"><thead><tr>' + cur.cols.map(function (c) { return '<th>' + c + '</th>'; }).join('') +
        '<th style="width:70px">Operate</th></tr></thead><tbody>' +
        ((r.data[cur.k] || []).length ? r.data[cur.k].map(function (x, i) {
          return '<tr>' + cur.show(x).map(function (v) {
            return '<td class="ell" title="' + esc(v) + '">' + esc(v) + '</td>';
          }).join('') + '<td><span class="wp-lnk sr-del" data-i="' + i + '">Delete</span></td></tr>';
        }).join('') : '<tr><td colspan="' + (cur.cols.length + 1) + '" class="wp-empty">No rules yet</td></tr>') +
        '</tbody></table>' +
        '<ul class="wp-notes"><li>' + cur.note + '</li><li>Changes apply within a couple of seconds — no nginx reload.</li></ul>' +
        '</div></div>';
      // switching tabs reopens the dialog; only a real close refreshes the table
      S.srSwitching = true;
      layer.closeAll('page');
      S.srSwitching = false;
      W.open({
        type: 1, title: single ? cur.t + (name === '*' ? '' : ' [' + esc(name) + ']') :
          (name === '*' ? 'Global rules' : 'Site rules — ' + name),
        area: [single ? '720px' : '820px', '600px'], content: h,
        success: function () {
          $('.sr-tab').on('click', function () { siteRules(name, $(this).data('k')); });
          $('#sr-add').on('click', function () {
            var d = {};
            cur.form.forEach(function (f) {
              var el = $('#sr-f-' + f[0]);
              d[f[0]] = f[2] === 'checkbox' ? el.is(':checked') : (el.val() || '').trim();
            });
            post('site_rule_add', { siteName: name, kind: cur.k, data: JSON.stringify(d) }, function (rr) {
              layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
              if (rr.status) siteRules(name, cur.k, single, done);
            });
          });
          $('.sr-del').on('click', function () {
            post('site_rule_del', { siteName: name, kind: cur.k, index: $(this).data('i') }, function (rr) {
              layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
              if (rr.status) siteRules(name, cur.k, single, done);
            });
          });
        },
        end: function () {
          if (S.srSwitching) return;
          if (done) done();
          else if (S.tab === 'website') pageWebsite();
        }
      });
    });
  }


  // exports
  W.SR_KINDS = SR_KINDS;
  W.cbx = cbx;
  W.icoSearch = icoSearch;
  W.qmark = qmark;
  W.cleanCsv = cleanCsv;
  W.modRow2 = modRow2;
  W.pageWebsite = pageWebsite;
  W.renderSiteTable = renderSiteTable;
  W.siteConfig = siteConfig;
  W.siteFiltered = siteFiltered;
  W.siteRow = siteRow;
  W.siteRules = siteRules;
})(window.WAFPRO = window.WAFPRO || {});
