(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }

  /* ================= WEBSITE =================
     The aaPanel 8 WAF's Site page, element for element: malicious-IP
     checkbox and search on top, one row per site (Site | Total
     interceptions | Fake spider | Using CDN | Smart CC defense | Crawl
     Protection | Waiting Room/Rate Limit | CC Defense | Status | Operate:
     Log, Set), its help list below. Set opens "Website Configuration
     [site]" (Name / Description / Status / Operate, switches applied at
     once); every Set / Rule in it opens the stock dialog for that row. */
  function pageWebsite() {
    $('#wp-body').html('<div class="wp-loading">Loading...</div>');
    post('get_sites', {}, function (r) {
      S.sites = r.data || [];
      S.malOpen = r.mal_open;
      S.sitePage = S.sitePage || 1; S.siteSize = S.siteSize || 10; S.siteQ = S.siteQ || '';
      var h = '<div class="wp-card wp-site-card">';
      h += '<div class="wp-site-top">' +
        '<label class="wp-site-mal"><span>Intercept access from known malicious IPs of aaPanel</span>' +
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
      $('#wp-site-q').on('keyup', function (e) { if (e.keyCode === 13) search(); });
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
  // the stock column-title help: an orange "?" with a popover
  function qmark(tip) { return '<span class="wp-qm" data-pop="' + popHtml(tip) + '">?</span>'; }

  /* ---------- hover popovers (the stock n-popover) ----------
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
      '<th style="min-width:150px">Site</th><th style="width:10%;min-width:140px">Total interceptions</th>' +
      '<th style="width:12%;min-width:120px"><span class="wp-th">Fake spider' + qmark('Intercept forged spider IPs') + '</span></th>' +
      '<th style="width:12%;min-width:120px"><span class="wp-th">Using CDN' +
        qmark('CDN: A switch for obtaining IPs when a website enables CDN.') + '</span></th>' +
      '<th style="width:14%;min-width:140px"><span class="wp-th">Smart CC defense' +
        qmark('<div style="width:500px;white-space:normal">According to website load conditions and historical access data, ' +
        'automatically analyze whether an attack is in progress. Automatically adjust defense strategies according to the ' +
        'impact, thereby reducing the impact on business.</div>') + '</span></th>' +
      '<th style="width:9%;min-width:100px">Crawl Protection</th><th style="width:10%;min-width:170px">Waiting Room/Rate Limit</th>' +
      '<th style="width:8%;min-width:100px">CC Defense</th><th style="width:6%;min-width:70px">Status</th>' +
      '<th class="r" style="width:100px">Operate</th></tr></thead><tbody>';
    h += rows.length ? rows.map(function (s) {
      var n = esc(s.name);
      var total = s.intercepts || 0;
      var byPop = popHtml((s.hits_by || []).map(function (x) {
        return '<div class="wp-pop-line">' + esc(hitLabel(x[0])) + ': ' + num(x[1]) + ' times</div>';
      }).join(''));
      return '<tr>' +
        '<td class="site"><span class="wp-lnk wp-site-set" data-n="' + n + '">' + n + '</span></td>' +
        '<td><span' + ((s.hits_by || []).length ? ' data-pop="' + byPop + '"' : '') + '>' + (total > 0 ?
          '<span class="wp-lnk err wp-site-total" data-n="' + n + '">' + num(total) + '</span>' : '0') + '</span></td>' +
        '<td>' + cbx(s.name, 'fake_spider', s.fake_spider) + '</td>' +
        '<td>' + cbx(s.name, 'cdn', s.cdn) + '</td>' +
        '<td><span class="wp-cell-in">' + cbx(s.name, 'smart_cc', s.smart_cc) +
          '<span class="cnt" data-pop="' + timesPop(s.smart_hits) + '">' + num(s.smart_hits) + '</span></span></td>' +
        '<td><span class="wp-lnk wp-site-crawl' + (s.enc ? '' : ' err') + '" data-n="' + n + '">' +
          (s.enc ? 'Enable' : 'Disable') + '</span></td>' +
        '<td><span class="wp-lnk wp-site-wait' + (s.wait ? '' : ' err') + '" data-n="' + n + '">' +
          (s.wait ? 'Enable' : 'Disable') + '</span></td>' +
        '<td><span class="wp-cell-in">' + cbx(s.name, 'cc_open', s.cc_open) +
          '<span class="cnt" data-pop="' + timesPop(s.cc_hits) + '">' + num(s.cc_hits) + '</span></span></td>' +
        '<td><label class="wp-sw wp-sw-sm"><input type="checkbox" class="wp-site-sw" data-n="' + n + '"' +
          (s.open ? ' checked' : '') + '><span class="sl"></span></label></td>' +
        '<td class="r"><span class="wp-lnk wp-site-log" data-n="' + n + '">Log</span><span class="sep"></span>' +
        '<span class="wp-lnk wp-site-set" data-n="' + n + '">Set</span></td></tr>';
    }).join('') : '<tr><td colspan="10" class="wp-empty">No Data</td></tr>';
    h += '</tbody></table></div>';
    h += W.pager(S.sitePage, pages, all.length, 'wp-site-pg', S.siteSize);

    var $t = $('#wp-site-table');
    $t.off().html(h);
    bindPops($t);
    W.bindPager('wp-site-pg', pages, function (p) { S.sitePage = p; renderSiteTable(); },
      function (k) { S.siteSize = k; S.sitePage = 1; renderSiteTable(); });

    $t.on('change', '.wp-site-sw', function () {
      setField($(this).data('n'), 'open', this.checked);
    });
    $t.on('change', '.wp-cbx', function () {
      var n = $(this).data('n'), f = $(this).data('f'), on = this.checked, $cb = $(this);
      if (f === 'smart_cc' && on) {
        $cb.prop('checked', false);
        return smartConfirm(function () { $cb.prop('checked', true); setField(n, f, true); });
      }
      setField(n, f, on);
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
  function smartConfirm(yes) {
    W.confirm('Intelligent CC defense will automatically determine if there is high load or slow response. If there is an ' +
      'abnormality, human-machine verification will be enabled for protection.', function (i) { layer.close(i); yes(); });
  }

  // site fields, saved at once (the stock switches have no Save button);
  // value: a boolean / number / string, or {field: value} for several
  function setField(name, field, value, done) {
    var patch = {};
    if (typeof field === 'object') patch = field; else patch[field] = value;
    post('save_site_detail', { siteName: name, config: JSON.stringify(patch) }, function (rr) {
      layer.msg(rr.status ? 'Setup successfully' : rr.msg, { icon: rr.status ? 1 : 2 });
      if (!rr.status) return;
      var s = siteRow(name);
      if (s) Object.keys(patch).forEach(function (k) { s[k] = patch[k]; });
      if (done) done();
    });
  }
  function refreshList() { if (S.tab === 'website') pageWebsite(); }

  /* ---------- naive-ui form pieces ----------
     n-form label-width 160: right-aligned 12px label, 20px gap, 32px
     controls, 20px feedback space under each item. */
  function nf(label, ctl, show) {
    return '<div class="wp-nf"' + (show === false ? ' style="display:none"' : '') + '><div class="wp-nf-l">' + label +
      '</div><div class="wp-nf-c">' + ctl + '</div></div>';
  }
  function nNum(id, v, w) {
    return '<input class="wp-in wp-nnum" id="' + id + '" type="number" min="0" style="width:' + (w || 160) + 'px" value="' +
      esc(v) + '">';
  }
  function nSel(id, opts, v, w) {
    return '<select class="wp-in" id="' + id + '" style="width:' + (w || 160) + 'px">' + opts.map(function (o) {
      return '<option value="' + esc(o[0]) + '"' + (String(o[0]) === String(v) ? ' selected' : '') + '>' + esc(o[1]) + '</option>';
    }).join('') + '</select>';
  }
  function nRadio(name, opts, v) {
    return '<div class="wp-nradio">' + opts.map(function (o) {
      return '<label><input type="radio" name="' + name + '" value="' + esc(o[0]) + '"' + (o[0] === v ? ' checked' : '') +
        '><span>' + esc(o[1]) + '</span></label>';
    }).join('') + '</div>';
  }
  function helpPop(items) {
    return '<span class="wp-help" data-pop="' + popHtml('<div class="wp-help-pop">' + items.map(function (x) {
      return '<div class="t">' + x[0] + '</div><div class="d">' + x[1] + '</div>';
    }).join('') + '</div>') + '">?</span>';
  }
  function tips(list) {
    return '<ul class="wp-site-tips">' + list.map(function (x) {
      return typeof x === 'string' ? '<li>' + x + '</li>' : '<li class="' + x[0] + '">' + x[1] + '</li>';
    }).join('') + '</ul>';
  }
  // BtModal with a footer: Cancel + the confirm button
  function modal(o) {
    var idx = W.open({
      type: 1, title: o.title, area: [o.width + 'px', 'auto'], btn: o.footer === false ? undefined : [o.ok || 'Confirm', 'Cancel'],
      content: '<div class="wp-modal ' + (o.cls || 'wp-g-dlg') + '"' + (o.minHeight ? ' style="min-height:' + o.minHeight + 'px"' : '') +
        '>' + o.body + '</div>',
      success: function (el) { bindPops($(el)); if (o.success) o.success($(el), function () { layer.close(idx); }); },
      yes: function () { if (o.yes) o.yes(function () { layer.close(idx); }); },
      end: o.end
    });
    return idx;
  }

  /* ---------- Total interception times [site] ---------- */
  function totalDialog(name) {
    var s = siteRow(name) || {};
    var rows = (s.hits_by || []).map(function (x) {
      return '<tr><td>' + esc(hitLabel(x[0])) + '</td><td><span class="wp-lnk err" data-pop="' + timesPop(x[1]) + '">' +
        num(x[1]) + '</span></td></tr>';
    }).join('') || '<tr><td colspan="2" class="wp-empty">No Data</td></tr>';
    modal({ title: 'Total interception times [' + esc(name) + ']', width: 480, minHeight: 688, footer: false,
      body: '<table class="wp-site-tbl"><thead><tr><th>Type</th><th>Interception times</th></tr></thead><tbody>' +
        rows + '</tbody></table>' });
  }

  /* ---------- Interception log [site] ---------- */
  var LOG_DATES = [['today', 'Today'], ['yesterday', 'Yesterday'], ['l7', 'Last 7 days'], ['l30', 'Last 30 days']];
  function siteLogDialog(name) {
    post('get_logs', { siteName: name, date: 'all', p: 1, size: 5 }, function (r) {
      if (!r.status || !r.total) return layer.msg('No site logs for now', { icon: 1 });
      // first view: the newest day that has records, as the stock dialog does
      var newest = String(((r.data || [])[0] || {}).time || '').slice(0, 10);
      var st = { date: newest || 'today', p: 1, size: 15 };
      modal({
        title: 'Interception log [' + esc(name) + ']', width: 1100, footer: false, cls: 'wp-g-dlg wp-slog',
        body: '<div class="wp-slog-top"><span>Select date:</span>' +
          nSel('slog-date', LOG_DATES.concat(newest ? [[newest, newest]] : []), st.date, 160) +
          '<span class="wp-btn wp-slog-range" id="slog-pick">' + W.icoCalendar() + '<span>Start date ~ End date</span></span></div>' +
          '<div id="slog-body"><div class="wp-loading">Loading...</div></div>',
        success: function ($el) {
          var range = [];
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
          $el.on('change', '#slog-date', function () {
            st.date = $(this).val(); st.p = 1; range = [];
            $el.find('#slog-pick span').text('Start date ~ End date');
            load();
          });
          // date range: two picks, start then end
          $el.on('click', '#slog-pick', function () {
            var anchor = this;
            W.pickDate(anchor, { max: W.todayStr(), done: function (a) {
              if (!a) return;
              range = [a];
              $el.find('#slog-pick span').text(a + ' ~ End date');
              setTimeout(function () {
                W.pickDate(anchor, { min: a, max: W.todayStr(), done: function (b) {
                  if (!b) return;
                  st.date = a + '~' + b; st.p = 1;
                  $el.find('#slog-pick span').text(a + ' ~ ' + b);
                  load();
                } });
              }, 50);
            } });
          });
          load();
        }
      });
    });
  }

  /* ---------- Crawl Protection [site] ---------- */
  function crawlDialog(name) {
    var s = siteRow(name) || {};
    var custom = !!s.enc_text;
    modal({
      title: 'Crawl Protection [' + esc(name) + ']', width: 620, ok: 'Confirm',
      body: nf('Dynamic Encryption', '<label class="wp-sw"><input type="checkbox" id="cp-html"' + (s.enc ? ' checked' : '') +
          '><span class="sl"></span></label>') +
        '<div id="cp-more"' + (s.enc ? '' : ' style="display:none"') + '>' +
        nf('', nRadio('cp-type', [['default', 'Default (Loading page)'], ['text', 'Custom Page Redirect Content']],
          custom ? 'text' : 'default')) +
        nf('', '<input class="wp-in" id="cp-text" style="width:100%" placeholder="For example: The website is being decrypted, please wait." value="' +
          esc(s.enc_text || '') + '">', custom) + '</div>' +
        tips([['red', 'Crawler Protection (Currently a beta feature)'],
          '<b>Effect: </b>When enabled, the webpage will be randomly encrypted, and each visit will display a different page, ' +
            'effectively preventing crawlers.',
          '<b>Impact: </b>Enabling this feature will double the traffic compared to before, and in some rare cases, it may ' +
            'cause the webpage to fail to load.',
          '<b>Recommendation: </b>You can try enabling it for testing purposes, but it is not recommended for live/production ' +
            'environments.']),
      success: function ($el) {
        $el.on('change', '#cp-html', function () { $el.find('#cp-more').toggle(this.checked); });
        $el.on('change', 'input[name=cp-type]', function () {
          $el.find('#cp-text').closest('.wp-nf').toggle(this.value === 'text');
        });
      },
      yes: function (close) {
        var on = $('#cp-html').is(':checked');
        var text = $('input[name=cp-type]:checked').val() === 'text' ? ($('#cp-text').val() || '').trim() : '';
        function go() { setField(name, { enc: on, enc_text: text }, function () { close(); refreshList(); }); }
        if (!on) return go();
        W.confirm('<ul class="wp-confirm-ul"><li class="red">Effect: Webpage content is randomly encrypted on each visit, effectively preventing crawlers.</li>' +
          '<li>Impact: Enabling this feature will double the traffic compared to previous levels.</li>' +
          '<li>Recommendation: It is advised not to enable this for online services.</li>' +
          '<li class="red">Warning: This is a beta feature. Do NOT enable it for production services!!</li></ul>',
          { title: 'Tips', area: ['408px', 'auto'] }, function (i) { layer.close(i); go(); });
      }
    });
  }

  /* ---------- Waiting Room/Rate Limit [site] ---------- */
  function waitDialog(name) {
    var s = siteRow(name) || {};
    var custom = !!s.wait_text;
    modal({
      title: 'Waiting Room/Rate Limit [' + esc(name) + ']', width: 700,
      body: nf('Waiting Room Switch', '<label class="wp-sw"><input type="checkbox" id="wr-open"' + (s.wait ? ' checked' : '') +
          '><span class="sl"></span></label>') +
        nf('Max Number of Users', nNum('wr-users', s.wait_users || 50, 120)) +
        nf('Active Timeout', nNum('wr-time', s.wait_time || 10, 120) + '<span class="wp-nf-u">Minutes, QPS exceeds</span>' +
          nNum('wr-qps', s.wait_limit, 120) + '<span class="wp-nf-u">times to trigger</span>') +
        nf('Identification Page', nRadio('wr-type', [['default', 'Default (6KB)'], ['text', 'Custom Web Content (3KB)']],
          custom ? 'text' : 'default')) +
        nf('', '<input class="wp-in" id="wr-text" style="width:100%" maxlength="3000" ' +
          'placeholder="For example: Too many online users on the website, need to queue" value="' + esc(s.wait_text || '') + '">', custom) +
        tips([['red', 'Waiting Room/Rate Limiting currently in testing'],
          '<b>Effect: </b>Enabling the waiting room can help alleviate peak load issues',
          '<b>Impact: </b>Older versions of browsers may experience continuous loading',
          '<b>Suggestion: </b>Testing businesses can try enabling it, but it\'s recommended not to enable for online services',
          '<b>Default Policy: </b>Website real-time traffic must exceed once to trigger. Up to 50 users can access simultaneously, ' +
            'with a timeout of 10 minutes',
          'If QPS is 0, then the QPS count will not be detected']),
      success: function ($el) {
        $el.on('change', 'input[name=wr-type]', function () {
          $el.find('#wr-text').closest('.wp-nf').toggle(this.value === 'text');
        });
      },
      yes: function (close) {
        setField(name, {
          wait: $('#wr-open').is(':checked'), wait_users: +$('#wr-users').val() || 0, wait_time: +$('#wr-time').val() || 0,
          wait_limit: +$('#wr-qps').val() || 0,
          wait_text: $('input[name=wr-type]:checked').val() === 'text' ? ($('#wr-text').val() || '').trim() : ''
        }, function () { close(); refreshList(); });
      }
    });
  }

  /* ---------- Set CC Rules [site] ---------- */
  var REQ_TYPES = [['url', 'Loose'], ['path', 'Standard (Recommended)'], ['ipua', 'Strict'], ['ip', 'Super strict']];
  var VERIFY = [['browser', 'Browser'], ['js', 'Redirect'], ['code', 'Code'], ['renji', 'Captcha'], ['huadong', 'Slide']];
  function siteCcDialog(name, c, done) {
    post('country_list', {}, function (cl) {
      var countries = (cl && cl.status) ? cl.data : [];
      var chosen = (c.cc_country || '').split(',').filter(Boolean);
      var enh = c.cc_mode === 'enhanced';
      var getSel = function () { return chosen; };
      var body =
        nf('Mode', nSel('sc-mode', [['block', 'Standard Mode'], ['enhanced', 'Enhanced Mode']], enh ? 'enhanced' : 'block') +
          '<div class="wp-nf-desc sc-enh"' + (enh ? '' : ' style="display:none"') + '>After enabling, a CAPTCHA mechanism ' +
          'will appear when accessing the website, requiring manual verification to continue. It is recommended to enable ' +
          'this during CC attacks.</div>') +
        '<div class="sc-std"' + (enh ? ' style="display:none"' : '') + '>' +
        nf('Request Type', nSel('sc-key', REQ_TYPES, c.cc_key || 'path') + helpPop([
          ['Loose', 'Poor effect, less interception'],
          ['Standard (recommended)', 'Recommended, better effect, fewer false positives, use URL without parameters as the only value'],
          ['Strict', 'Use with caution: good effect, more false positives, use IP+UA as the only value'],
          ['Super strict', 'Not recommended: strong effect, large number of false positives, using IP as the only value']])) +
        nf('Access Time', nNum('sc-cycle', c.cc_cycle || 60) + '<span class="wp-nf-u">Seconds</span>') +
        nf('Access Count', nNum('sc-limit', c.cc_limit || 120) + '<span class="wp-nf-u">Times</span>') +
        nf('Block Time', nNum('sc-block', c.cc_block || 600) + '<span class="wp-nf-u">Seconds</span>') +
        nf('URL CC Defense', nSel('sc-url', [['1', 'Enable'], ['0', 'Disable']], c.cc_url ? '1' : '0', 100) + helpPop([
          ['Enable', 'Recommended to enable. When a specific page is under CC attack, human verification will be triggered ' +
            'for the attacked URL without affecting other pages.'], ['Disable', 'Not Recommended']])) +
        nf('Single IP Defense', '<div class="wp-nf-col"><div class="wp-nf-line">' +
          nSel('sc-ipo', [['1', 'Enable'], ['0', 'Disable']], c.cc_ipmax_open ? '1' : '0', 100) + helpPop([
          ['Enable', 'Intercept based on the number of visits per IP within 24 hours. Recommended to enable. The default ' +
            'threshold should not be lower than 2000 visits (the count will reset if Nginx is restarted).'],
          ['Disable', 'Not Recommended']]) +
          '<span class="sc-ipm"' + (c.cc_ipmax_open ? '' : ' style="display:none"') + '>' + nNum('sc-ipmax', c.cc_ipmax || 10000, 80) +
          '<span class="wp-nf-u">Times</span><label class="wp-ncb"><input type="checkbox" class="wp-cb" id="sc-ips"' +
          (c.cc_ipmax_static ? ' checked' : '') + '><span>Include Static Resources</span></label></span></div>' +
          '<div class="wp-nf-err sc-ipm"' + (c.cc_ipmax_open ? '' : ' style="display:none"') + '>The suggested value is ' +
          'greater than 5000; otherwise, false positives may occur.</div></div>') +
        nf('Regional Verification', '<div class="wp-cs" id="sc-cty"><div class="wp-cs-box"></div><div class="wp-cs-drop">' +
          '<div class="wp-cs-head"><input class="wp-in" placeholder="Search"><span class="wp-btn" data-a="all">All</span>' +
          '<span class="wp-btn" data-a="none">Cancel</span></div><div class="wp-cs-list"></div></div></div>') +
        '</div>' +
        '<div class="sc-enh"' + (enh ? '' : ' style="display:none"') + '>' +
        nf('Verification Method', '<div class="wp-nf-col">' + nSel('sc-verify', VERIFY, c.cc_verify || 'js') +
          '<div class="wp-nf-err sc-code"' + (c.cc_verify === 'code' ? '' : ' style="display:none"') + '>CAPTCHA verification: ' +
          'If the site has CDN enabled, it is recommended not to use this.</div></div>') + '</div>' +
        '<ul class="wp-site-tips" id="sc-tips"></ul>';
      modal({
        title: 'Set CC Rules [' + esc(name) + ']', width: 640, minHeight: 516, ok: 'Apply', cls: 'wp-g-dlg wp-ccd', body: body,
        success: function ($el) {
          var sel = {};
          chosen.forEach(function (k) { sel[k] = 1; });
          var byCode = {};
          countries.forEach(function (x) { byCode[x.code] = x.name; });
          function drawCty() {
            var keys = Object.keys(sel);
            $el.find('#sc-cty .wp-cs-box').html(keys.length ? keys.slice(0, 3).map(function (k) {
              return '<span class="wp-cs-tag">' + esc(byCode[k] || k) + '<i data-c="' + esc(k) + '">&times;</i></span>';
            }).join('') + (keys.length > 3 ? '<span class="wp-cs-tag">+' + (keys.length - 3) + '</span>' : '') :
              '<span class="ph">Please select a region</span>');
            var q = ($el.find('.wp-cs-head input').val() || '').toLowerCase();
            $el.find('#sc-cty .wp-cs-list').html(countries.filter(function (x) {
              return !q || x.name.toLowerCase().indexOf(q) !== -1 || x.code.toLowerCase() === q;
            }).map(function (x) {
              return '<div class="wp-cs-opt' + (sel[x.code] ? ' on' : '') + '" data-c="' + esc(x.code) + '">' + esc(x.name) + '</div>';
            }).join(''));
          }
          function tipsDraw() {
            var e = $el.find('#sc-mode').val() === 'enhanced';
            var lim = esc($el.find('#sc-limit').val()), cyc = esc($el.find('#sc-cycle').val()), blk = esc($el.find('#sc-block').val());
            $el.find('#sc-tips').html('<li>Settings here only apply to the current site.</li>' + (e ?
              '<li class="red">Browser verification: Verify if it is a normal browser request. If the website encounters issues ' +
              'after opening, please close it</li>' :
              '<li>This IP has requested the same URL more than <span class="red">' + lim + '</span> times within <span class="red">' +
              cyc + '</span> seconds, triggering CC defense and blocking this IP for <span class="red">' + blk + '</span> seconds</li>' +
              '<li class="red">Please do not set overly strict CC rules to avoid affecting the normal user experience.</li>' +
              '<li>Regional verification: The selected region automatically turns on verification mode: <span class="red">JS</span>, ' +
              'access time: <span class="red">' + cyc + '</span> seconds, If verification fails: <span class="red">' +
              esc(c.retry_eff || 10) + '</span> times, block: <span class="red">' + blk + '</span> seconds</li>'));
          }
          drawCty(); tipsDraw();
          $el.on('change', '#sc-mode', function () {
            var e = this.value === 'enhanced';
            $el.find('.sc-enh').toggle(e); $el.find('.sc-std').toggle(!e); tipsDraw();
          });
          $el.on('input', '#sc-cycle, #sc-limit, #sc-block', tipsDraw);
          $el.on('change', '#sc-ipo', function () { $el.find('.sc-ipm').toggle(this.value === '1'); });
          $el.on('change', '#sc-verify', function () { $el.find('.sc-code').toggle(this.value === 'code'); });
          var $cs = $el.find('#sc-cty');
          $cs.on('click', '.wp-cs-box', function (e) {
            if ($(e.target).is('i')) { delete sel[$(e.target).data('c')]; drawCty(); return; }
            $cs.toggleClass('open');
            if ($cs.hasClass('open')) $cs.find('.wp-cs-head input').focus();
          });
          $cs.on('input', '.wp-cs-head input', drawCty);
          $cs.on('click', '.wp-cs-opt', function () {
            var k = String($(this).data('c'));
            if (sel[k]) delete sel[k]; else sel[k] = 1;
            drawCty();
          });
          $cs.on('click', '.wp-cs-head .wp-btn', function () {
            if ($(this).data('a') === 'all') countries.forEach(function (x) { sel[x.code] = 1; }); else sel = {};
            drawCty();
          });
          $(document).off('mousedown.sccty').on('mousedown.sccty', function (e) {
            if (!$(e.target).closest('#sc-cty').length) $cs.removeClass('open');
          });
          getSel = function () { return Object.keys(sel); };
        },
        yes: function (close) {
          var e = $('#sc-mode').val() === 'enhanced';
          var cyc = +$('#sc-cycle').val(), lim = +$('#sc-limit').val(), blk = +$('#sc-block').val();
          if (!e) {
            if (!cyc) return layer.msg('Please enter access time.', { icon: 2 });
            if (cyc < 30 || lim < 30) return layer.msg('Recommended value is an integer greater than 30.', { icon: 2 });
            if (!lim) return layer.msg('Please enter access count.', { icon: 2 });
            if (!blk) return layer.msg('Please enter block time.', { icon: 2 });
          }
          var p = { cc_mode: e ? 'enhanced' : 'block', cc_verify: $('#sc-verify').val() };
          if (!e) {
            $.extend(p, { cc_key: $('#sc-key').val(), cc_cycle: cyc, cc_limit: lim, cc_block: blk, cc_url: $('#sc-url').val() === '1',
              cc_ipmax_open: $('#sc-ipo').val() === '1', cc_ipmax: +$('#sc-ipmax').val() || 0, cc_ipmax_static: $('#sc-ips').is(':checked'),
              cc_country: getSel().join(',') });
          }
          function go() {
            var ld = layer.msg('Setting Site CC configuration, please wait...', { icon: 16, time: 0, shade: 0.3 });
            post('save_site_detail', { siteName: name, config: JSON.stringify(p) }, function (rr) {
              layer.close(ld);
              layer.msg(rr.status ? 'Setup successfully' : rr.msg, { icon: rr.status ? 1 : 2 });
              if (rr.status) { close(); if (done) done(); }
            });
          }
          if (!e) return go();
          W.confirm('Effect: Significantly improves interception effectiveness<br>Impact: User experience may decline and some ' +
            'normal accesses might be mistakenly intercepted<br>Suggestion: Temporarily enable when unable to defend in normal ' +
            'mode, and disable after the attack ends', { title: 'Tips' }, function (i) { layer.close(i); go(); });
        }
      });
    });
  }

  /* ---------- Set Attack Count Interception [site] (Request defence) ---------- */
  function tolerateDialog(name, c, done) {
    var cyc = c.retry_cycle || c.g_retry_cycle || 120, cnt = c.retry || c.g_retry || 10, blk = c.retry_time || c.g_retry_time || 1800;
    modal({
      title: 'Set Attack Count Interception [' + esc(name) + ']', width: 420, minHeight: 230, ok: 'Apply', cls: 'wp-g-dlg wp-tol',
      body: nf('Access Time', nNum('tl-cycle', cyc, 120) + '<span class="wp-nf-u">Seconds</span>') +
        nf('Attack Count', nNum('tl-retry', cnt, 120) + '<span class="wp-nf-u">Times</span>') +
        nf('Block Time', nNum('tl-time', blk, 120) + '<span class="wp-nf-u">Seconds</span>') +
        '<ul class="wp-site-tips"><li>Accumulated malicious requests exceeded <span class="red" id="tl-a">' + cnt +
        '</span> times within <span class="red" id="tl-b">' + cyc + '</span> seconds , blocked <span class="red" id="tl-c">' + blk +
        '</span> seconds</li></ul>',
      success: function ($el) {
        $el.on('input', 'input', function () {
          $el.find('#tl-a').text($('#tl-retry').val()); $el.find('#tl-b').text($('#tl-cycle').val()); $el.find('#tl-c').text($('#tl-time').val());
        });
      },
      yes: function (close) {
        var p = { retry_cycle: +$('#tl-cycle').val(), retry: +$('#tl-retry').val(), retry_time: +$('#tl-time').val() };
        if (!p.retry_cycle) return layer.msg('Please enter access time.', { icon: 2 });
        if (!p.retry) return layer.msg('Please enter attack count.', { icon: 2 });
        if (!p.retry_time) return layer.msg('Please enter block time.', { icon: 2 });
        setField(name, p, function () { close(); if (done) done(); });
      }
    });
  }

  /* ---------- Edit Site Rules [site] - [name] ---------- */
  function siteRuleSetDialog(name, set, title) {
    modal({
      title: 'Edit Site Rules [' + esc(name) + '] - [' + esc(title) + ']', width: 800, minHeight: 558, footer: false,
      body: '<div class="wp-wc-box" style="max-height:420px"><table class="wp-site-tbl"><thead><tr><th>Rule</th>' +
        '<th style="width:180px">Description</th><th style="width:60px">Status</th></tr></thead><tbody id="srs-body">' +
        '<tr><td colspan="3" class="wp-empty">Loading...</td></tr></tbody></table></div>' +
        tips(['This inherits rules that have been enabled in global settings.', 'The settings here only apply to the current site.']),
      success: function ($el) {
        post('site_rule_list', { siteName: name, rule_name: set }, function (r) {
          var rows = r.data || [];
          $el.find('#srs-body').html(rows.length ? rows.map(function (x) {
            return '<tr><td class="ell" title="' + esc(x.rule) + '"><code class="wp-rule">' + esc(x.rule) + '</code></td>' +
              '<td class="ell" title="' + esc(x.ps) + '">' + esc(x.ps) + '</td>' +
              '<td><label class="wp-sw wp-sw-sm"><input type="checkbox" class="srs-sw" data-i="' + x.index + '"' +
              (x.open ? ' checked' : '') + '><span class="sl"></span></label></td></tr>';
          }).join('') : '<tr><td colspan="3" class="wp-empty">No Data</td></tr>');
        });
        $el.on('change', '.srs-sw', function () {
          var $cb = $(this), on = this.checked;
          post('site_rule_toggle', { siteName: name, rule_name: set, index: $cb.data('i'), open: on ? 1 : 0 }, function (rr) {
            layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
            if (!rr.status) $cb.prop('checked', !on);
          });
        });
      }
    });
  }

  /* ---------- Common Scanner Filtering Rules ---------- */
  function scannerDialog() {
    post('scan_black_get', {}, function (r) {
      modal({
        title: 'Common Scanner Filtering Rules', width: 600, minHeight: 420, ok: 'Apply',
        body: ['header', 'cookie', 'args'].map(function (k) {
          return nf(k === 'args' ? 'Args' : k.charAt(0).toUpperCase() + k.slice(1),
            '<textarea class="wp-in wp-nta" id="sb-' + k + '" rows="3" spellcheck="false">' + esc(r[k] || '') + '</textarea>');
        }).join('') + tips([['red', 'Will filter both key and value; please set with caution.'],
          'Please use regular expressions; backup the original expressions before submitting.']),
        yes: function (close) {
          post('scan_black_save', { header: $('#sb-header').val(), cookie: $('#sb-cookie').val(), args: $('#sb-args').val() },
            function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) close(); });
        }
      });
    });
  }

  /* ---------- Spider pond [site] ---------- */
  function spiderDialog(name, title) {
    modal({
      title: esc(title) + ' [' + esc(name) + ']', width: 800, minHeight: 420, footer: false,
      body: '<table class="wp-site-tbl"><thead><tr><th>Name</th><th>Status Code After Prohibition</th>' +
        '<th style="width:100px">Allow Crawling</th></tr></thead><tbody id="sp-body"><tr><td colspan="3" class="wp-empty">Loading...</td>' +
        '</tr></tbody></table>' + tips(['Default allowed spiders to crawl means allowing crawling.',
          'The status code after prohibition indicates the code returned after prohibiting that spider.']),
      success: function ($el) {
        function load() {
          post('site_spiders', { siteName: name }, function (r) {
            $el.find('#sp-body').html((r.data || []).map(function (x) {
              return '<tr><td>' + esc(x.name) + '</td><td>' + nSel('', [[444, '444'], [403, '403'], [404, '404'], [500, '500'],
                [502, '502'], [503, '503']], x['return'], 100).replace('<select', '<select data-n="' + esc(x.name) + '"') +
                '</td><td><label class="wp-sw wp-sw-sm"><input type="checkbox" class="sp-sw" data-n="' + esc(x.name) + '"' +
                (x.status ? ' checked' : '') + '><span class="sl"></span></label></td></tr>';
            }).join(''));
          });
        }
        function save(n) {
          var on = $el.find('.sp-sw[data-n="' + n + '"]').is(':checked');
          post('site_spider_set', { siteName: name, spider: n, open: on ? 1 : 0,
            code: $el.find('select[data-n="' + n + '"]').val() }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); });
        }
        $el.on('change', '.sp-sw', function () { save($(this).data('n')); });
        $el.on('change', 'select[data-n]', function () {
          if (!$el.find('.sp-sw[data-n="' + $(this).data('n') + '"]').is(':checked')) save($(this).data('n'));
        });
        load();
      }
    });
  }

  /* ---------- list dialogs: input + Add on top, table, help ----------
     o: { title, width, inputs: [[key, placeholder]], cols: [[key, title]],
          tips, empty, get(): rows, add(values, done), del(index, done) } */
  function listDialog(o) {
    modal({
      title: o.title, width: o.width || 550, minHeight: 552, footer: false,
      body: '<div class="wp-ld-add">' + o.inputs.map(function (x) {
          return '<input class="wp-in" data-k="' + x[0] + '" placeholder="' + esc(x[1]) + '">';
        }).join('') + '<span class="wp-btn primary" id="ld-add">Add</span></div>' +
        '<div class="wp-wc-box" style="max-height:' + (o.maxHeight || 368) + 'px"><table class="wp-site-tbl"><thead><tr>' +
        o.cols.map(function (c) { return '<th>' + c[1] + '</th>'; }).join('') +
        '<th class="r" style="width:80px">Operate</th></tr></thead><tbody id="ld-body"></tbody></table></div>' + tips(o.tips),
      success: function ($el) {
        function draw() {
          o.get(function (rows) {
            $el.find('#ld-body').html(rows.length ? rows.map(function (r, i) {
              return '<tr>' + o.cols.map(function (c) { return '<td class="ell" title="' + esc(r[c[0]]) + '">' + esc(r[c[0]]) + '</td>'; }).join('') +
                '<td class="r"><span class="wp-lnk ld-del" data-i="' + i + '">Delete</span></td></tr>';
            }).join('') : '<tr><td colspan="' + (o.cols.length + 1) + '" class="wp-empty">No Data</td></tr>');
          });
        }
        function add() {
          var v = {}, miss = false;
          $el.find('.wp-ld-add input').each(function () { v[$(this).data('k')] = ($(this).val() || '').trim(); if (!v[$(this).data('k')]) miss = true; });
          if (miss) return layer.msg(o.empty, { icon: 2 });
          o.add(v, function () { $el.find('.wp-ld-add input').val(''); draw(); });
        }
        $el.on('click', '#ld-add', add);
        $el.on('keyup', '.wp-ld-add input', function (e) { if (e.keyCode === 13) add(); });
        $el.on('click', '.ld-del', function () { o.del($(this).data('i'), draw); });
        draw();
      }
    });
  }
  // a comma-separated site field as a list
  function csvList(name, field, o) {
    function items(c) { return (c[field] || '').split(',').map(function (x) { return x.trim(); }).filter(Boolean); }
    function save(list, done) {
      var p = {}; p[field] = list.join(',');
      setField(name, p, done);
    }
    listDialog($.extend({
      get: function (cb) { post('get_site_detail', { siteName: name }, function (c) { cb(items(c).map(function (x) { return { rule: x }; })); }); },
      add: function (v, done) {
        post('get_site_detail', { siteName: name }, function (c) {
          var list = items(c);
          o.clean(v.rule).forEach(function (x) { if (list.indexOf(x) === -1) list.push(x); });
          save(list, done);
        });
      },
      del: function (i, done) {
        post('get_site_detail', { siteName: name }, function (c) { var list = items(c); list.splice(i, 1); save(list, done); });
      }
    }, o));
  }
  // a per-site rule list (site_rules.json kind)
  function kindList(name, kind, o) {
    listDialog($.extend({
      get: function (cb) { post('site_rules_get', { siteName: name }, function (r) { cb((r.data || {})[kind] || []); }); },
      add: function (v, done) {
        post('site_rule_add', { siteName: name, kind: kind, data: JSON.stringify(o.map ? o.map(v) : v) }, function (rr) {
          layer.msg(rr.status ? 'Setup successfully' : rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) done();
        });
      },
      del: function (i, done) {
        post('site_rule_del', { siteName: name, kind: kind, index: i }, function (rr) {
          layer.msg(rr.status ? 'Setup successfully' : rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) done();
        });
      }
    }, o));
  }
  var CASE_TIP = 'Rule values are case insensitive except for regular expression statements; it is recommended to use lowercase consistently.';
  function extClean(v) {
    return (v || '').split(/[,\s]+/).map(function (x) { return x.trim().replace(/^\./, '').toLowerCase(); }).filter(Boolean);
  }
  function pathClean(v) { return (v || '').split(',').map(function (x) { return x.trim(); }).filter(Boolean); }
  function regexEsc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function cdnHeadersDialog(name) {
    csvList(name, 'cdn_headers', { title: 'Manage Website CDN-Headers [' + esc(name) + ']', minHeight: 530,
      inputs: [['rule', 'Header Name']], cols: [['rule', 'Header']], empty: 'Please enter Header.',
      clean: function (v) { return pathClean(v.toLowerCase()); },
      tips: ['The firewall will attempt to retrieve the client IP from the above headers.'] });
  }
  function phpPathDialog(name) {
    csvList(name, 'php_path', { title: 'Prohibited URLs for PHP Execution [' + esc(name) + ']',
      inputs: [['rule', 'URL address, e.g., /admin/update']], cols: [['rule', 'Rule']], empty: 'Please enter URL address.',
      clean: pathClean, tips: [CASE_TIP, 'Do not include URI parameters here; generally targeted at directory URLs. Example: /admin.'] });
  }
  function denyExtDialog(name) {
    csvList(name, 'deny_ext', { title: 'Prohibited File Extensions [' + esc(name) + ']',
      inputs: [['rule', 'File extension, without the dot (.), e.g.: sql']], cols: [['rule', 'Rule']], empty: 'Please enter extension.',
      clean: extClean, tips: [CASE_TIP, 'Directly fill in the extension to be prohibited. For example, to prohibit access to *.sql files: sql.'] });
  }
  function uploadExtDialog(name) {
    csvList(name, 'upload_ext', { title: 'Prohibited File Types for Upload [' + esc(name) + ']',
      inputs: [['rule', 'File extension, without the dot (.), e.g.: sql']], cols: [['rule', 'Rule']], empty: 'Please enter extension.',
      clean: extClean, tips: [CASE_TIP, 'Directly fill in the extension to be prohibited. For example, to prohibit access to *.sql files: sql.'] });
  }
  function denyPathDialog(name) {
    kindList(name, 'dpath', { title: 'Prohibited URLs [' + esc(name) + ']',
      inputs: [['rule', 'URL address, e.g., /admin/update']], cols: [['rule', 'Rule']], empty: 'Please enter URL address.',
      map: function (v) { return { rule: /^[\^\\]/.test(v.rule) || /[*+?()[\]{}|$]/.test(v.rule) ? v.rule : '^' + regexEsc(v.rule) }; },
      tips: [CASE_TIP, 'Do not include URI parameters here; generally targeted at directory URLs. Example: /admin.'] });
  }
  function protectUrlDialog(name) {
    kindList(name, 'purl', { title: 'Protected URI Addresses [' + esc(name) + ']', width: 600, maxHeight: 250,
      inputs: [['path', 'URI address, e.g., /admin/update.'], ['param', 'Parameter Name'], ['value', 'Parameter Value']],
      cols: [['path', 'URI Address'], ['param', 'Parameter Name'], ['value', 'Parameter Value']],
      empty: 'Please enter address or parameter.',
      map: function (v) { return { path: /^[\^]/.test(v.path) ? v.path : '^' + regexEsc(v.path) + '$', param: v.param, value: v.value }; },
      tips: ['Can be used to protect backend addresses, API interfaces, and other non-public URI addresses from penetration.',
        'Parameter names and values are case sensitive.',
        'Set protected URL. Accessing this URL requires specified parameter name and value; otherwise, it will be intercepted by the firewall.',
        'Assuming URI address: /admin/admin.php, parameter name: test, parameter value: bt.cn.',
        'Correct access method: /admin/admin.php?test=bt.cn.'] });
  }
  function urlFilterDialog(name) {
    kindList(name, 'ufilter', { title: 'URL-Specific Filtering [' + esc(name) + ']', width: 600, maxHeight: 230,
      inputs: [['path', 'URL address, e.g., /admin/update'], ['rule', 'Filter Value, e.g., date.']],
      cols: [['path', 'URL Address'], ['rule', 'Filtering Rule']], empty: 'Please enter address or filtering rule.',
      map: function (v) { return { path: /^[\^]/.test(v.path) ? v.path : '^' + regexEsc(v.path), rule: v.rule }; },
      tips: ['Can be used to enhance protection for login interfaces, comment sections, etc., quickly patching security ' +
        'vulnerabilities in third-party programs.', 'Parameter names and values are case sensitive.',
        'This filter applies to both GET and POST parameters.',
        'Example: /admin/update.php?update=_date&date=666. The update parameter contains _date, which has a risk of ' +
        'vulnerability. It can be set to:',
        'URL address /admin/update.php, filtering rule _date, filtering the content of the parameter.'] });
  }

  /* ---------- HTTP package [site] ---------- */
  function bodyMaxDialog(name, c, done) {
    modal({
      title: 'HTTP package [' + esc(name) + ']', width: 480, ok: 'Apply',
      body: nf('Max body', nNum('bm-kb', c.body_max || 0, 120) + '<span class="wp-nf-u">KB</span>') +
        tips(['Largest request body allowed, uploads excluded. 0 = no limit of its own (the Global value applies).']),
      yes: function (close) {
        setField(name, { body_max: Math.max(+$('#bm-kb').val() || 0, 0) }, function () { close(); if (done) done(); });
      }
    });
  }
  /* ---------- Crawl limit [site] (unverified bots' own budget) ---------- */
  function crawlLimitDialog(name, c, done) {
    modal({
      title: 'Crawl limit [' + esc(name) + ']', width: 480, ok: 'Apply',
      body: nf('Limit', nNum('cl-n', c.crawl_limit || 30, 120) + '<span class="wp-nf-u">requests / minute per bot</span>') +
        tips(['Clients that look like bots but are not verified search engine crawlers get their own, much tighter budget.']),
      yes: function (close) {
        setField(name, { crawl_limit: +$('#cl-n').val() || 30 }, function () { close(); if (done) done(); });
      }
    });
  }

  /* ---------- Website Configuration [site] ----------
     The stock table's rows, in its order (f: the switch fields, set: what
     Set / Rule opens, conf: confirm before switching), then WAF Pro's own
     protections, which the stock WAF does not have per site. */
  function configRows(name, c) {
    var cnt = function (k) { return ((siteRow(name) || {}).rule_counts || {})[k] || 0; };
    var rules = function (k) { return function (done) { siteRules(name, k, true, done); }; };
    var listPs = function (ps, k) { return ps + (cnt(k) ? ' (' + cnt(k) + ')' : ''); };
    var setRules = function (set, title) { return function () { siteRuleSetDialog(name, set, title); }; };
    return [
      { t: 'CC defense', f: ['cc_open'], cc: true, set: function (done) { siteCcDialog(name, c, done); } },
      { t: 'Request defence', f: ['tolerate'], ps: 'Malicious request blocking threshold.',
        set: function (done) { tolerateDialog(name, c, done); } },
      { t: 'SQL injection defense', f: ['sqli', 'get'],
        ps: 'Detect malicious SQL statements and prevent malicious tampering of the database due to SQL injection',
        set: setRules('get', 'SQL injection defense') },
      { t: 'XSS Defense', f: ['xss', 'post'],
        ps: 'Detect XSS syntax to prevent web pages from being maliciously tampered with, user information leaked, and permissions stolen',
        set: setRules('post', 'XSS Defense') },
      { t: 'Command Execution Interception', f: ['rce'],
        ps: 'Determine and block the execution of potentially dangerous commands through the syntax model, effectively ' +
          'preventing hackers from invading the server through the website' },
      { t: 'Malicious file upload defense', f: ['upload'],
        ps: 'Detect malicious file uploads, prevent Trojans from being uploaded, and prevent server permissions from being lost' },
      { t: 'Malicious Download Defense', f: ['download'],
        ps: 'Detect malicious downloads and prevent backup files, source code, and other critical data from being downloaded',
        rule: setRules('scan', 'Malicious Download Defense') },
      { t: 'Malicious crawler defense', f: ['ua'],
        ps: 'Detect malicious crawlers and prevent malicious crawlers from accessing the website',
        rule: setRules('ua', 'Malicious crawler defense') },
      { t: 'Cookie filter', f: ['cookie'], ps: 'Filter out penetration attacks using cookies',
        set: setRules('cookie', 'Cookie filter') },
      { t: 'Scanner', f: ['scan'], ps: 'Filter penetration testing for common scan testing tools', set: scannerDialog },
      { t: 'Spider pond', f: ['spider'], ps: 'Default allowed spiders to crawl', spider: true,
        set: function () { spiderDialog(name, 'Spider pond'); } },
      { t: 'CDN', f: ['cdn'], ps: 'If the site uses CDN, the client IP can be obtained correctly after turn on, Get the last ' +
          'IP address of the request header as the client IP by default', set: function () { cdnHeadersDialog(name); } },
      { t: 'Get the first IP', f: ['cdn_first'], ps: 'When CDN is turned on, start with the first request header or the real IP' },
      { t: 'Read-only Mode', f: ['readonly'], readonly: true,
        ps: 'Read-only mode. Do not enable it outside attack-defense drills. Login, payment, search, registration, comments, ' +
          'and other features may be affected.' },
      { t: 'Block php exec', ps: 'Prohibit running PHP scripts at the specified URL', set: function () { phpPathDialog(name); } },
      { t: 'Forbidden URL', ps: listPs('Prohibit access to the specified URL', 'dpath'), set: function () { denyPathDialog(name); } },
      { t: 'Forbidden extension', ps: 'Prohibit access to the specified extension', set: function () { denyExtDialog(name); } },
      { t: 'Block File types', ps: 'File types prohibited from uploading', set: function () { uploadExtDialog(name); } },
      { t: 'Protected URL', ps: listPs('Encrypt the URL address with custom parameters, parameter errors will be intercepted', 'purl'),
        set: function () { protectUrlDialog(name); } },
      { t: 'URL filter', ps: listPs('Set filtering rules for specific URL addresses', 'ufilter'), set: function () { urlFilterDialog(name); } },
      // ---- WAF Pro only ----
      { t: 'Custom rule interception', f: ['nday'], extra: true,
        ps: 'Detect known exploits (PHP code execution, framework RCE, SSRF probes) with editable rules',
        rule: setRules('nday', 'Custom rule interception') },
      { t: 'IDC interception', f: ['idc'], ps: 'Refuse visitors from cloud / datacenter networks. Verified search crawlers still pass.' },
      { t: 'Non-browser interception', f: ['browser'],
        ps: 'Page loads must run JavaScript once. Blocks scripts and scrapers; verified crawlers, APIs and assets are not affected.' },
      { t: 'From-data protocol', f: ['form_strict'],
        ps: 'Reject malformed multipart/form-data bodies (no boundary, parts without Content-Disposition)' },
      { t: 'PHP2Shell guard', f: ['php_guard'],
        ps: 'Block the known triggers of CVE-2026-109618/109619 in PHP uploads. Updating PHP is the real fix.' },
      { t: 'Crawl limit', f: ['crawl'], ps: 'Unverified bots get their own budget: ' + num(c.crawl_limit || 30) + ' requests / minute',
        set: function (done) { crawlLimitDialog(name, c, done); } },
      { t: 'HTTP package', ps: 'Block oversized request bodies (uploads excluded): ' +
          (c.body_max ? num(c.body_max) + ' KB' : 'no limit of its own'), set: function (done) { bodyMaxDialog(name, c, done); } },
      { t: 'Anti-Leech', ps: listPs('Only this site and the listed domains may embed its files', 'leech'), set: rules('leech') },
      { t: 'API interface defense', ps: listPs('Restrict the methods of API endpoints and cap requests per IP', 'api'), set: rules('api') },
      { t: 'URL CC defense', ps: listPs('URL defense CC rule, priority is higher than URL whitelist', 'ucc'), set: rules('ucc') },
      { t: 'URL enhancement mode', ps: listPs('Setting up a URL validation rule independently', 'uverify'), set: rules('uverify') },
      { t: 'Machine verification whitelist', ps: listPs('Pages that are never asked for browser verification', 'vwhite'),
        set: rules('vwhite') },
      { t: 'URL request type interception', ps: listPs('Set URL interception request type separately', 'umethod'), set: rules('umethod') },
      { t: 'Content replace', ps: listPs('Replace text in the site\'s HTML pages', 'repl'), set: rules('repl') }
    ];
  }

  function siteConfig(name) {
    post('get_site_detail', { siteName: name }, function (c) {
      if (!c.status) { layer.msg(c.msg || 'error', { icon: 2 }); return; }
      var rows = configRows(name, c);
      function isOn(x) { return x.f.every(function (k) { return !!c[k]; }); }
      function body() {
        return rows.map(function (x, i) {
          var st = x.f ? '<label class="wp-sw wp-sw-sm"><input type="checkbox" class="wc-sw" data-i="' + i + '"' +
            (isOn(x) ? ' checked' : '') + '><span class="sl"></span></label>' : '--';
          var op = x.rule ? 'Rule' : (x.set ? 'Set' : '');
          var ps = x.cc ? 'Request the same URI more than <span class="red">' + num(c.cc_limit || 120) + '</span> times in ' +
            '<span class="red">' + num(c.cc_cycle || 60) + '</span> second, Block IP for <span class="red">' +
            num(c.cc_block || 600) + '</span> seconds.' : esc(x.ps);
          return '<tr' + (x.extra ? ' class="wc-extra"' : '') + '><td>' + esc(x.t) + '</td><td class="wc-ps">' + ps + '</td>' +
            '<td>' + st + '</td><td class="r">' + (op ? '<span class="wp-lnk wc-op" data-i="' + i + '">' + op + '</span>' : '') +
            '</td></tr>';
        }).join('');
      }
      modal({
        title: 'Website Configuration [' + esc(name) + ']', width: 760, minHeight: 554, footer: false, cls: 'wp-wc',
        body: '<div class="wp-wc-top"><span>Website Firewall Switch</span>' +
          '<label class="wp-sw"><input type="checkbox" id="wc-open"' + (c.open ? ' checked' : '') + '><span class="sl"></span></label></div>' +
          '<div class="wp-wc-box"><table class="wp-site-tbl"><thead><tr><th style="width:140px">Name</th><th>Description</th>' +
          '<th style="width:60px">Status</th><th class="r" style="width:80px">Operate</th></tr></thead>' +
          '<tbody id="wc-body">' + body() + '</tbody></table></div>' +
          tips(['Note: Most configurations here only apply to the current site!']),
        success: function ($el) {
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
            var patch = {};
            x.f.forEach(function (k) { patch[k] = on; });
            function go() { $cb.prop('checked', on); setField(name, patch, function () { $.extend(c, patch); }); }
            if (x.spider && !on) {
              $cb.prop('checked', true);
              return W.confirm('<div class="wp-cf-t">If spider crawling is disabled, the website will not be crawled!</div>' +
                '<div class="red" style="font-size:12px">Note: Disabling may affect data entry.</div>', { title: 'Tips' },
                function (i) { layer.close(i); go(); });
            }
            if (x.readonly && on) {
              $cb.prop('checked', false);
              return W.confirm('Maximize protection against intrusion, which may affect normal requests such as payments and APIs. ' +
                'Only web access is allowed; other actions will be intercepted. It is recommended to enable this only during ' +
                'attack-defense drills!', { title: 'Tips' }, function (i) { layer.close(i); go(); });
            }
            go();
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
  function cleanCsv(v) { return extClean(v).join(','); }
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
  W.scannerDialog = scannerDialog;
  W.siteConfig = siteConfig;
  W.siteFiltered = siteFiltered;
  W.siteRow = siteRow;
  W.siteRules = siteRules;
})(window.WAFPRO = window.WAFPRO || {});
