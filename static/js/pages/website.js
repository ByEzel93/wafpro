(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function renderTabs() { return W.renderTabs.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }

  /* ================= WEBSITE ================= */
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
        'nodes will be intercepted.</li>' +
        '<li>Modify opens every protection of the site (filters, CC, uploads, vulnerability defense, rules for URLs, ' +
        'hotlinking and APIs).</li></ul></div>';
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
  function qmark(tip) { return '<span class="wp-qm" title="' + esc(tip) + '">?</span>'; }

  function renderSiteTable() {
    var all = siteFiltered();
    var pages = Math.max(Math.ceil(all.length / S.siteSize), 1);
    if (S.sitePage > pages) S.sitePage = pages;
    var rows = all.slice((S.sitePage - 1) * S.siteSize, S.sitePage * S.siteSize);

    var h = '<div class="wp-site-box"><table class="wp-site-tbl"><thead><tr>' +
      '<th>Site</th><th>Total interceptions</th>' +
      '<th>Fake spider ' + qmark('Blocks clients calling themselves Googlebot/Bingbot/Applebot from IPs those crawlers do not use.') + '</th>' +
      '<th>Using CDN ' + qmark('Read the visitor IP from CF-Connecting-IP / X-Forwarded-For. Only when a CDN or proxy really sits in front.') + '</th>' +
      '<th>Smart CC defense ' + qmark('Tightens each visitor\'s CC allowance automatically while the whole site is under load. The number is today\'s Smart CC blocks.') + '</th>' +
      '<th>Crawl Protection</th><th>Waiting Room/Rate Limit</th>' +
      '<th>CC Defense</th><th>Status</th><th class="r">Operate</th></tr></thead><tbody>';
    h += rows.length ? rows.map(function (s) {
      var n = esc(s.name);
      return '<tr>' +
        '<td class="site" title="' + esc((s.domains || []).join(', ')) + '">' + n + '</td>' +
        '<td class="' + (s.intercepts ? 'red' : '') + '">' + num(s.intercepts) + '</td>' +
        '<td>' + cbx(s.name, 'fake_spider', s.fake_spider) + '</td>' +
        '<td>' + cbx(s.name, 'cdn', s.cdn) + '</td>' +
        '<td>' + cbx(s.name, 'smart_cc', s.smart_cc) + '<span class="cnt">' + num(s.smart_hits) + '</span></td>' +
        '<td>' + (s.crawl ? '<span class="on">' + num(s.crawl_limit) + '/min</span>' : '<span class="off">Disable</span>') + '</td>' +
        '<td>' + (s.wait ? '<span class="on">' + num(s.wait_limit) + '/s</span>' : '<span class="off">Disable</span>') + '</td>' +
        '<td title="' + num(s.cc_limit) + ' requests / ' + s.cc_cycle + 's">' + cbx(s.name, 'cc_open', s.cc_open) +
          '<span class="cnt">' + num(s.cc_hits) + '</span></td>' +
        '<td><label class="wp-sw wp-sw-sm"><input type="checkbox" class="wp-site-sw" data-n="' + n + '"' +
          (s.open ? ' checked' : '') + '><span class="sl"></span></label></td>' +
        '<td class="r"><span class="wp-lnk wp-site-log" data-n="' + n + '">Log</span><span class="sep"></span>' +
        '<span class="wp-lnk wp-site-mod" data-n="' + n + '">Modify</span></td></tr>';
    }).join('') : '<tr><td colspan="10" class="wp-empty">' +
      (S.sites.length ? 'No site matches "' + esc(S.siteQ) + '"' : 'No sites configured') + '</td></tr>';
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

    $('#wp-site-table').html(h);

    $('.wp-site-sw').on('change', function () {
      var n = $(this).data('n'), on = this.checked ? '1' : '0';
      post('set_site_field', { siteName: n, field: 'open', value: on }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        var s = S.sites.filter(function (x) { return x.name === n; })[0];
        if (s) s.open = on === '1';
      });
    });
    $('.wp-cbx').on('change', function () {
      var n = $(this).data('n'), f = $(this).data('f'), on = this.checked ? '1' : '0';
      post('set_site_field', { siteName: n, field: f, value: on }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        var s = S.sites.filter(function (x) { return x.name === n; })[0];
        if (s) s[f] = on === '1';
      });
    });
    $('.wp-site-pager .pg').on('click', function () {
      var p = $(this).data('p');
      if (p === 'prev') S.sitePage = Math.max(S.sitePage - 1, 1);
      else if (p === 'next') S.sitePage = Math.min(S.sitePage + 1, pages);
      else S.sitePage = parseInt(p, 10);
      renderSiteTable();
    });
    $('#wp-site-size').on('change', function () {
      S.siteSize = parseInt($(this).val(), 10); S.sitePage = 1; renderSiteTable();
    });
    $('#wp-site-goto').on('keydown', function (e) {
      if (e.keyCode !== 13) return;
      var p = parseInt($(this).val(), 10);
      if (p >= 1 && p <= pages) { S.sitePage = p; renderSiteTable(); }
    });
    $('.wp-site-log').on('click', function () {
      // jump to Blockade > Interception record, pre-filtered to this site
      S.blQ = $(this).data('n');
      S.blSub = 'intercept'; S.blDate = 'all';
      S.tab = 'blockade'; renderTabs(); route();
    });
    $('.wp-site-mod').on('click', function () { siteModify($(this).data('n')); });
  }

  function cbx(name, field, on) {
    return '<input type="checkbox" class="wp-cb wp-cbx" data-n="' + esc(name) + '" data-f="' + field + '"' + (on ? ' checked' : '') + '>';
  }

  function siteModify(name) {
    post('get_site_detail', { siteName: name }, function (c) {
      if (!c.status) { layer.msg(c.msg || 'error', { icon: 2 }); return; }
      var body = '<div class="wp-modal" id="wp-mod">' +
        '<div class="wp-mod-head">' +
          '<div class="wp-mod-site">' + esc(name) + '</div>' +
          '<div class="wp-mod-meta">' + ((siteRow(name) || {}).domains || []).map(esc).join(', ') +
          ' &middot; applies within a couple of seconds — no nginx reload.</div>' +
        '</div>' +
        '<div class="wp-mod-body">' +

        modSec('Protection', [
          modRow2('Protection', modSw('m-open', c.open), 'Master switch for this site'),
          modRow2('Scan protection', modSw('m-scan', c.scan), 'Block probes for .env, .git, backups'),
          modRow2('CDN', modSw('m-cdn', c.cdn),
            'The site sits behind a CDN/proxy: take the visitor IP from CF-Connecting-IP / X-Forwarded-For. ' +
            'Leave off otherwise — visitors could fake their IP.'),
          modRow2('Fake spider', modSw('m-spider', c.fake_spider),
            'Block clients that claim to be Googlebot/Bingbot/Applebot from IPs those crawlers do not use'),
          modRow2('IDC interception', modSw('m-idc', c.idc),
            'Refuse visitors from cloud/datacenter networks (AWS, Google Cloud, Oracle, DigitalOcean, Linode). ' +
            'Verified search crawlers still pass. Needs the list from Global &rsaquo; CC defense.')
        ]) +

        modSec('Website vulnerability defense', [
          modRow2('N-day exploits', modSw('m-nday', c.nday),
            'Virtual patches for public CVEs (PHP-CGI, ThinkPHP, PHPUnit, Ignition, Spring, Struts, F5...)'),
          modRow2('PHP2Shell guard', modSw('m-php-guard', c.php_guard),
            'Blocks the known triggers of CVE-2026-109618/109619 in uploads (no length, upload-progress field, ' +
            'part/header/nesting floods). Updating PHP is still the real fix.'),
          modRow2('From-data check', modSw('m-form-strict', c.form_strict),
            'Reject malformed multipart/form-data bodies (no boundary, parts without Content-Disposition)'),
          modRow2('Non-browser', modSw('m-browser', c.browser),
            'Page loads must run JavaScript once (cookie for a day). Blocks curl/scripts/scrapers; ' +
            'verified search crawlers, APIs and assets are not affected.'),
          modRow2('HTTP package',
            '<input class="wp-in" id="m-body-max" type="number" min="0" value="' + (c.body_max || 0) + '"> ' +
            '<span class="wp-unit">KB (0 = off)</span>',
            'Largest request body allowed, uploads excluded')
        ]) +

        modSec('Request filters', [
          modRow2('GET filter', modSw('m-get', c.get), 'Inspect query strings'),
          modRow2('POST filter', modSw('m-post', c.post), 'Inspect request bodies'),
          modRow2('Cookie filter', modSw('m-cookie', c.cookie), 'Inspect cookies'),
          modRow2('User-Agent filter', modSw('m-ua', c.ua), 'Block scanners by their user-agent')
        ]) +

        modSec('CC defense', [
          modRow2('CC defense', modSw('m-cc', c.cc_open), 'Rate-limit repeated requests from one IP'),
          modRow2('Threshold',
            '<input class="wp-in" id="m-cc-limit" type="number" value="' + (c.cc_limit || 120) + '"> ' +
            '<span class="wp-unit">requests /</span> ' +
            '<input class="wp-in" id="m-cc-cycle" type="number" value="' + (c.cc_cycle || 60) + '"> ' +
            '<span class="wp-unit">seconds</span>', ''),
          modRow2('Block time',
            '<input class="wp-in" id="m-cc-block" type="number" value="' + (c.cc_block || 600) + '"> ' +
            '<span class="wp-unit">seconds</span>', 'How long an offending IP stays blocked'),
          modRow2('Smart CC', modSw('m-smart', c.smart_cc),
            'Tighten each visitor&apos;s allowance automatically while the whole site is under load'),
          modRow2('Over the limit',
            '<select class="wp-in" id="m-cc-mode" style="width:220px">' +
            '<option value="block"' + (c.cc_mode !== 'challenge' ? ' selected' : '') + '>Block the IP</option>' +
            '<option value="challenge"' + (c.cc_mode === 'challenge' ? ' selected' : '') + '>Ask to verify (browser check)</option>' +
            '</select>',
            'Verify: a real browser passes the check and gets 4x the allowance; scripts stay blocked')
        ]) +

        modSec('Traffic control', [
          modRow2('Crawl protection', modSw('m-crawl', c.crawl),
            'Give unverified bots their own tight budget (verified crawlers unaffected)'),
          modRow2('Crawl limit',
            '<input class="wp-in" id="m-crawl-limit" type="number" value="' + (c.crawl_limit || 30) + '"> ' +
            '<span class="wp-unit">requests / minute</span>', ''),
          modRow2('Waiting room', modSw('m-wait', c.wait),
            'Past the rate below, extra visitors get a retry page instead of a timeout'),
          modRow2('Rate limit',
            '<input class="wp-in" id="m-wait-limit" type="number" value="' + (c.wait_limit || 200) + '"> ' +
            '<span class="wp-unit">requests / second (site-wide)</span>', '')
        ]) +

        modSec('Files', [
          modRow2('Never serve extensions',
            '<input class="wp-in wp-wide" id="m-deny-ext" value="' + esc(c.deny_ext || '') + '" placeholder="sql, bak, ini">',
            'Comma separated, no dots. Direct requests for these files are refused.', true),
          modRow2('Blocked upload extensions',
            '<input class="wp-in wp-wide" id="m-upload-ext" value="' + esc(c.upload_ext || '') + '" placeholder="php, jsp, exe">',
            'Refuse uploads whose filename ends in these — the usual webshell route.', true),
          modRow2('No PHP under paths',
            '<input class="wp-in wp-wide" id="m-php-path" value="' + esc(c.php_path || '') + '" placeholder="/upload/, /static/">',
            'Comma separated path prefixes. A .php request under them is refused, ' +
            'so an uploaded shell cannot execute.', true)
        ]) +

        '</div>' +
        '<div class="wp-mod-foot">' +
          '<span class="wp-btn" id="m-rules" style="margin-right:auto">URL, hotlink &amp; API rules' +
            (ruleTotal(siteRow(name) || {}) ? ' (' + ruleTotal(siteRow(name)) + ')' : '') + '</span>' +
          '<span class="wp-btn" id="m-cancel">Cancel</span>' +
          '<span class="wp-btn primary" id="m-save">Save</span>' +
        '</div></div>';
      W.open({
        type: 1, title: 'Modify site — ' + name, area: ['720px', '680px'], content: body,
        success: function () {
          $('#m-cancel').on('click', function () { layer.closeAll('page'); });
          $('#m-rules').on('click', function () { siteRules(name, 'dpath'); });
          $('#m-save').on('click', function () {
            var cfg = {
              open: $('#m-open').is(':checked'), scan: $('#m-scan').is(':checked'),
              fake_spider: $('#m-spider').is(':checked'), cdn: $('#m-cdn').is(':checked'),
              get: $('#m-get').is(':checked'), post: $('#m-post').is(':checked'),
              cookie: $('#m-cookie').is(':checked'), ua: $('#m-ua').is(':checked'),
              cc_open: $('#m-cc').is(':checked'),
              cc_limit: parseInt($('#m-cc-limit').val() || 120, 10),
              cc_cycle: parseInt($('#m-cc-cycle').val() || 60, 10),
              cc_block: parseInt($('#m-cc-block').val() || 600, 10),
              smart_cc: $('#m-smart').is(':checked'),
              crawl: $('#m-crawl').is(':checked'),
              crawl_limit: parseInt($('#m-crawl-limit').val() || 30, 10),
              wait: $('#m-wait').is(':checked'),
              wait_limit: parseInt($('#m-wait-limit').val() || 200, 10),
              php_guard: $('#m-php-guard').is(':checked'),
              nday: $('#m-nday').is(':checked'),
              idc: $('#m-idc').is(':checked'),
              form_strict: $('#m-form-strict').is(':checked'),
              browser: $('#m-browser').is(':checked'),
              body_max: Math.max(parseInt($('#m-body-max').val() || 0, 10), 0),
              cc_mode: $('#m-cc-mode').val(),
              deny_ext: cleanCsv($('#m-deny-ext').val()),
              upload_ext: cleanCsv($('#m-upload-ext').val()),
              php_path: cleanCsv($('#m-php-path').val())
            };
            post('save_site_detail', { siteName: name, config: JSON.stringify(cfg) }, function (rr) {
              layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
              if (rr.status) { layer.closeAll('page'); pageWebsite(); }
            });
          });
        }
      });
    });
  }
  // normalise "php, .jsp ,exe" -> "php,jsp,exe"; the engine matches bare, lowercase
  function cleanCsv(v) {
    return (v || '').split(',').map(function (x) {
      return x.trim().replace(/^\./, '').toLowerCase();
    }).filter(Boolean).join(',');
  }
  function modSec(title, rows) {
    return '<div class="wp-mod-sec"><div class="wp-mod-sec-t">' + title + '</div>' +
      rows.join('') + '</div>';
  }
  function modRow2(label, ctrl, hint, wide) {
    return '<div class="wp-mod-row' + (wide ? ' wide' : '') + '">' +
      '<div class="wp-mod-lbl">' + label + '</div>' +
      '<div class="wp-mod-ctl">' + ctrl + '</div>' +
      '<div class="wp-mod-hint">' + (hint || '') + '</div>' +
      '</div>';
  }
  function modSw(id, on) {
    return '<label class="wp-sw"><input type="checkbox" id="' + id + '"' + (on ? ' checked' : '') + '><span class="sl"></span></label>';
  }

  function siteRow(name) { return (S.sites || []).filter(function (x) { return x.name === name; })[0]; }
  function ruleTotal(s) {
    var c = s.rule_counts || {}, n = 0;
    Object.keys(c).forEach(function (k) { n += c[k] || 0; });
    return n;
  }

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

  function siteRules(name, kind, single) {
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
        type: 1, title: single ? cur.t : (name === '*' ? 'Global rules' : 'Site rules — ' + name),
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
              if (rr.status) siteRules(name, cur.k, single);
            });
          });
          $('.sr-del').on('click', function () {
            post('site_rule_del', { siteName: name, kind: cur.k, index: $(this).data('i') }, function (rr) {
              layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
              if (rr.status) siteRules(name, cur.k, single);
            });
          });
        },
        end: function () { if (!S.srSwitching && S.tab === 'website') pageWebsite(); }
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
  W.modSec = modSec;
  W.modSw = modSw;
  W.pageWebsite = pageWebsite;
  W.renderSiteTable = renderSiteTable;
  W.ruleTotal = ruleTotal;
  W.siteFiltered = siteFiltered;
  W.siteModify = siteModify;
  W.siteRow = siteRow;
  W.siteRules = siteRules;
})(window.WAFPRO = window.WAFPRO || {});
