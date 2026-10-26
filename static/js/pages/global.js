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

  /* ---------------- Global: the stock WAF's settings page ----------------
     Sub tabs (All, CC defense, Access filter, Website vulnerability
     defense, Sensitive words) jump to their section and follow the scroll.
     Each card: title + switch on top, description + "Status [code]" picker
     and buttons below. A protection runs only when its card is on here AND
     the website has it on (WebSite > Modify). */
  var RESP_CODES = [[200, '200 Normal access'], [404, '404 File not exist'], [403, '403 Access denied'],
                    [444, '444 Close connection'], [500, '500 Application error'],
                    [502, '502 Connection timed out'], [503, '503 Server is unavailable']];

  function saveCfg(patch, done) {
    post('save_config', { config: JSON.stringify(patch) }, function (rr) {
      layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
      if (rr.status && done) done();
    });
  }

  var G_SECTIONS = [['all', 'Global'], ['cc', 'CC defense'], ['filter', 'Access filter'],
                    ['site', 'Website vulnerability defense'], ['sensitive', 'Sensitive words']];

  // cards per section. sw: config key (or {get, set} for special switches),
  // st: config key of the response code, btns: [[label, action, primary?]]
  function globalCards(c, extra) {
    var mal = extra.mal || {}, sp = extra.sp || {}, idc = extra.idc || {};
    var rules = function (set) { return function () { ruleSetDialog(set); }; };
    var resp = ['Response content', blockPage];
    return {
      cc: [
        { t: 'CC defense', d: 'Defense against CC attacks, please adjust the specific defense parameters in the site configuration',
          sw: 'm_cc', st: 'cc_status', btns: [['Set rule', ccRuleDialog, 1]] },
        { t: 'Request defence', d: 'Malicious request blocking threshold.', btns: [['Set rule', toleranceDialog, 1]] },
        { t: 'Static file protection', d: 'CC protection by default will not protect: JS, CSS, GIF, JPG, JPEG, PNG, these static ' +
          'files, if it is not brushed image traffic is not recommended to always open.', sw: 'static_protect' },
        { t: 'Malicious IP library', d: 'Block known malicious IPs from public feeds (ipsum, blocklist.de, Spamhaus DROP, Feodo)' +
          (mal.have ? ' — ' + num(mal.count) + ' ranges, updated ' + esc(mal.updated) : ' — click Synchronize to download'),
          sw: { on: !!mal.open, set: function (on, $cb) {
            post('malicious_toggle', { open: on ? 1 : 0 }, function (rr) {
              layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (!rr.status) $cb.prop('checked', !on);
            }); } },
          btns: [['Synchronize', function () { syncList('malicious_update'); }]] },
        { t: 'URL CC defense', d: 'URL defense CC rule, priority is higher than URL whitelist',
          btns: [['Set', function () { W.siteRules('*', 'ucc', true); }, 1]] },
        { t: 'URL enhancement mode', d: 'Setting up a URL validation rule independently',
          btns: [['Set', function () { W.siteRules('*', 'uverify', true); }, 1]] },
        { t: 'Machine verification whitelist', d: 'Use when you need to not validate certain pages when enabling human authentication',
          btns: [['Set', function () { W.siteRules('*', 'vwhite', true); }, 1]] }
      ],
      filter: [
        { t: 'Non-browser interception', d: 'Can defend against crawler attacks and non-browser access. Currently, it will be ' +
          'applied to all websites. If the website has CDN enabled, it is recommended to turn on CDN for the site first.',
          sw: 'browser_all' },
        { t: 'HTTP request filtering', d: 'HTTP request type filtering/request header filtering/request quantity filtering',
          btns: [['Set', function () { httpFilterDialog(extra.methods, extra.hdr); }, 1]] },
        { t: 'URL request type interception', d: 'Set URL interception request type separately',
          btns: [['Set', function () { W.siteRules('*', 'umethod', true); }, 1]] },
        { t: 'API interface defense', d: 'When some interfaces are in the whitelist, one of them needs to be used under CC defense',
          btns: [['Set', function () { W.siteRules('*', 'api', true); }, 1]] },
        { t: 'Spider pond', d: 'By default, all major search engine spiders are allowed to crawl' +
          (sp.have ? ' — ' + num(sp.count) + ' verified crawler ranges' : ' — click Synchronize to download the crawler IP lists'),
          btns: [['Synchronize', function () { syncList('spider_update'); }]] },
        { t: 'IDC interception list', d: 'Cloud / datacenter address space used by the per-site IDC interception switch' +
          (idc.have ? ' — ' + num(idc.count) + ' ranges' : ' — click Synchronize to download'),
          btns: [['Synchronize', function () { syncList('idc_update'); }]] },
        { t: 'HTTP package', d: 'Block oversized request bodies (uploads excluded) on every website without its own limit.',
          sw: 'http_all', st: 'header_status', btns: [['Set', function () { httpPackageDialog(c); }, 1]] }
      ],
      site: [
        { t: 'SQL injection defense', d: 'Detect malicious SQL statements and prevent malicious tampering of the database due to SQL injection',
          n: 'Semantic analysis per parameter. If the content published on your website contains SQL statements, enabling this defense may block publishing.',
          sw: 'm_sqli', st: 'sqli_status', btns: [resp] },
        { t: 'XSS Defense', d: 'Detect XSS syntax to prevent web pages from being maliciously tampered with, user information leaked, and permissions stolen',
          n: 'If the content published on your website contains javascript tutorials, enabling this defense may block publishing.',
          sw: 'm_xss', st: 'xss_status', btns: [resp] },
        { t: 'Command Execution Interception', d: 'Determine and block the execution of potentially dangerous commands and file ' +
          'access through the syntax model, preventing hackers from invading the server', sw: 'm_rce', st: 'rce_status' },
        { t: 'Weak password defense', d: 'Real-time detection of weak password login and interception', sw: 'weak_pass' },
        { t: 'Sensitive information detection', d: 'Intercept sensitive information in error messages, including SQL errors, PHP errors, etc.',
          sw: 'info_leak' },
        { t: 'GET filter', d: 'Regex rules for SQL injection, XSS, traversal and code execution in the URI and its parameters',
          sw: 'm_get', st: 'get_status', btns: [['Rule', rules('get')], resp] },
        { t: 'POST filter', d: 'Regex rules for attacks in form and JSON request bodies', sw: 'm_post', st: 'post_status',
          btns: [['Rule', rules('post')], resp] },
        { t: 'Malicious file upload defense', d: 'Detect malicious file uploads, prevent Trojans from being uploaded, and prevent server permissions from being lost',
          n: 'If you upload a file with the keyword php in the file name, enabling this defense may block it.',
          sw: 'm_upload', st: 'post_status', btns: [resp] },
        { t: 'PHP2Shell guard', d: 'Block the known triggers of CVE-2026-109618/109619 in PHP uploads. Updating PHP is the real fix.',
          sw: 'm_php2shell', st: 'php2shell_status', btns: [['Set', function () { php2shellDialog(c); }, 1]] },
        { t: 'From-data protocol', d: 'From-data is the default format for file uploads, and the firewall only trusts the default ' +
          'format. Turning this on rejects malformed upload bodies on every website.', sw: 'form_all' },
        { t: 'Malicious Download Defense', d: 'Detect malicious downloads and prevent backup files, source code, and other critical data from being downloaded',
          n: 'Uses each website\'s forbidden extensions (WebSite › Modify).', sw: 'm_download', st: 'black_status', btns: [resp] },
        { t: 'Custom rule interception', d: 'Detect known exploits (PHP code execution, framework RCE, SSRF probes) with editable rules',
          sw: 'm_nday', st: 'get_status', btns: [['Rule', rules('nday')], resp] },
        { t: 'Malicious crawler defense', d: 'Detect malicious crawlers and prevent malicious crawlers from accessing the website',
          n: 'If your website needs to be included in the search engine, be sure not to add the search engine features.',
          sw: 'm_ua', st: 'ua_status', btns: [['Rule', rules('ua')], resp] },
        { t: 'Malicious Cookie Defense', d: 'Detect whether the cookie contains malicious code, SQL injection, XSS attack',
          sw: 'm_cookie', st: 'cookie_status', btns: [['Rule', rules('cookie')], resp] },
        { t: 'Malicious Scanner Defense', d: 'Detect malicious scanners, prevent all kinds of scanners, Trojan connection tools, and access to the website',
          n: 'If your website is doing security testing, it may be blocked.',
          sw: 'm_scan', st: 'scan_status', btns: [['Set', rules('scan'), 1]] },
        { t: 'Directory Scan Defense', d: 'Prevent directory/file scanning, and perform statistical interception through the 404 status code of the access.',
          n: 'If your webpage has many 404 images, it may cause access to be blocked.',
          sw: 'dirscan', btns: [['Set', function () { dirscanDialog(c); }, 1]] },
        { t: 'Trojan detection', d: 'Webshell inspection of the website files. The results are on the Webshell page.',
          btns: [['Set', function () { S.tab = 'webshell'; W.renderTabs(); route(); }, 1]] },
        { t: 'Logging', d: 'Write intercepted requests to /www/wwwlogs/wafpro/, kept for ' + (c.log_save || 30) + ' days.',
          sw: 'log', btns: [['Set', function () { logDialog(c); }, 1]] }
      ],
      sensitive: [
        { t: 'Sensitive text replacement', d: 'Replace the set sensitive text in the pages of every website.',
          btns: [['Set', function () { W.siteRules('*', 'repl', true); }, 1]] },
        { t: 'URL keyword interception', d: 'Intercept keywords from URL',
          btns: [['Set', function () { wordListDialog('url_keyword', 'URL keyword interception', 'For example: find.zip'); }, 1]] },
        { t: 'Banned words', d: 'Banned banned words or phrases in text',
          btns: [['Set', function () { wordListDialog('sensitive', 'Banned words', 'Illegal word'); }, 1]] }
      ]
    };
  }

  function stSel(key, val) {
    return '<span class="wp-st" data-key="' + key + '">Status [' + (val || '-') + ']<i></i></span>';
  }

  function renderGlobal(c, m, hl, sp, ml, senList) {
    var e = c.engine || {};
    var cards = globalCards(c, { mal: ml, sp: sp, idc: S.idcStatus, methods: m, hdr: hl });
    var all = [];
    function card(x) {
      var i = all.push(x) - 1, on = false;
      if (x.sw && typeof x.sw === 'object') on = x.sw.on;
      else if (x.sw) on = c[x.sw] === true;
      return '<div class="wp-sc" data-i="' + i + '">' +
        '<div class="wp-sc-top"><div class="wp-sc-t">' + esc(x.t) + '</div>' +
          (x.sw ? '<label class="wp-sw"><input type="checkbox" class="wp-sc-sw"' + (on ? ' checked' : '') + '><span class="sl"></span></label>' : '') +
        '</div>' +
        '<div class="wp-sc-bot"><div class="wp-sc-d">' + x.d + (x.n ? '<div class="wp-sc-n">' + esc(x.n) + '</div>' : '') + '</div>' +
          '<div class="wp-sc-btns">' + (x.st ? stSel(x.st, c[x.st]) : '') +
          (x.btns || []).map(function (b, j) {
            return '<span class="wp-btn wp-sc-b' + (b[2] ? ' ghost' : '') + '" data-j="' + j + '">' + esc(b[0]) + '</span>';
          }).join('') + '</div></div></div>';
    }

    var h = '<div class="wp-g">';
    h += '<div class="wp-g-tabs" id="g-tabs">' + G_SECTIONS.map(function (x) {
      return '<span class="wp-g-tab' + (x[0] === 'all' ? ' on' : '') + '" data-g="' + x[0] + '">' + (x[0] === 'all' ? 'All' : x[1]) + '</span>';
    }).join('') + '</div>';

    // Global
    h += '<div class="wp-g-sec" id="g-sec-all"><div class="wp-g-title">Global</div>' +
      '<div class="wp-g-main' + (c.open ? '' : ' off') + '" id="g-main">' +
        '<div class="wp-sc-top"><div class="wp-sc-t">Switch</div>' + sw('g-open', c.open) + '</div>' +
        '<div class="wp-sc-bot"><div class="wp-sc-d">All protection will be ineffective when this switch is turned off</div>' +
        '<div class="wp-sc-btns"><span class="wp-btn ghost" id="g-sim">Simulated attack</span>' +
        '<span class="wp-btn ghost" id="g-export">Export</span><span class="wp-btn ghost" id="g-import">Import</span>' +
        '<span class="wp-btn ghost" id="g-restore">Restore default config</span></div></div></div>' +
      '<div class="wp-sc">' +
        '<div class="wp-sc-top"><div class="wp-sc-t">Engine</div>' + sw('g-wired', e.wired) + '</div>' +
        '<div class="wp-sc-bot"><div class="wp-sc-d">Wire the WAF Pro engine into nginx (tested with nginx -t, rolled back on failure).' +
          '<div class="wp-sc-n" style="color:inherit">' + engineStatusText(e, c.health) + '</div></div>' +
        '<div class="wp-sc-btns">' + (e.installed && !e.current ? '<span class="wp-btn ghost" id="g-engine-update">Update engine</span>' : '') +
        '</div></div></div></div>';

    G_SECTIONS.slice(1).forEach(function (sec) {
      h += '<div class="wp-g-sec" id="g-sec-' + sec[0] + '"><div class="wp-g-title muted">' + sec[1] + '</div>' +
        cards[sec[0]].map(card).join('') + '</div>';
    });
    h += '<ul class="wp-site-tips">' +
      '<li>Inheritance: The global setting will automatically inherit the default value in the site configuration</li>' +
      '<li>Priority: IP whitelist &gt; IP blacklist &gt; UA whitelist &gt; UA blacklist &gt; URL CC defense &gt; URL whitelist &gt; ' +
      'URL blacklist &gt; URL keyword interception &gt; Spider &gt; Region &gt; Malicious crawler &gt; Scanner &gt; Custom rule &gt; ' +
      'SQL injection / XSS &gt; GET &gt; Cookie &gt; POST &gt; Non-browser &gt; CC defense &gt; Traffic limit</li></ul>';
    h += '</div>';
    $('#wp-body').html(h);

    /* ---- sub tabs: jump to a section, follow the scroll ---- */
    var $body = $('#wp-body');
    function offsets() {
      return G_SECTIONS.map(function (x) {
        var el = document.getElementById('g-sec-' + x[0]);
        return [x[0], el ? el.offsetTop - document.getElementById('g-tabs').offsetHeight - 20 : 0];
      });
    }
    var jumping = false;
    $('#g-tabs').on('click', '.wp-g-tab', function () {
      var g = $(this).data('g');
      $('#g-tabs .wp-g-tab').removeClass('on'); $(this).addClass('on');
      var top = g === 'all' ? 0 : (offsets().filter(function (x) { return x[0] === g; })[0] || [0, 0])[1];
      jumping = true;
      $body.stop().animate({ scrollTop: top }, 300, function () { setTimeout(function () { jumping = false; }, 50); });
    });
    $body.on('scroll.gtabs', function () {
      if (jumping) return;
      var y = $body.scrollTop() + 2, cur = 'all';
      offsets().forEach(function (x) { if (x[1] <= y) cur = x[0]; });
      $('#g-tabs .wp-g-tab').removeClass('on').filter('[data-g=' + cur + ']').addClass('on');
    });

    /* ---- card controls ---- */
    $body.on('change', '.wp-sc-sw', function () {
      var x = all[$(this).closest('.wp-sc').data('i')], on = this.checked;
      if (typeof x.sw === 'object') return x.sw.set(on, $(this));
      var p = {}; p[x.sw] = on; c[x.sw] = on;
      saveCfg(p);
    });
    $body.on('click', '.wp-sc-b', function () {
      var x = all[$(this).closest('.wp-sc').data('i')];
      x.btns[$(this).data('j')][1]();
    });
    $body.on('click', '.wp-st', function (ev) {
      ev.stopPropagation();
      var $st = $(this), key = $st.data('key');
      $('.wp-st-menu').remove();
      var $m = $('<div class="wp-st-menu">' + RESP_CODES.map(function (r) {
        return '<div class="wp-st-opt' + (+c[key] === r[0] ? ' on' : '') + '" data-v="' + r[0] + '">' + r[1] + '</div>';
      }).join('') + '</div>').appendTo($st);
      $m.on('click', '.wp-st-opt', function (e2) {
        e2.stopPropagation();
        var v = +$(this).data('v'), p = {};
        p[key] = v; c[key] = v;
        $m.remove();
        saveCfg(p, function () { $('.wp-st[data-key=' + key + ']').html('Status [' + v + ']<i></i>'); });
      });
      $(document).one('click', function () { $m.remove(); });
    });

    $('#g-open').on('change', function () {
      var on = this.checked;
      $('#g-main').toggleClass('off', !on);
      saveCfg({ open: on });
    });
    $('#g-wired').on('change', function () {
      var on = this.checked;
      post('engine_wire', { open: on ? 1 : 0 }, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); route(); });
    });
    $('#g-sim').on('click', function () { selfTestDialog(''); });
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
      layer.confirm('All configurations will be cleared and restored to the default configuration, including URL black and white list, IP black and white list...',
        { icon: 3, title: 'Restoring default configuration' }, function (i) {
          layer.close(i);
          post('restore_config', {}, function (rr) { layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) route(); });
        });
    });
  }

  function dirscanDialog(c) {
    gDialog('Directory Scan Defense', 520,
      fRow('Access time', nIn('ds-time', c.dirscan_time) + ' <span class="wp-unit">Sec</span>') +
      fRow('Number of attacks', nIn('ds-count', c.dirscan_count) + ' <span class="wp-unit">404 responses</span>') +
      '<ul class="wp-site-tips"><li>This interception is to defend against 404 links generated by accessing URLs: an IP collecting more ' +
      '404 responses than the number above within the time above is banned.</li><li>The minimum cannot be less than 20 times in 20 seconds.</li></ul>',
      function (close) {
        var t = +$('#ds-time').val(), n = +$('#ds-count').val();
        if (t < 20 || n < 20) return layer.msg('The minimum cannot be less than 20 times in 20 seconds', { icon: 2 });
        saveCfg({ dirscan_time: t, dirscan_count: n }, close);
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
  W.globalCards = globalCards;
  W.stSel = stSel;
  W.dirscanDialog = dirscanDialog;
  W.G_SECTIONS = G_SECTIONS;
})(window.WAFPRO = window.WAFPRO || {});
