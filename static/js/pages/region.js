(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function icoWarn() { return W.icoWarn.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }

  /* ================= REGION (aaPanel 8 layout, our engine) =================
     Table: Area / Status / Status code / Website / Type / Operate(Response,
     Delete). The add dialog is the stock area picker: Hot area tags, then
     continents that open their own tab of countries. */

  // Above this the dialog warns: the engine binary-searches the ranges, but
  // the panel still compiles and writes them (the US alone is ~43k ranges).
  var REG_WARN_CIDR = 20000;

  var REG_CODES = [
    { code: 200, name: '200 Normal access' },
    { code: 404, name: '404 File not exist' },
    { code: 403, name: '403 Access denied' },
    { code: 444, name: '444 Close connection (No content)' },
    { code: 502, name: '502 Connection timed out' },
    { code: 503, name: '503 Server is unavailable' }
  ];

  // ISO 3166 codes per continent (anything unlisted shows under Other)
  var CONTINENTS = [
    ['AS', 'Asia', 'AF AM AZ BH BD BT BN KH CN CY GE HK IN ID IR IQ IL JP JO KZ KW KG LA LB MO MY MV MN MM NP KP OM PK PS PH QA SA SG KR LK SY TW TJ TH TL TR TM AE UZ VN YE IO'],
    ['EU', 'Europe', 'AX AL AD AT BY BE BA BG HR CZ DK EE FO FI FR DE GI GR GG HU IS IE IM IT JE XK LV LI LT LU MT MD MC ME NL MK NO PL PT RO RU SM RS SK SI ES SJ SE CH UA GB VA EU'],
    ['NA', 'North America', 'AI AG AW BS BB BZ BM BQ VG CA KY CR CU CW DM DO SV GL GD GP GT HT HN JM MQ MX MS NI PA PR BL KN LC MF PM VC SX TT TC US VI UM'],
    ['SA', 'South America', 'AR BO BR CL CO EC FK GF GY PY PE SR UY VE'],
    ['AF', 'Africa', 'DZ AO BJ BW BF BI CV CM CF TD KM CD CG CI DJ EG GQ ER SZ ET GA GM GH GN GW KE LS LR LY MG MW ML MR MU YT MA MZ NA NE NG RE RW SH ST SN SC SL SO ZA SS SD TZ TG TN UG EH ZM ZW'],
    ['OC', 'Oceania', 'AS AU CK FJ PF GU KI MH FM NR NC NZ NU NF MP PW PG PN WS SB TK TO TV VU WF'],
    ['AN', 'Antarctica', 'AQ BV GS HM TF']
  ];
  var HOT = 'CN US RU IN BR DE GB FR NL JP KR HK SG VN ID TR UA IR'.split(' ');

  function pageRegion() {
    $('#wp-body').html('<div class="wp-loading">Loading...</div>');
    post('region_rules', {}, function (r) {
      if (!r.status) { $('#wp-body').html('<div class="wp-note">' + esc(r.msg || 'error') + '</div>'); return; }
      post('country_list', {}, function (c) {
        S.regAll = (c && c.status) ? c.data : [];
        S.regMeta = r;
        renderRegion(r);
      });
    });
  }

  function siteText(sites) {
    return (sites || []).map(function (x) { return x === '*' ? 'All websites' : x; }).join(', ');
  }

  function renderRegion(r) {
    var e = r.engine || {};
    var h = '';
    if (!e.wired) {
      h += '<div class="wp-note" style="margin-bottom:12px">' + icoWarn() +
        ' The WAF Pro engine is not wired into nginx yet, so these rules are stored but <b>not enforced</b>.</div>';
    }
    h += '<div class="wp-card"><div class="wp-bl-bar" style="margin-bottom:14px">' +
      '<span class="wp-btn primary" id="rg-add">Add Region Restriction</span></div>';
    h += '<div class="wp-site-box"><table class="wp-site-tbl"><thead><tr>' +
      '<th style="min-width:300px">Area</th><th>Status</th><th>Status code</th><th style="min-width:200px">Website</th>' +
      '<th>Type</th><th class="r">Operate</th></tr></thead><tbody>';
    h += r.rules.length ? r.rules.map(function (x) {
      var opts = REG_CODES.map(function (s) {
        return '<option value="' + s.code + '"' + (s.code === x.status ? ' selected' : '') + '>' + esc(s.name) + '</option>';
      }).join('');
      return '<tr data-id="' + esc(x.id) + '">' +
        '<td class="ell" style="max-width:380px;white-space:normal" title="' + esc(x.area_text) + '">' + esc(x.area_text) + '</td>' +
        '<td><label class="wp-sw wp-sw-sm"><input type="checkbox" class="rg-on"' + (x.open ? ' checked' : '') + '><span class="sl"></span></label></td>' +
        '<td><select class="wp-in rg-code" style="width:210px;height:28px">' + opts + '</select></td>' +
        '<td class="ell" style="max-width:260px">' + esc(siteText(x.sites)) + '</td>' +
        '<td>' + (x.type === 'pass' ? 'Pass' : 'Intercept') + '</td>' +
        '<td class="wp-ops"><span class="wp-lnk rg-page">Response' + (x.page ? ' *' : '') + '</span>' +
        '<span class="wp-ops-sep">|</span><span class="wp-lnk rg-del">Delete</span></td></tr>';
    }).join('') : '<tr><td colspan="6" class="wp-empty">No Data</td></tr>';
    h += '</tbody></table></div></div>';
    $('#wp-body').html(h);

    $('#rg-add').on('click', regAddDialog);
    $('#wp-body').on('change', '.rg-on', function () {
      var id = $(this).closest('tr').data('id'), on = $(this).is(':checked');
      post('region_rule_toggle', { id: id, open: on ? 1 : 0 }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
      });
    });
    $('#wp-body').on('change', '.rg-code', function () {
      var id = $(this).closest('tr').data('id');
      post('region_rule_status', { id: id, status_code: $(this).val() }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
      });
    });
    $('#wp-body').on('click', '.rg-page', function () {
      var id = $(this).closest('tr').data('id');
      post('region_page_get', { id: id }, function (rr) {
        if (!rr.status) { layer.msg(rr.msg, { icon: 2 }); return; }
        htmlEditDialog({
          title: 'Online Edit [Region rule response]', html: rr.html, def: rr.default,
          hint: 'Sent with the rule\'s status code instead of the shared block page. Leave empty to use the default page ' +
            '(444 always just closes the connection).',
          save: function (html, done) {
            post('region_page_save', { id: id, html: html }, function (sr) {
              layer.msg(sr.msg, { icon: sr.status ? 1 : 2 });
              if (sr.status) { done(); route(); }
            });
          }
        });
      });
    });
    $('#wp-body').on('click', '.rg-del', function () {
      var id = $(this).closest('tr').data('id');
      layer.confirm('Delete this region restriction?', { icon: 3, title: 'Delete' }, function (i) {
        layer.close(i);
        post('region_rule_del', { id: id }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) route();
        });
      });
    });
  }

  /* ---- online HTML editor (Region Response, Traffic Limit web content) ----
     o: { title, html, def, hint, save(html, done) } */
  function htmlEditDialog(o) {
    var idx = layer.open({
      type: 1, title: o.title, area: ['900px', '600px'], btn: ['Save', 'Restore default', 'Cancel'],
      content: '<div class="wp-g-dlg" style="height:100%;display:flex;flex-direction:column;box-sizing:border-box">' +
        (o.hint ? '<div style="color:#909399;font-size:12px;margin-bottom:8px">' + esc(o.hint) + '</div>' : '') +
        '<textarea class="wp-in wp-html-ed" id="wp-html-ed" spellcheck="false"></textarea></div>',
      success: function () { $('#wp-html-ed').val(o.html || o.def || ''); },
      yes: function () { o.save($('#wp-html-ed').val() || '', function () { layer.close(idx); }); },
      btn2: function () { o.save('', function () { layer.close(idx); }); return false; }
    });
  }

  /* ---- add dialog ---- */
  function regAddDialog() {
    var r = S.regMeta, sel = {}, sites = {}, tabs = [], cur = 'all';
    var by = {};
    S.regAll.forEach(function (x) { by[x.code] = x; });
    var seen = {};
    var groups = CONTINENTS.map(function (c) {
      var list = c[2].split(' ').filter(function (k) { seen[k] = 1; return by[k]; });
      return { code: c[0], name: c[1], list: list };
    });
    var other = S.regAll.map(function (x) { return x.code; }).filter(function (k) { return !seen[k]; });
    if (other.length) groups.push({ code: 'XX', name: 'Other', list: other });

    var h = '<div class="wp-g-dlg wp-ra">' +
      '<div class="wp-ra-top"><span>Type</span><select class="wp-in" id="ra-type" style="width:220px">' +
      '<option value="intercept">Intercept</option><option value="pass">Pass</option></select>' +
      '<span style="margin-left:20px">Website</span><div class="wp-ms" id="ra-sites"><div class="wp-ms-box"></div>' +
      '<div class="wp-ms-drop"></div></div></div>' +
      '<div class="wp-ra-sel"><span>Region (choose more):</span><span id="ra-chips"></span></div>' +
      '<div class="wp-ra-tabs"><div class="wp-ra-tabbar" id="ra-tabbar"></div>' +
      '<div class="wp-ra-search"><input class="wp-in" id="ra-q" placeholder="Please search..."><div class="wp-ra-ac" id="ra-ac"></div></div></div>' +
      '<div class="wp-ra-body" id="ra-body"></div>' +
      '<div id="ra-cost" class="wp-cost" style="margin-top:8px"></div></div>';

    var idx = layer.open({
      type: 1, title: 'Add Region Restriction', area: ['760px', '560px'], btn: ['Confirm', 'Cancel'],
      content: h, success: draw,
      yes: function () {
        var areas = Object.keys(sel), ss = Object.keys(sites);
        if (!ss.length) return layer.msg('Please choose Website...', { icon: 2 });
        if (!areas.length) return layer.msg('Select at least one area', { icon: 2 });
        var ld = layer.load(1);
        post('region_rule_add', {
          areas: JSON.stringify(areas), sites: JSON.stringify(ss),
          type: $('#ra-type').val(), status_code: $('#ra-type').val() === 'pass' ? 444 : 403
        }, function (rr) {
          layer.close(ld);
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) { layer.close(idx); route(); }
        });
      }
    });

    function tag(code, label, on, cls) {
      return '<span class="wp-ra-tag' + (on ? ' on' : '') + (cls ? ' ' + cls : '') + '" data-c="' + code + '">' + esc(label) + '</span>';
    }
    function name(k) { return (by[k] && by[k].name) || k; }
    function drawSites() {
      var all = ['*'].concat(r.sites || []), keys = Object.keys(sites);
      $('#ra-sites .wp-ms-box').html(keys.length ? keys.map(function (k) {
        return '<span class="wp-chip2"><b>' + esc(k === '*' ? 'All websites' : k) + '</b><i data-s="' + esc(k) + '">&times;</i></span>';
      }).join('') : '<span class="ph">Please choose Website...</span>');
      $('#ra-sites .wp-ms-drop').html(all.map(function (k) {
        return '<div class="wp-ms-opt' + (sites[k] ? ' on' : '') + '" data-s="' + esc(k) + '">' +
          esc(k === '*' ? 'All websites' : k) + '</div>';
      }).join(''));
    }
    function drawBody() {
      var g;
      $('#ra-tabbar').html('<span class="' + (cur === 'all' ? 'on' : '') + '" data-t="all">All</span>' + tabs.map(function (t) {
        g = groups.filter(function (x) { return x.code === t; })[0];
        return '<span class="' + (cur === t ? 'on' : '') + '" data-t="' + t + '">' + esc(g.name) + '</span>';
      }).join(''));
      if (cur === 'all') {
        $('#ra-body').html('<div class="wp-ra-t">Hot area</div><div class="wp-ra-grid">' +
          HOT.filter(function (k) { return by[k]; }).map(function (k) { return tag(k, name(k), sel[k]); }).join('') + '</div>' +
          '<div class="wp-ra-t">Other regions</div><div class="wp-ra-grid">' + groups.map(function (x) {
            var n = x.list.filter(function (k) { return sel[k]; }).length;
            return '<span class="wp-ra-tag cont" data-g="' + x.code + '">' + esc(x.name) +
              (n ? '<em>' + n + '</em>' : '') + '</span>';
          }).join('') + '</div>');
      } else {
        g = groups.filter(function (x) { return x.code === cur; })[0];
        var list = g.list.slice().sort(function (a, b) { return name(a) < name(b) ? -1 : 1; });
        $('#ra-body').html('<div class="wp-ra-t">' + esc(g.name) + ' <span class="wp-lnk" id="ra-gall" style="font-weight:400;margin-left:8px">Select all</span>' +
          '<span class="wp-lnk" id="ra-gnone" style="font-weight:400;margin-left:8px">Clear</span></div>' +
          '<div class="wp-ra-grid">' + list.map(function (k) { return tag(k, name(k), sel[k]); }).join('') + '</div>');
      }
    }
    function drawChips() {
      var keys = Object.keys(sel);
      $('#ra-chips').html(keys.map(function (k) {
        return '<span class="wp-ra-chip">' + esc(name(k)) + '<i data-c="' + k + '">&times;</i></span>';
      }).join(''));
      var cidr = keys.reduce(function (a, k) { return a + ((by[k] && by[k].cidr) || 0); }, 0);
      var warn = cidr > REG_WARN_CIDR;
      $('#ra-cost').attr('class', 'wp-cost' + (warn ? ' warn' : ''))
        .html(keys.length ? ('<b>' + keys.length + '</b> selected · <b>' + num(cidr) + '</b> CIDR' +
          (warn ? ' — large list, compiles slower' : '')) : '');
    }
    function draw() { drawSites(); drawBody(); drawChips(); }
    function toggle(k) { if (sel[k]) delete sel[k]; else sel[k] = 1; drawBody(); drawChips(); }

    $(document).off('.wpra');
    $('#ra-sites .wp-ms-box').on('click', function (e) {
      if ($(e.target).is('i')) {
        delete sites[$(e.target).data('s')]; drawSites(); return;
      }
      $('#ra-sites').toggleClass('open');
    });
    $('#ra-sites').on('click', '.wp-ms-opt', function () {
      var k = String($(this).data('s'));
      if (sites[k]) delete sites[k];
      else if (k === '*') sites = { '*': 1 };   // all websites replaces the list
      else { delete sites['*']; sites[k] = 1; }
      drawSites();
    });
    $(document).on('mousedown.wpra', function (e) {
      if (!$(e.target).closest('#ra-sites').length) $('#ra-sites').removeClass('open');
      if (!$(e.target).closest('.wp-ra-search').length) $('#ra-ac').hide();
    });
    $('#ra-tabbar').on('click', 'span', function () {
      cur = $(this).data('t');
      if (cur === 'all') tabs = [];      // back to All closes the opened continents
      drawBody();
    });
    $('#ra-body').on('click', '.wp-ra-tag', function () {
      var g = $(this).data('g');
      if (g) {
        if (tabs.indexOf(g) === -1) tabs.push(g);
        cur = g; drawBody(); return;
      }
      toggle($(this).data('c'));
    });
    $('#ra-body').on('click', '#ra-gall,#ra-gnone', function () {
      var on = this.id === 'ra-gall';
      groups.filter(function (x) { return x.code === cur; })[0].list.forEach(function (k) {
        if (on) sel[k] = 1; else delete sel[k];
      });
      drawBody(); drawChips();
    });
    $('#ra-chips').on('click', 'i', function () { toggle($(this).data('c')); });
    $('#ra-q').on('input', function () {
      var q = ($(this).val() || '').trim().toLowerCase();
      if (!q) { $('#ra-ac').hide(); return; }
      var hits = S.regAll.filter(function (x) {
        return x.name.toLowerCase().indexOf(q) !== -1 || x.code.toLowerCase() === q;
      }).slice(0, 11);
      $('#ra-ac').html(hits.length ? hits.map(function (x) {
        return '<div data-c="' + x.code + '">' + esc(x.name) + ' <span>(' + x.code + ')</span></div>';
      }).join('') : '<div class="none">No match</div>').show();
    });
    $('#ra-ac').on('click', 'div[data-c]', function () {
      var k = $(this).data('c');
      sel[k] = 1;
      $('#ra-q').val(''); $('#ra-ac').hide();
      drawBody(); drawChips();
    });
  }

  /* Status code select used by Global's response dialogs */
  var STATUS_OPTS = [
    { code: 444, name: '444 Close connection' },
    { code: 403, name: '403 Access denied' },
    { code: 404, name: '404 File not exist' },
    { code: 503, name: '503 Server unavailable' },
    { code: 405, name: '405 Method not allowed' }
  ];
  function statusSel(id, val) {
    return '<select class="wp-in" id="' + id + '" style="width:200px">' + STATUS_OPTS.map(function (s) {
      return '<option value="' + s.code + '"' + (s.code === val ? ' selected' : '') + '>' + s.name + '</option>';
    }).join('') + '</select>';
  }

  // exports
  W.REG_WARN_CIDR = REG_WARN_CIDR;
  W.STATUS_OPTS = STATUS_OPTS;
  W.htmlEditDialog = htmlEditDialog;
  W.pageRegion = pageRegion;
  W.regAddDialog = regAddDialog;
  W.renderRegion = renderRegion;
  W.statusSel = statusSel;
})(window.WAFPRO = window.WAFPRO || {});
