(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function icoWarn() { return W.icoWarn.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }
  function row() { return W.row.apply(this, arguments); }

  /* ================= LOGS ================= */

  /* ================= GLOBAL ================= */
  /* ================= REGION (standalone engine) =================
     One rule per row, each with its own areas, type and status code — our own
     engine backs this, so rows are genuinely independent. */

  // Above this the picker warns: the engine binary-searches the ranges, but the
  // panel still compiles and writes them (the US alone is ~43k ranges).
  var REG_WARN_CIDR = 20000;

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

  function renderRegion(r) {
    var e = r.engine || {};
    var h = '';
    if (!e.wired) {
      h += '<div class="wp-note" style="margin-bottom:12px">' + icoWarn() +
        ' The WAF Pro engine is not wired into nginx yet, so these rules are stored but <b>not enforced</b>.' +
        (e.free_waf_active ? ' The free WAF is currently handling traffic; only one lua engine can be active at a time.' : '') +
        '</div>';
    }
    h += '<div class="wp-card">';
    h += '<div style="margin-bottom:14px"><span class="wp-btn primary" id="rg-add">Add Region Restriction</span></div>';
    h += '<table class="wp-table" style="width:100%;border-collapse:collapse">' +
      '<thead><tr>' +
      ['Area', 'Status', 'Status code', 'Website', 'Type', 'Operate'].map(function (t, i) {
        return '<th style="text-align:' + (i === 5 ? 'right' : 'left') + ';padding:10px 8px;color:var(--wp-text2);' +
          'font-weight:400;border-bottom:1px solid var(--wp-border)">' + t + '</th>';
      }).join('') + '</tr></thead><tbody>';
    if (!r.rules.length) {
      h += '<tr><td colspan="6" style="padding:26px;text-align:center;color:var(--wp-text3)">No region restriction yet.</td></tr>';
    } else {
      h += r.rules.map(function (x) {
        var opts = (r.status_codes || []).map(function (s) {
          return '<option value="' + s.code + '"' + (s.code === x.status ? ' selected' : '') + '>' + esc(s.name) + '</option>';
        }).join('');
        return '<tr data-id="' + x.id + '" style="border-bottom:1px solid var(--wp-border)">' +
          '<td style="padding:9px 8px">' + esc(x.area_text) +
            '<div style="color:var(--wp-text3);font-size:12px">' + num(x.ranges) + ' ranges</div></td>' +
          '<td style="padding:9px 8px"><label class="wp-sw"><input type="checkbox" class="rg-on"' +
            (x.open ? ' checked' : '') + '><span class="sl"></span></label></td>' +
          '<td style="padding:9px 8px"><select class="wp-in rg-code" style="width:210px">' + opts + '</select></td>' +
          '<td style="padding:9px 8px">' + esc(x.site) + '</td>' +
          '<td style="padding:9px 8px">' + (x.type === 'pass' ? 'Pass' : 'Intercept') + '</td>' +
          '<td style="padding:9px 8px;text-align:right"><a href="javascript:;" class="rg-del" style="color:var(--wp-green)">Delete</a></td>' +
          '</tr>';
      }).join('');
    }
    h += '</tbody></table></div>';
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
    $('#wp-body').on('click', '.rg-del', function () {
      var id = $(this).closest('tr').data('id');
      layer.confirm('Delete this region restriction?', function (i) {
        layer.close(i);
        post('region_rule_del', { id: id }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) route();
        });
      });
    });
  }

  /* Built on the .wp-modal system (head/body/foot): layer renders the dialog
     outside #wafpro-app, so it needs .wp-modal to pick up the CSS variables,
     and the sticky foot is what keeps Add reachable without scrolling. */
  function regAddDialog() {
    var r = S.regMeta, sel = {}, q = '';

    var sites = (r.sites || []).map(function (s) {
      return '<option value="' + esc(s) + '">' + esc(s) + '</option>';
    }).join('');
    var codes = (r.status_codes || []).map(function (s) {
      return '<option value="' + s.code + '"' + (s.code === 444 ? ' selected' : '') + '>' + esc(s.name) + '</option>';
    }).join('');

    var h = '<div class="wp-modal">' +
      '<div class="wp-mod-head">' +
        '<div class="wp-mod-site">Add Region Restriction</div>' +
        '<div class="wp-mod-meta">Match visitors by country and decide what happens. ' +
          'Loopback and LAN addresses are always allowed.</div>' +
      '</div>' +
      '<div class="wp-mod-body">' +

        '<div class="wp-mod-sec">' +
          '<div class="wp-mod-sec-t">Scope</div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">Website</div>' +
            '<div class="wp-mod-ctl"><select class="wp-in" id="ra-site" style="min-width:250px">' + sites + '</select></div>' +
            '<div class="wp-mod-hint">The rule applies to this site only.</div></div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">Response</div>' +
            '<div class="wp-mod-ctl"><select class="wp-in" id="ra-code" style="min-width:250px">' + codes + '</select></div>' +
            '<div class="wp-mod-hint">What blocked visitors receive.</div></div>' +
        '</div>' +

        '<div class="wp-mod-sec">' +
          '<div class="wp-mod-sec-t">Type</div>' +
          '<div class="wp-seg">' +
            '<label id="ra-t-i" class="on"><input type="radio" name="ra-type" value="intercept" checked>' +
              '<span class="t"><span class="dot"></span>Intercept</span>' +
              '<div class="d">Block the selected areas. Everyone else gets through.</div></label>' +
            '<label id="ra-t-p"><input type="radio" name="ra-type" value="pass">' +
              '<span class="t"><span class="dot"></span>Pass</span>' +
              '<div class="d">Allow only the selected areas. Everyone else is blocked.</div></label>' +
          '</div>' +
        '</div>' +

        '<div class="wp-mod-sec">' +
          '<div class="wp-mod-sec-t">Area</div>' +
          '<div class="wp-pick">' +
            '<div class="wp-pick-bar">' +
              '<input class="wp-in" id="ra-q" placeholder="Search country or ISO code">' +
              '<span class="wp-link" id="ra-all">Select all</span>' +
              '<span class="wp-link" id="ra-none">Clear</span>' +
            '</div>' +
            '<div class="wp-pick-list" id="ra-list"></div>' +
            '<div class="wp-chips" id="ra-chips"></div>' +
          '</div>' +
        '</div>' +

      '</div>' +
      '<div class="wp-mod-foot">' +
        '<div id="ra-cost" class="wp-cost" style="margin-right:auto;align-self:center"></div>' +
        '<span class="wp-btn" id="ra-cancel">Cancel</span>' +
        '<span class="wp-btn primary" id="ra-ok">Add rule</span>' +
      '</div>' +
      '</div>';

    var idx = layer.open({
      type: 1, title: false, closeBtn: 1, shadeClose: true,
      area: ['720px', '620px'], content: h
    });

    function shown() {
      return S.regAll.filter(function (x) {
        return !q || x.name.toLowerCase().indexOf(q) >= 0 || x.code.toLowerCase().indexOf(q) >= 0;
      });
    }
    function drawList() {
      var rows = shown();
      $('#ra-list').html(rows.length ? rows.map(function (x) {
        return '<label class="wp-ctry' + (sel[x.code] ? ' on' : '') + '" data-c="' + x.code + '">' +
          '<input type="checkbox" class="ra-c" data-c="' + x.code + '"' + (sel[x.code] ? ' checked' : '') + '>' +
          '<span class="n">' + esc(x.name) + ' <span class="c">(' + x.code + ')</span></span>' +
          '<span class="k">' + num(x.cidr) + '</span></label>';
      }).join('') : '<div style="padding:26px;text-align:center;color:var(--wp-text3)">No match for "' + esc(q) + '"</div>');
    }
    function drawChips() {
      var keys = Object.keys(sel);
      if (!keys.length) {
        $('#ra-chips').html('<span style="color:var(--wp-text3);font-size:12px">No area selected yet</span>');
      } else {
        var by = {};
        S.regAll.forEach(function (x) { by[x.code] = x; });
        $('#ra-chips').html(keys.map(function (c) {
          return '<span class="wp-chip2"><b>' + esc((by[c] && by[c].name) || c) + '</b>' +
            '<i class="ra-x" data-c="' + c + '">&times;</i></span>';
        }).join(''));
      }
      var cidr = S.regAll.reduce(function (a, x) { return a + (sel[x.code] ? x.cidr : 0); }, 0);
      var warn = cidr > REG_WARN_CIDR;
      // The engine binary-searches these ranges, but the panel still has to
      // compile and ship them — worth showing before someone picks the US.
      $('#ra-cost').attr('class', 'wp-cost' + (warn ? ' warn' : ''))
        .html(keys.length ? ('<b>' + keys.length + '</b> selected · <b>' + num(cidr) + '</b> CIDR' +
          (warn ? ' — large list, compiles slower' : '')) : '');
    }
    function draw() { drawList(); drawChips(); }
    draw();

    $('#ra-q').on('input', function () { q = ($(this).val() || '').toLowerCase(); drawList(); });
    $('#ra-list').on('change', '.ra-c', function () {
      var c = $(this).data('c');
      if (this.checked) sel[c] = 1; else delete sel[c];
      $(this).closest('.wp-ctry').toggleClass('on', this.checked);
      drawChips();
    });
    $('#ra-chips').on('click', '.ra-x', function () {
      delete sel[$(this).data('c')];
      draw();
    });
    $('#ra-all').on('click', function () {
      shown().forEach(function (x) { sel[x.code] = 1; });   // only what the filter shows
      draw();
    });
    $('#ra-none').on('click', function () { sel = {}; draw(); });
    $('.wp-seg input').on('change', function () {
      $('.wp-seg label').removeClass('on');
      $(this).closest('label').addClass('on');
    });
    $('#ra-cancel').on('click', function () { layer.close(idx); });
    $('#ra-ok').on('click', function () {
      var areas = Object.keys(sel);
      if (!areas.length) return layer.msg('Select at least one area', { icon: 2 });
      var $b = $(this);
      if ($b.data('busy')) return;
      $b.data('busy', 1).text('Adding...');
      post('region_rule_add', {
        areas: JSON.stringify(areas), site: $('#ra-site').val(),
        type: $('.wp-seg input:checked').val(), status_code: $('#ra-code').val()
      }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        if (rr.status) { layer.close(idx); route(); }
        else $b.data('busy', 0).text('Add rule');
      });
    });
  }
  /* Global = engine-wide settings only. The per-filter switches (GET/POST/
     cookie/UA/scan/CC) are per site and live on the WebSite tab. */
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
  W.pageRegion = pageRegion;
  W.regAddDialog = regAddDialog;
  W.renderRegion = renderRegion;
  W.statusSel = statusSel;
})(window.WAFPRO = window.WAFPRO || {});
