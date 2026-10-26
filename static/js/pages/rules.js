(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function icoWarn() { return W.icoWarn.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }
  function row() { return W.row.apply(this, arguments); }

  /* ================= CUSTOM RULES ================= */
  /* ================= CUSTOM RULES =================
     User-defined multi-condition rules. Each rule is a set of AND-conditions;
     if all match, the action fires. Evaluated before the built-in filters, so
     an allow rule whitelists and a block rule pre-empts them. */
  var CR_FIELDS = [
    { v: 'ip', t: 'IP range', kind: 'ipset' },
    { v: 'country', t: 'Country', kind: 'country' },
    { v: 'method', t: 'Method', kind: 'text' },
    { v: 'uri', t: 'URI (path)', kind: 'text' },
    { v: 'uri_args', t: 'URI (with parameters)', kind: 'text' },
    { v: 'uri_param', t: 'URI parameter', kind: 'named' },
    { v: 'args', t: 'Query string', kind: 'text' },
    { v: 'user_agent', t: 'User-Agent', kind: 'text' },
    { v: 'referer', t: 'Referer', kind: 'text' },
    { v: 'cookie', t: 'Cookie', kind: 'text' },
    { v: 'header', t: 'Request header', kind: 'named' }
  ];
  var CR_TEXT_OPS = [
    { v: 'eq', t: 'equals' }, { v: 'ne', t: 'does not equal' },
    { v: 'contains', t: 'contains' }, { v: 'ncontains', t: 'does not contain' },
    { v: 'prefix', t: 'starts with' }, { v: 'suffix', t: 'ends with' },
    { v: 'regex', t: 'matches regex' }, { v: 'in', t: 'is one of (comma list)' },
    { v: 'exists', t: 'exists' }, { v: 'nexists', t: 'is absent' }
  ];
  var CR_SET_OPS = [{ v: 'match', t: 'is in' }, { v: 'notmatch', t: 'is not in' }];
  var CR_STATUS = [
    { code: 403, name: '403 Access denied' }, { code: 444, name: '444 Close connection' },
    { code: 404, name: '404 Not found' }, { code: 502, name: '502 Bad gateway' },
    { code: 503, name: '503 Service unavailable' }
  ];
  function crFieldOf(v) { return CR_FIELDS.filter(function (x) { return x.v === v; })[0] || CR_FIELDS[0]; }
  function crFieldName(v) { return crFieldOf(v).t; }
  function crRuleSummary(r) {
    // the paid UI lists the fields a rule matches on
    var seen = {}, out = [];
    (r.conds || []).forEach(function (c) { if (!seen[c.field]) { seen[c.field] = 1; out.push(crFieldName(c.field)); } });
    return out.join(', ');
  }
  function crActionText(r) {
    if (r.action === 'allow') return 'Allow (whitelist)';
    if (r.action === 'block') return 'Intercept (default blocked page)';
    return 'Intercept (' + r.status + ' response)';
  }

  function pageRules() {
    $('#wp-body').html('<div class="wp-loading">Loading...</div>');
    post('custom_rules', {}, function (r) {
      if (!r.status) { $('#wp-body').html('<div class="wp-note">' + esc(r.msg || 'error') + '</div>'); return; }
      S.crMeta = r;
      renderCustom(r);
    });
  }

  function renderCustom(r) {
    var e = r.engine || {};
    var h = '';
    if (!e.wired) {
      h += '<div class="wp-note" style="margin-bottom:12px">' + icoWarn() +
        ' The engine is not wired into nginx, so these rules are stored but not enforced.</div>';
    }
    h += '<div class="wp-card">';
    h += '<div style="margin-bottom:14px"><span class="wp-btn primary" id="cr-add">Add custom interception</span></div>';
    h += '<table class="wp-tbl"><thead><tr>' +
      '<th style="width:140px">Rule name</th>' +
      '<th style="width:160px">Website name</th>' +
      '<th style="width:90px">Status</th>' +
      '<th style="width:60px">Hits</th>' +
      '<th>Rule</th>' +
      '<th style="width:230px">Action</th>' +
      '<th style="width:140px">Operate</th></tr></thead><tbody>';
    if (!r.rules.length) {
      h += '<tr><td colspan="7" style="padding:26px;text-align:center;color:var(--wp-text3)">No custom rule yet.</td></tr>';
    } else {
      h += r.rules.map(function (x) {
        return '<tr data-id="' + x.id + '">' +
          '<td style="color:var(--wp-text);font-weight:600">' + esc(x.name) + '</td>' +
          '<td class="ell" title="' + esc(x.site) + '">' + esc(x.site) + '</td>' +
          '<td><span class="cr-st" style="cursor:pointer;color:' + (x.open ? 'var(--wp-green)' : 'var(--wp-text3)') + '">' +
            (x.open ? 'Running &#9654;' : 'Stopped &#9632;') + '</span></td>' +
          '<td style="color:' + (x.hits ? 'var(--wp-red)' : 'var(--wp-text3)') + ';font-weight:600">' + num(x.hits) + '</td>' +
          '<td style="color:var(--wp-text2)">' + esc(crRuleSummary(x)) + '</td>' +
          '<td>' + esc(crActionText(x)) + '</td>' +
          '<td>' +
            '<a href="javascript:;" class="cr-copy" style="color:var(--wp-green)">Copy</a> <span style="color:var(--wp-border)">|</span> ' +
            '<a href="javascript:;" class="cr-edit" style="color:var(--wp-green)">Edit</a> <span style="color:var(--wp-border)">|</span> ' +
            '<a href="javascript:;" class="cr-del" style="color:var(--wp-green)">Delete</a></td></tr>';
      }).join('');
    }
    h += '</tbody></table>';
    h += '<ul class="wp-notes">' +
      '<li>Custom rules run before the built-in filters: an <b>allow</b> rule whitelists the request, a <b>block</b> rule stops it early.</li>' +
      '<li>All conditions in a rule must match (AND). Loopback and LAN traffic is never touched.</li>' +
      '</ul>';
    h += '</div>';
    $('#wp-body').html(h);

    $('#cr-add').on('click', function () { crDialog(null); });
    $('#wp-body').on('click', '.cr-edit', function () {
      var id = $(this).closest('tr').data('id');
      crDialog(r.rules.filter(function (x) { return x.id === id; })[0]);
    });
    $('#wp-body').on('click', '.cr-copy', function () {
      var id = $(this).closest('tr').data('id');
      post('custom_copy', { id: id }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        if (rr.status) route();
      });
    });
    $('#wp-body').on('click', '.cr-st', function () {
      var tr = $(this).closest('tr'), id = tr.data('id');
      var rule = r.rules.filter(function (x) { return x.id === id; })[0];
      post('custom_toggle', { id: id, open: rule.open ? 0 : 1 }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        if (rr.status) route();
      });
    });
    $('#wp-body').on('click', '.cr-del', function () {
      var id = $(this).closest('tr').data('id');
      W.confirm('Delete this custom rule?', function (i) {
        layer.close(i);
        post('custom_del', { id: id }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) route();
        });
      });
    });
  }

  // one condition row inside the dialog
  function crCondRow(c) {
    c = c || { field: 'uri', op: 'contains', extra: '', value: '' };
    var fopts = CR_FIELDS.map(function (f) {
      return '<option value="' + f.v + '"' + (f.v === c.field ? ' selected' : '') + '>' + f.t + '</option>';
    }).join('');
    return '<div class="cr-cond" style="display:flex;gap:6px;align-items:flex-start;margin-bottom:8px;flex-wrap:wrap">' +
      '<select class="wp-in cr-c-field" style="width:150px">' + fopts + '</select>' +
      '<input class="wp-in cr-c-extra" placeholder="name" style="width:110px" value="' + esc(c.extra || '') + '">' +
      '<select class="wp-in cr-c-op" style="width:150px"></select>' +
      '<input class="wp-in cr-c-value" placeholder="value" style="flex:1;min-width:140px" value="' + esc(c.value || '') + '">' +
      '<span class="wp-btn cr-c-del" style="padding:6px 10px">&times;</span></div>';
  }
  // sync a condition row's op list + which inputs show, from its field
  function crSyncRow($row, presetOp) {
    var f = crFieldOf($row.find('.cr-c-field').val());
    var ops = (f.kind === 'ipset' || f.kind === 'country') ? CR_SET_OPS : CR_TEXT_OPS;
    $row.find('.cr-c-op').html(ops.map(function (o) {
      return '<option value="' + o.v + '"' + (o.v === presetOp ? ' selected' : '') + '>' + o.t + '</option>';
    }).join(''));
    $row.find('.cr-c-extra').css('display', f.kind === 'named' ? '' : 'none')
      .attr('placeholder', f.v === 'header' ? 'header name' : 'param name');
    var op = $row.find('.cr-c-op').val();
    var noVal = (op === 'exists' || op === 'nexists');
    $row.find('.cr-c-value').css('display', noVal ? 'none' : '')
      .attr('placeholder', (f.kind === 'ipset') ? '1.2.3.0/24, 5.5.5.5'
        : (f.kind === 'country') ? 'TR, US, DE' : 'value');
  }

  function crDialog(rule) {
    var r = S.crMeta, edit = !!rule;
    rule = rule || { name: '', site: '', action: 'block', status: 403,
                     conds: [{ field: 'uri', op: 'contains', extra: '', value: '' }] };
    var sites = (r.sites || []).map(function (s) {
      return '<option value="' + esc(s) + '"' + (s === rule.site ? ' selected' : '') + '>' + esc(s) + '</option>';
    }).join('');
    var codes = CR_STATUS.map(function (s) {
      return '<option value="' + s.code + '"' + (s.code === rule.status ? ' selected' : '') + '>' + s.name + '</option>';
    }).join('');

    var h = '<div class="wp-modal">' +
      '<div class="wp-mod-head">' +
        '<div class="wp-mod-site">' + (edit ? 'Edit' : 'Add') + ' custom interception</div>' +
        '<div class="wp-mod-meta">All conditions must match for the action to fire.</div>' +
      '</div>' +
      '<div class="wp-mod-body">' +
        '<div class="wp-mod-sec"><div class="wp-mod-sec-t">Rule</div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">Rule name</div>' +
            '<div class="wp-mod-ctl"><input class="wp-in" id="cr-name" style="min-width:250px" value="' + esc(rule.name) + '" placeholder="e.g. block_admin"></div>' +
            '<div class="wp-mod-hint"></div></div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">Website</div>' +
            '<div class="wp-mod-ctl"><select class="wp-in" id="cr-site" style="min-width:250px">' + sites + '</select></div>' +
            '<div class="wp-mod-hint"></div></div>' +
        '</div>' +
        '<div class="wp-mod-sec"><div class="wp-mod-sec-t">Conditions <span style="text-transform:none;font-weight:400;color:var(--wp-text3)">(all must match)</span></div>' +
          '<div id="cr-conds"></div>' +
          '<span class="wp-btn" id="cr-add-cond" style="margin-top:4px">+ Add condition</span>' +
        '</div>' +
        '<div class="wp-mod-sec"><div class="wp-mod-sec-t">Action</div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">When matched</div>' +
            '<div class="wp-mod-ctl"><select class="wp-in" id="cr-action" style="min-width:250px">' +
              '<option value="block"' + (rule.action === 'block' ? ' selected' : '') + '>Intercept — default blocked page</option>' +
              '<option value="code"' + (rule.action === 'code' ? ' selected' : '') + '>Intercept — custom status code</option>' +
              '<option value="allow"' + (rule.action === 'allow' ? ' selected' : '') + '>Allow — whitelist, skip all checks</option>' +
            '</select></div>' +
            '<div class="wp-mod-hint"></div></div>' +
          '<div class="wp-mod-row" id="cr-code-row"><div class="wp-mod-lbl">Status code</div>' +
            '<div class="wp-mod-ctl"><select class="wp-in" id="cr-code" style="min-width:250px">' + codes + '</select></div>' +
            '<div class="wp-mod-hint"></div></div>' +
        '</div>' +
      '</div>' +
      '<div class="wp-mod-foot">' +
        '<span class="wp-btn" id="cr-cancel">Cancel</span>' +
        '<span class="wp-btn primary" id="cr-ok">' + (edit ? 'Save' : 'Add') + '</span>' +
      '</div></div>';

    var idx = W.open({ type: 1, title: false, closeBtn: 1, area: ['760px', '640px'], content: h });

    function addCond(c) {
      var $row = $(crCondRow(c)).appendTo('#cr-conds');
      crSyncRow($row, c && c.op);
    }
    (rule.conds || []).forEach(addCond);
    $('#cr-add-cond').on('click', function () { addCond(null); });
    $('#cr-conds').on('change', '.cr-c-field', function () { crSyncRow($(this).closest('.cr-cond')); });
    $('#cr-conds').on('change', '.cr-c-op', function () { crSyncRow($(this).closest('.cr-cond'), $(this).val()); });
    $('#cr-conds').on('click', '.cr-c-del', function () {
      if ($('.cr-cond').length > 1) $(this).closest('.cr-cond').remove();
      else layer.msg('A rule needs at least one condition', { icon: 0 });
    });

    function syncCode() { $('#cr-code-row').css('display', $('#cr-action').val() === 'code' ? '' : 'none'); }
    syncCode();
    $('#cr-action').on('change', syncCode);
    $('#cr-cancel').on('click', function () { layer.close(idx); });
    $('#cr-ok').on('click', function () {
      var conds = [];
      $('.cr-cond').each(function () {
        var $r = $(this);
        conds.push({ field: $r.find('.cr-c-field').val(), op: $r.find('.cr-c-op').val(),
                     extra: $r.find('.cr-c-extra').val(), value: $r.find('.cr-c-value').val() });
      });
      // rname/act, not name/action: the panel's router owns those two keys
      // (posting them is what produced "Specific parameters are invalid!")
      var payload = { rname: $('#cr-name').val(), site: $('#cr-site').val(),
                      act: $('#cr-action').val(), status_code: $('#cr-code').val(),
                      conds: JSON.stringify(conds) };
      if (edit) payload.id = rule.id;
      post(edit ? 'custom_edit' : 'custom_add', payload, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        if (rr.status) { layer.close(idx); route(); }
      });
    });
  }


  // exports
  W.CR_FIELDS = CR_FIELDS;
  W.CR_SET_OPS = CR_SET_OPS;
  W.CR_STATUS = CR_STATUS;
  W.CR_TEXT_OPS = CR_TEXT_OPS;
  W.crActionText = crActionText;
  W.crCondRow = crCondRow;
  W.crDialog = crDialog;
  W.crFieldName = crFieldName;
  W.crFieldOf = crFieldOf;
  W.crRuleSummary = crRuleSummary;
  W.crSyncRow = crSyncRow;
  W.pageRules = pageRules;
  W.renderCustom = renderCustom;
})(window.WAFPRO = window.WAFPRO || {});
