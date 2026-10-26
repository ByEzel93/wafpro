(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function icoWarn() { return W.icoWarn.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }

  /* ================= CUSTOM RULES (aaPanel 8 layout) =================
     A rule is OR-groups of AND-conditions ("And" adds a row to the group,
     "Or" starts a new group), applied to some or all websites. Evaluated
     right after the IP/UA/URL white- and blacklists. */
  var CR_FIELDS = [
    { v: 'ip', t: 'IP address', kind: 'ipset', ph: '1.2.3.0/24, 5.5.5.5' },
    { v: 'country', t: 'IP region', kind: 'country', ph: 'TR, US, DE' },
    { v: 'method', t: 'Request method', kind: 'text', ph: 'POST' },
    { v: 'uri', t: 'URI (without parameters)', kind: 'text', ph: '/admin' },
    { v: 'uri_args', t: 'URI (with parameters)', kind: 'text', ph: '/index.php?s=1' },
    { v: 'uri_param', t: 'URI parameter', kind: 'named', ph: 'value' },
    { v: 'args', t: 'Query string', kind: 'text', ph: 'id=1' },
    { v: 'user_agent', t: 'User-Agent', kind: 'text', ph: 'python-requests' },
    { v: 'referer', t: 'Referer', kind: 'text', ph: 'https://example.com' },
    { v: 'cookie', t: 'Cookie', kind: 'text', ph: 'session=' },
    { v: 'header', t: 'Request header', kind: 'named', ph: 'value' }
  ];
  var CR_TEXT_OPS = [
    { v: 'eq', t: 'Equal to' }, { v: 'ne', t: 'Not equal to' },
    { v: 'contains', t: 'Contains' }, { v: 'ncontains', t: 'Does not contain' },
    { v: 'prefix', t: 'Starts with' }, { v: 'suffix', t: 'Ends with' },
    { v: 'regex', t: 'Regular match' }, { v: 'in', t: 'In list (comma)' },
    { v: 'exists', t: 'Exists' }, { v: 'nexists', t: 'Does not exist' }
  ];
  var CR_SET_OPS = [{ v: 'match', t: 'Belongs to' }, { v: 'notmatch', t: 'Does not belong to' }];
  // Operation Options -> Response page / Verification method
  var CR_RESP = [
    ['block', 'Default blocked page'], ['code:403', '403 Access denied'], ['code:404', '404 File not exist'],
    ['code:444', '444 Close connection'], ['code:502', '502 Bad gateway'], ['code:503', '503 Service unavailable']
  ];
  var CR_STATUS = [403, 404, 444, 502, 503];
  function crFieldOf(v) { return CR_FIELDS.filter(function (x) { return x.v === v; })[0] || CR_FIELDS[0]; }
  function crFieldName(v) { return crFieldOf(v).t; }
  function opName(v) {
    var o = CR_TEXT_OPS.concat(CR_SET_OPS).filter(function (x) { return x.v === v; })[0];
    return o ? o.t : v;
  }
  // "URI (without parameters) Contains /admin And ..." with Or between groups
  function crRuleSummary(r) {
    var groups = {}, order = [];
    (r.conds || []).forEach(function (c) {
      var g = c.g || 0;
      if (!groups[g]) { groups[g] = []; order.push(g); }
      groups[g].push(crFieldName(c.field) + (c.extra ? ' [' + c.extra + ']' : '') + ' ' + opName(c.op) +
        (c.op === 'exists' || c.op === 'nexists' ? '' : ' ' + c.value));
    });
    return order.map(function (g) { return groups[g].join(' And '); }).join(' Or ');
  }
  function crActionText(r) {
    if (r.action === 'allow') return 'Release';
    if (r.action === 'verify') return 'Verification (Browser verification)';
    if (r.action === 'block') return 'Intercept (Default blocked page)';
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
    h += '<div class="wp-card"><div class="wp-bl-bar" style="margin-bottom:14px">' +
      '<span class="wp-btn primary" id="cr-add">Add custom interception</span></div>';
    h += '<div class="wp-site-box"><table class="wp-site-tbl"><thead><tr>' +
      '<th>Rule name</th><th style="width:20%">Website name</th><th style="width:8%">Status</th><th style="width:8%">Hits</th>' +
      '<th style="width:22%">Rule</th><th style="width:18%">Action</th><th class="r" style="width:140px">Operate</th>' +
      '</tr></thead><tbody>';
    h += r.rules.length ? r.rules.map(function (x) {
      var sum = crRuleSummary(x);
      return '<tr data-id="' + esc(x.id) + '"><td class="ell" title="' + esc(x.name) + '">' + esc(x.name) + '</td>' +
        '<td class="ell" style="max-width:260px">' + esc((x.sites || [x.site]).map(function (s) {
          return s === '*' ? 'All websites' : s; }).join(', ')) + '</td>' +
        '<td><label class="wp-sw wp-sw-sm"><input type="checkbox" class="cr-on"' + (x.open ? ' checked' : '') + '><span class="sl"></span></label></td>' +
        '<td><span class="wp-tag' + (x.hits ? ' ok' : '') + '">' + (x.hits || 0) + '</span></td>' +
        '<td class="ell" style="max-width:260px" title="' + esc(sum) + '">' + esc(sum) + '</td>' +
        '<td class="ell">' + esc(crActionText(x)) + '</td>' +
        '<td class="wp-ops"><span class="wp-lnk cr-copy">Copy</span><span class="wp-ops-sep">|</span>' +
        '<span class="wp-lnk cr-edit">Edit</span><span class="wp-ops-sep">|</span><span class="wp-lnk cr-del">Delete</span></td></tr>';
    }).join('') : '<tr><td colspan="7" class="wp-empty">No Data</td></tr>';
    h += '</tbody></table></div>';
    h += '<ul class="wp-notes" style="margin-top:20px">' +
      '<li>Customized Priority: IP whitelist &gt; IP blacklist &gt; UA whitelist &gt; UA blacklist &gt; URL whitelist &gt; ' +
      'Customized interception &gt; URL blacklist &gt; Regional restriction &gt; CC defense and the other filters</li>' +
      '<li>If a custom intercept is prioritized ahead it will execute the preceding</li></ul></div>';
    $('#wp-body').html(h);

    function byId(el) {
      var id = $(el).closest('tr').data('id');
      return r.rules.filter(function (x) { return x.id === id; })[0];
    }
    $('#cr-add').on('click', function () { crDialog(null); });
    $('#wp-body').on('click', '.cr-edit', function () { crDialog(byId(this)); });
    $('#wp-body').on('click', '.cr-copy', function () {
      var x = byId(this);
      W.confirm('Is the rule copied and created as a new rule?', { title: 'Copy rule [' + esc(x.name) + ']' }, function (i) {
        layer.close(i);
        post('custom_copy', { id: x.id }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) route();
        });
      });
    });
    $('#wp-body').on('change', '.cr-on', function () {
      var x = byId(this), on = this.checked;
      post('custom_toggle', { id: x.id, open: on ? 1 : 0 }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        if (rr.status) x.open = on;
      });
    });
    $('#wp-body').on('click', '.cr-del', function () {
      var x = byId(this);
      W.confirm('Are you sure you want to delete this rule?', { title: 'Delete rule [' + esc(x.name) + ']' }, function (i) {
        layer.close(i);
        post('custom_del', { id: x.id }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) route();
        });
      });
    });
  }

  /* ---- rule builder rows ---- */
  function crCondRow(c) {
    c = c || { field: '', op: '', extra: '', value: '' };
    return '<div class="cr-row"><div class="field"><select class="wp-in cr-c-field">' +
      '<option value="">Please select</option>' + CR_FIELDS.map(function (f) {
        return '<option value="' + f.v + '"' + (f.v === c.field ? ' selected' : '') + '>' + f.t + '</option>';
      }).join('') + '</select></div>' +
      '<div class="condition"><input class="wp-in cr-c-extra" placeholder="Name" value="' + esc(c.extra || '') + '">' +
      '<select class="wp-in cr-c-op"' + (c.field ? '' : ' disabled') + '></select></div>' +
      '<div class="content"><input class="wp-in cr-c-value" spellcheck="false" value="' + esc(c.value || '') + '"' +
      (c.field ? '' : ' disabled') + '></div>' +
      '<div class="btns"><span class="wp-btn sm cr-and">And</span><span class="wp-btn sm cr-or">Or</span>' +
      '<span class="cr-x" title="Delete">&times;</span></div></div>';
  }
  // sync a row's operator list + inputs from its field
  function crSyncRow($row, presetOp) {
    var fv = $row.find('.cr-c-field').val();
    if (!fv) { $row.find('.cr-c-op').html('').prop('disabled', true); $row.find('.cr-c-value').prop('disabled', true); return; }
    var f = crFieldOf(fv);
    var ops = (f.kind === 'ipset' || f.kind === 'country') ? CR_SET_OPS : CR_TEXT_OPS;
    $row.find('.cr-c-op').prop('disabled', false).html(ops.map(function (o) {
      return '<option value="' + o.v + '"' + (o.v === presetOp ? ' selected' : '') + '>' + o.t + '</option>';
    }).join(''));
    $row.toggleClass('named', f.kind === 'named');
    $row.find('.cr-c-extra').attr('placeholder', f.v === 'header' ? 'Header name' : 'Parameter name');
    var op = $row.find('.cr-c-op').val();
    $row.find('.cr-c-value').prop('disabled', op === 'exists' || op === 'nexists').attr('placeholder', f.ph);
  }

  function crDialog(rule) {
    var r = S.crMeta, edit = !!rule;
    rule = rule || { name: '', sites: [], action: 'block', status: 403, conds: [] };
    var resp = rule.action === 'code' ? 'code:' + rule.status : 'block';
    var op = rule.action === 'allow' ? 'allow' : rule.action === 'verify' ? 'verify' : 'deny';

    var h = '<div class="wp-g-dlg wp-tl wp-cr">' +
      '<div class="wp-tl-t">When website</div>' +
      '<div class="wp-g-row"><div class="wp-g-rl">Apply to website</div><div class="wp-g-rc">' +
      '<div class="wp-ms" id="cr-sites" style="width:320px"><div class="wp-ms-box"></div><div class="wp-ms-drop"></div></div>' +
      '<span class="wp-btn" id="cr-copy-dom" style="margin-left:8px;height:30px">Copy domain</span></div></div>' +
      '<div class="wp-g-row"><div class="wp-g-rl">Rule name</div><div class="wp-g-rc"><input class="wp-in" id="cr-name" ' +
      'style="width:320px" spellcheck="false" placeholder="Please enter the rule name" value="' + esc(rule.name) + '"></div></div>' +
      '<div class="wp-tl-t">When matching rules</div>' +
      '<div class="cr-builder"><div class="cr-row cr-head"><div class="field">Type</div><div class="condition">Rule</div>' +
      '<div class="content">Match content</div><div class="btns"></div></div><div id="cr-groups"></div></div>' +
      '<div class="wp-tl-t">Action</div>' +
      '<div class="wp-g-row"><div class="wp-g-rl">Operation Options</div><div class="wp-g-rc">' +
      '<select class="wp-in" id="cr-op" style="width:320px"><option value="deny"' + (op === 'deny' ? ' selected' : '') + '>Intercept</option>' +
      '<option value="allow"' + (op === 'allow' ? ' selected' : '') + '>Release</option>' +
      '<option value="verify"' + (op === 'verify' ? ' selected' : '') + '>Verification</option></select></div></div>' +
      '<div class="wp-g-row" id="cr-resp-row"><div class="wp-g-rl" id="cr-resp-l">Response page</div><div class="wp-g-rc">' +
      '<select class="wp-in" id="cr-resp" style="width:320px"></select></div></div></div>';

    var getSites;
    var idx = W.open({
      type: 1, title: edit ? 'Edit custom interception rule [' + esc(rule.name) + ']' : 'Add custom interception rule',
      area: ['800px', 'auto'], btn: ['Confirm', 'Cancel'], content: h,
      success: function () {
        getSites = W.siteMS('cr-sites', r.sites || [], rule.sites || (rule.site ? [rule.site] : []));
        // conditions grouped by g, in order
        var groups = [], at = {};
        (rule.conds || []).forEach(function (c) {
          var g = c.g || 0;
          if (at[g] === undefined) { at[g] = groups.length; groups.push([]); }
          groups[at[g]].push(c);
        });
        if (!groups.length) groups.push([null]);
        groups.forEach(function (g) {
          var $g = $('<div class="cr-group"></div>').appendTo('#cr-groups');
          g.forEach(function (c) { addRow($g, null, c); });
        });
        decorate();
        syncResp();
        $('#cr-op').on('change', syncResp);
      },
      yes: function () {
        var conds = [], bad = false;
        $('#cr-groups .cr-group').each(function (gi) {
          $(this).find('.cr-row').each(function () {
            var $r = $(this), f = $r.find('.cr-c-field').val(), o = $r.find('.cr-c-op').val(), v = $r.find('.cr-c-value').val();
            if (!f || !o || (v === '' && o !== 'exists' && o !== 'nexists')) bad = true;
            conds.push({ field: f, op: o, extra: $r.find('.cr-c-extra').val(), value: v, g: gi });
          });
        });
        if (bad) { layer.msg('Please improve the matching rules', { icon: 2 }); return; }
        var o = $('#cr-op').val(), rv = $('#cr-resp').val() || 'block';
        var act = o === 'allow' ? 'allow' : o === 'verify' ? 'verify' : (rv === 'block' ? 'block' : 'code');
        // rname/act, not name/action: the panel's router owns those two keys
        var d = { rname: $('#cr-name').val() || '', sites: JSON.stringify(getSites()), act: act,
                  status_code: rv.indexOf('code:') === 0 ? rv.slice(5) : 403, conds: JSON.stringify(conds) };
        if (edit) d.id = rule.id;
        post(edit ? 'custom_edit' : 'custom_add', d, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) { layer.close(idx); route(); }
        });
      }
    });

    function syncResp() {
      var o = $('#cr-op').val();
      $('#cr-resp-row').toggle(o !== 'allow');
      $('#cr-resp-l').text(o === 'verify' ? 'Verification method' : 'Response page');
      $('#cr-resp').html(o === 'verify' ? '<option value="block">Browser verification</option>' : CR_RESP.map(function (x) {
        return '<option value="' + x[0] + '"' + (x[0] === resp ? ' selected' : '') + '>' + x[1] + '</option>';
      }).join(''));
    }
    function addRow($g, $after, c) {
      var $row = $(crCondRow(c));
      if ($after) $row.insertAfter($after); else $row.appendTo($g);
      crSyncRow($row, c && c.op);
    }
    // And / Or separators, the Or button only on the very last row,
    // and no delete when only one row is left
    function decorate() {
      $('#cr-groups .cr-sep').remove();
      $('#cr-groups .cr-group').each(function (gi) {
        if (gi) $(this).before('<div class="cr-sep or"><span>Or</span></div>');
        $(this).find('.cr-row').each(function (ri) {
          if (ri) $(this).before('<div class="cr-sep and"><span>And</span></div>');
        });
      });
      var rows = $('#cr-groups .cr-row');
      rows.find('.cr-or').hide(); rows.last().find('.cr-or').show();
      rows.find('.cr-x').toggle(rows.length > 1);
    }
    $('#cr-groups').on('change', '.cr-c-field', function () { crSyncRow($(this).closest('.cr-row')); });
    $('#cr-groups').on('change', '.cr-c-op', function () { crSyncRow($(this).closest('.cr-row'), $(this).val()); });
    $('#cr-groups').on('click', '.cr-and', function () {
      var $row = $(this).closest('.cr-row');
      addRow($row.closest('.cr-group'), $row, null); decorate();
    });
    $('#cr-groups').on('click', '.cr-or', function () {
      addRow($('<div class="cr-group"></div>').appendTo('#cr-groups'), null, null); decorate();
    });
    $('#cr-groups').on('click', '.cr-x', function () {
      var $g = $(this).closest('.cr-group');
      $(this).closest('.cr-row').remove();
      if (!$g.find('.cr-row').length) $g.remove();
      decorate();
    });
    $('#cr-copy-dom').on('click', function () {
      var s = getSites().filter(function (x) { return x !== '*'; });
      if (!s.length) { layer.msg('No replicable domain names', { icon: 2 }); return; }
      var t = $('<textarea>').val(s.join('\n')).appendTo('body').select();
      try { document.execCommand('copy'); layer.msg('Copied', { icon: 1 }); } catch (e) {}
      t.remove();
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
