(function (W) {
  // generated wiring: names declared in other modules
  var API = W.API;
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function icoWarn() { return W.icoWarn.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }
  function row() { return W.row.apply(this, arguments); }

  /* ================= TRAFFIC LIMIT =================
     Per-URL rate limiting, lowest priority. One rule per row, same table
     language as Region. Built for API endpoints, not whole sites. */
  var TL_STATUS = [
    { code: 503, name: '503 (Service Unavailable)' },
    { code: 502, name: '502 (Connection Timeout)' },
    { code: 444, name: '444 (Close connection)' },
    { code: 403, name: '403 (Access denied)' }
  ];
  function tlTrigger(t) {
    var who = t.dim === 'ipua' ? 'Single IP + UA' : 'Single IP';
    return 'At <b>' + who + '</b> accessing <b>' + esc(t.url) + '</b> more than <b>' +
      t.rate + '</b> times per second, traffic restriction is triggered';
  }
  function tlAction(t) {
    if (t.action === 'block') return 'Intercept (Block IP)';
    var n = { 503: 'Service Unavailable', 502: 'Connection Timeout',
              444: 'Close connection', 403: 'Access denied' }[t.status] || '';
    return 'Status Code ' + t.status + (n ? ' (' + n + ')' : '');
  }

  function pageTraffic() {
    $('#wp-body').html('<div class="wp-loading">Loading...</div>');
    post('traffic_rules', {}, function (r) {
      if (!r.status) { $('#wp-body').html('<div class="wp-note">' + esc(r.msg || 'error') + '</div>'); return; }
      S.tlMeta = r;
      renderTraffic(r);
    });
  }

  function renderTraffic(r) {
    var e = r.engine || {};
    var h = '';
    if (!e.wired) {
      h += '<div class="wp-note" style="margin-bottom:12px">' + icoWarn() +
        ' The engine is not wired into nginx, so these rules are stored but not enforced.</div>';
    }
    h += '<div class="wp-card">';
    h += '<div style="margin-bottom:14px"><span class="wp-btn primary" id="tl-add">Add Restriction</span></div>';
    h += '<table class="wp-tbl"><thead><tr>' +
      '<th style="width:130px">Rule Name</th>' +
      '<th style="width:170px">Website Name</th>' +
      '<th>Trigger Condition</th>' +
      '<th style="width:230px">Execute Action</th>' +
      '<th style="width:60px">Status</th>' +
      '<th style="width:100px">Operate</th></tr></thead><tbody>';
    if (!r.rules.length) {
      h += '<tr><td colspan="6" style="padding:26px;text-align:center;color:var(--wp-text3)">No traffic restriction yet.</td></tr>';
    } else {
      h += r.rules.map(function (t) {
        return '<tr data-id="' + t.id + '">' +
          '<td style="color:var(--wp-text);font-weight:600">' + esc(t.name) + '</td>' +
          '<td class="ell" title="' + esc(t.site) + '">' + esc(t.site) + '</td>' +
          '<td style="color:var(--wp-text2)">' + tlTrigger(t) + '</td>' +
          '<td>' + tlAction(t) + '</td>' +
          '<td><label class="wp-sw"><input type="checkbox" class="tl-on"' + (t.open ? ' checked' : '') +
          '><span class="sl"></span></label></td>' +
          '<td><a href="javascript:;" class="tl-edit" style="color:var(--wp-green)">Edit</a> ' +
          '<span style="color:var(--wp-border)">|</span> ' +
          '<a href="javascript:;" class="tl-del" style="color:var(--wp-green)">Delete</a></td></tr>';
      }).join('');
    }
    h += '</tbody></table>';
    h += '<ul class="wp-notes">' +
      '<li>The priority of traffic restrictions is the lowest.</li>' +
      '<li>Traffic restrictions are generally used for API endpoints; enabling them for a whole site is not recommended.</li>' +
      '<li>The suggested return type is 503 or 502.</li>' +
      '<li>Loopback and LAN addresses are never rate-limited.</li>' +
      '</ul>';
    h += '</div>';
    $('#wp-body').html(h);

    $('#tl-add').on('click', function () { tlDialog(null); });
    $('#wp-body').on('click', '.tl-edit', function () {
      var id = $(this).closest('tr').data('id');
      tlDialog(r.rules.filter(function (x) { return x.id === id; })[0]);
    });
    $('#wp-body').on('change', '.tl-on', function () {
      var id = $(this).closest('tr').data('id'), on = $(this).is(':checked');
      post('traffic_toggle', { id: id, open: on ? 1 : 0 }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
      });
    });
    $('#wp-body').on('click', '.tl-del', function () {
      var id = $(this).closest('tr').data('id');
      W.confirm('Delete this traffic restriction?', function (i) {
        layer.close(i);
        post('traffic_del', { id: id }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) route();
        });
      });
    });
  }

  function tlDialog(rule) {
    var r = S.tlMeta, edit = !!rule;
    rule = rule || { name: '', site: '', url: '', dim: 'ip', rate: 20, action: 'status', status: 503 };
    var sites = (r.sites || []).map(function (s) {
      return '<option value="' + esc(s) + '"' + (s === rule.site ? ' selected' : '') + '>' + esc(s) + '</option>';
    }).join('');
    var codes = TL_STATUS.map(function (s) {
      return '<option value="' + s.code + '"' + (s.code === rule.status ? ' selected' : '') + '>' + s.name + '</option>';
    }).join('');

    var h = '<div class="wp-modal">' +
      '<div class="wp-mod-head">' +
        '<div class="wp-mod-site">' + (edit ? 'Edit' : 'Add') + ' Traffic Restriction</div>' +
        '<div class="wp-mod-meta">Rate-limit one URL per IP. Meant for API endpoints, not whole sites.</div>' +
      '</div>' +
      '<div class="wp-mod-body">' +
        '<div class="wp-mod-sec"><div class="wp-mod-sec-t">Scope</div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">Rule name</div>' +
            '<div class="wp-mod-ctl"><input class="wp-in" id="tl-name" style="min-width:250px" value="' + esc(rule.name) + '" placeholder="e.g. api_login"></div>' +
            '<div class="wp-mod-hint">Just a label.</div></div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">Website</div>' +
            '<div class="wp-mod-ctl"><select class="wp-in" id="tl-site" style="min-width:250px">' + sites + '</select></div>' +
            '<div class="wp-mod-hint"></div></div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">URL pattern</div>' +
            '<div class="wp-mod-ctl"><input class="wp-in" id="tl-url" style="min-width:250px" value="' + esc(rule.url) + '" placeholder="/api/login"></div>' +
            '<div class="wp-mod-hint">Matched as a regex against the request URI.</div></div>' +
        '</div>' +
        '<div class="wp-mod-sec"><div class="wp-mod-sec-t">Trigger</div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">Count by</div>' +
            '<div class="wp-mod-ctl"><select class="wp-in" id="tl-dim" style="min-width:250px">' +
              '<option value="ip"' + (rule.dim === 'ip' ? ' selected' : '') + '>Single IP</option>' +
              '<option value="ipua"' + (rule.dim === 'ipua' ? ' selected' : '') + '>Single IP + User-Agent</option>' +
            '</select></div>' +
            '<div class="wp-mod-hint">IP+UA counts each browser separately behind one IP.</div></div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">Rate</div>' +
            '<div class="wp-mod-ctl">more than <input class="wp-in" id="tl-rate" type="number" style="width:90px" value="' + rule.rate + '"> requests / second</div>' +
            '<div class="wp-mod-hint"></div></div>' +
        '</div>' +
        '<div class="wp-mod-sec"><div class="wp-mod-sec-t">Action</div>' +
          '<div class="wp-mod-row"><div class="wp-mod-lbl">When triggered</div>' +
            '<div class="wp-mod-ctl"><select class="wp-in" id="tl-action" style="min-width:250px">' +
              '<option value="status"' + (rule.action === 'status' ? ' selected' : '') + '>Return a status code</option>' +
              '<option value="block"' + (rule.action === 'block' ? ' selected' : '') + '>Intercept (block the IP)</option>' +
            '</select></div>' +
            '<div class="wp-mod-hint"></div></div>' +
          '<div class="wp-mod-row" id="tl-code-row"><div class="wp-mod-lbl">Status code</div>' +
            '<div class="wp-mod-ctl"><select class="wp-in" id="tl-code" style="min-width:250px">' + codes + '</select></div>' +
            '<div class="wp-mod-hint">503 or 502 recommended.</div></div>' +
        '</div>' +
      '</div>' +
      '<div class="wp-mod-foot">' +
        '<span class="wp-btn" id="tl-cancel">Cancel</span>' +
        '<span class="wp-btn primary" id="tl-ok">' + (edit ? 'Save' : 'Add') + '</span>' +
      '</div></div>';

    var idx = W.open({ type: 1, title: false, closeBtn: 1, area: ['680px', '620px'], content: h });

    function syncCode() { $('#tl-code-row').css('display', $('#tl-action').val() === 'block' ? 'none' : ''); }
    syncCode();
    $('#tl-action').on('change', syncCode);
    $('#tl-cancel').on('click', function () { layer.close(idx); });
    $('#tl-ok').on('click', function () {
      var payload = {
        rname: $('#tl-name').val(), site: $('#tl-site').val(), url: $('#tl-url').val(),
        dim: $('#tl-dim').val(), rate: $('#tl-rate').val(),
        act: $('#tl-action').val(), status_code: $('#tl-code').val()
      };
      if (edit) payload.id = rule.id;
      post(edit ? 'traffic_edit' : 'traffic_add', payload, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        if (rr.status) { layer.close(idx); route(); }
      });
    });
  }

  // exports
  W.TL_STATUS = TL_STATUS;
  W.pageTraffic = pageTraffic;
  W.renderTraffic = renderTraffic;
  W.tlAction = tlAction;
  W.tlDialog = tlDialog;
  W.tlTrigger = tlTrigger;
})(window.WAFPRO = window.WAFPRO || {});
