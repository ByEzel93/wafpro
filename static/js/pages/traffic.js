(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function icoWarn() { return W.icoWarn.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }

  /* ================= TRAFFIC LIMIT (aaPanel 8 layout) =================
     Rules carry the stock fields: sites, path (specified URL / entire site),
     who shares the budget (single IP, IP+UA, all IPs), a per-second limit
     and/or "N seconds, more than M times", and the response. */
  var TL_ACTIONS = [
    ['status_403', 'Status Code 403 (Access Denied)'],
    ['status_404', 'Status Code 404 (File Not Found)'],
    ['status_502', 'Status Code 502 (Connection Timeout)'],
    ['status_503', 'Status Code 503 (Service Unavailable)'],
    ['content', 'Return Web Content'],
    ['drop', 'Block IP']
  ];
  var TL_RETURNS = [
    ['html', 'Default Traffic Limiting Page (HTML Format)'],
    ['json', 'Default Traffic Limiting Page (JSON Format)'],
    ['444', '444 Response']
  ];
  function tlTrigger(t) {
    var who = { 1: 'Single IP', 2: 'Single IP + UA', 3: 'All IPs' }[t.cond] || 'Single IP';
    var n = who;
    if (t.req) n += ' accessing the specified URL more than ' + t.req + ' times per second';
    if (t.cnt_time && t.cnt_num) {
      if (t.req) n += ' or within ';
      else n += ' within ';
      n += t.cnt_time + ' seconds, accessing this URL more than ' + t.cnt_num + ' times';
    }
    return 'At ' + esc(n) + ', traffic restriction will be triggered' +
      '<div style="color:#909399;font-size:12px">' + (t.types === 'all' ? 'Entire Site' : esc(t.path)) + '</div>';
  }
  function tlAction(t) {
    if (t.action === 'drop') return 'Intercept (Block IP)';
    var a = TL_ACTIONS.filter(function (x) { return x[0] === t.action; })[0];
    return a ? a[1] : esc(t.action);
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
    h += '<div class="wp-card"><div class="wp-bl-bar" style="margin-bottom:14px">' +
      '<span class="wp-btn primary" id="tl-add">Add Restriction</span></div>';
    h += '<div class="wp-site-box"><table class="wp-site-tbl"><thead><tr>' +
      '<th style="width:12%">Rule Name</th><th style="width:16%">Website Name</th><th>Trigger Condition</th>' +
      '<th style="width:16%">Execute Action</th><th style="width:6%">Status</th><th class="r" style="width:100px">Operate</th>' +
      '</tr></thead><tbody>';
    h += r.rules.length ? r.rules.map(function (t) {
      return '<tr data-id="' + esc(t.id) + '"><td class="ell">' + esc(t.name) + '</td>' +
        '<td class="ell" style="max-width:200px">' + esc((t.sites || []).map(function (x) {
          return x === '*' ? 'All Websites' : x; }).join(', ')) + '</td>' +
        '<td style="white-space:normal">' + tlTrigger(t) + '</td>' +
        '<td style="white-space:normal">' + tlAction(t) + '</td>' +
        '<td><label class="wp-sw wp-sw-sm"><input type="checkbox" class="tl-on"' + (t.open ? ' checked' : '') +
        '><span class="sl"></span></label></td>' +
        '<td class="wp-ops"><span class="wp-lnk tl-edit">Edit</span><span class="wp-ops-sep">|</span>' +
        '<span class="wp-lnk tl-del">Delete</span></td></tr>';
    }).join('') : '<tr><td colspan="6" class="wp-empty">No Data</td></tr>';
    h += '</tbody></table></div>';
    h += '<ul class="wp-notes">' +
      '<li>The priority of traffic restrictions is the lowest</li>' +
      '<li>Traffic restrictions are generally used for API interfaces; it is not recommended to enable them for the entire site</li>' +
      '<li>The suggested return type is 503 or 502</li>' +
      '<li>If you want to modify the return content, edit the Traffic limiting page (HTML / JSON) under ' +
      '<span class="wp-lnk" id="tl-page-h">HTML</span> / <span class="wp-lnk" id="tl-page-j">JSON</span>; it is sent with status 429</li>' +
      '</ul></div>';
    $('#wp-body').html(h);

    function byId(el) {
      var id = $(el).closest('tr').data('id');
      return r.rules.filter(function (x) { return x.id === id; })[0];
    }
    $('#tl-add').on('click', function () { tlDialog(null); });
    $('#wp-body').on('click', '.tl-edit', function () { tlDialog(byId(this)); });
    $('#wp-body').on('change', '.tl-on', function () {
      var id = $(this).closest('tr').data('id'), on = $(this).is(':checked');
      post('traffic_toggle', { id: id, open: on ? 1 : 0 }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
      });
    });
    $('#wp-body').on('click', '.tl-del', function () {
      var t = byId(this);
      W.confirm('Are you sure you want to delete the [' + esc(t.name) + '] rule?', { title: 'Delete Traffic Restriction' }, function (i) {
        layer.close(i);
        post('traffic_del', { id: t.id }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) route();
        });
      });
    });
    $('#tl-page-h,#tl-page-j').on('click', function () {
      var kind = this.id === 'tl-page-h' ? 'limit' : 'limitjson';
      post('get_page', { kind: kind }, function (pr) {
        if (!pr.status) { layer.msg(pr.msg, { icon: 2 }); return; }
        W.htmlEditDialog({
          title: 'Online Edit [Traffic limiting page (' + (kind === 'limit' ? 'HTML' : 'JSON') + ')]',
          html: pr.html, def: pr.default,
          save: function (html, done) {
            post('save_page', { kind: kind, html: html }, function (sr) {
              layer.msg(sr.msg, { icon: sr.status ? 1 : 2 });
              if (sr.status) done();
            });
          }
        });
      });
    });
  }

  /* ---- website multi-select with an "All Websites" option ('*') ---- */
  function siteMS(id, all, chosen) {
    var sel = {};
    (chosen || []).forEach(function (k) { sel[k] = 1; });
    function draw() {
      var keys = Object.keys(sel);
      $('#' + id + ' .wp-ms-box').html(keys.length ? keys.map(function (k) {
        return '<span class="wp-chip2"><b>' + esc(k === '*' ? 'All Websites' : k) + '</b><i data-s="' + esc(k) + '">&times;</i></span>';
      }).join('') : '<span class="ph">Please select a website</span>');
      $('#' + id + ' .wp-ms-drop').html(['*'].concat(all).map(function (k) {
        return '<div class="wp-ms-opt' + (sel[k] ? ' on' : '') + '" data-s="' + esc(k) + '">' +
          esc(k === '*' ? 'All Websites' : k) + '</div>';
      }).join(''));
    }
    draw();
    var $m = $('#' + id);
    $m.find('.wp-ms-box').on('click', function (e) {
      if ($(e.target).is('i')) { delete sel[$(e.target).data('s')]; draw(); return; }
      $m.toggleClass('open');
    });
    $m.on('click', '.wp-ms-opt', function () {
      var k = String($(this).data('s'));
      if (sel[k]) delete sel[k];
      else if (k === '*') sel = { '*': 1 };
      else { delete sel['*']; sel[k] = 1; }
      draw();
    });
    $(document).off('mousedown.' + id).on('mousedown.' + id, function (e) {
      if (!$(e.target).closest('#' + id).length) $m.removeClass('open');
    });
    return function () { return Object.keys(sel); };
  }

  function tlDialog(rule) {
    var edit = !!rule;
    rule = rule || { name: '', sites: [], types: 'url', path: '', cond: 1, req: '', cnt_time: '', cnt_num: '',
                     action: 'status_503', ret: 'html' };
    var secondOn = edit ? !!rule.req : true, countOn = edit ? !!rule.cnt_time : false;
    function opts(list, v) {
      return list.map(function (x) {
        return '<option value="' + x[0] + '"' + (x[0] === v ? ' selected' : '') + '>' + x[1] + '</option>';
      }).join('');
    }
    var h = '<div class="wp-g-dlg wp-tl">' +
      '<div class="wp-tl-t">When the website</div>' +
      '<div class="wp-g-row"><div class="wp-g-rl">Name</div><div class="wp-g-rc"><input class="wp-in" id="tl-name" style="width:380px" ' +
      'placeholder="Please enter the rule name" value="' + esc(rule.name) + '"></div></div>' +
      '<div class="wp-g-row"><div class="wp-g-rl">Apply to website</div><div class="wp-g-rc">' +
      '<div class="wp-ms" id="tl-sites" style="width:380px"><div class="wp-ms-box"></div><div class="wp-ms-drop"></div></div></div></div>' +
      '<div class="wp-tl-t">Trigger Condition</div>' +
      '<div class="wp-g-row"><div class="wp-g-rl">Path</div><div class="wp-g-rc">' +
      '<select class="wp-in" id="tl-types" style="width:130px">' + opts([['url', 'Specified URL'], ['all', 'Entire Site']], rule.types) + '</select>' +
      '<input class="wp-in" id="tl-url" style="width:242px" placeholder="Please enter URL" value="' +
      esc(rule.types === 'all' ? '/' : rule.path) + '"' + (rule.types === 'all' ? ' disabled' : '') + '></div></div>' +
      '<div class="wp-g-row"><div class="wp-g-rl">Access Restriction</div><div class="wp-g-rc wp-g-radios">' +
      [[1, 'Single IP'], [2, 'IP+UA'], [3, 'All IPs']].map(function (x) {
        return '<label><input type="radio" name="tl-cond" value="' + x[0] + '"' + (rule.cond === x[0] ? ' checked' : '') + '> ' + x[1] + '</label>';
      }).join('') + '</div></div>' +
      '<div class="wp-g-row"><div class="wp-g-rl"></div><div class="wp-g-rc">' +
      '<label class="wp-g-chk"><input type="checkbox" id="tl-sec"' + (secondOn ? ' checked' : '') + '> Access Limit Per Second</label>' +
      '<input class="wp-in wp-tl-n" id="tl-req" value="' + esc(rule.req || '') + '"><span class="wp-unit">Time(s)</span></div></div>' +
      '<div class="wp-g-row"><div class="wp-g-rl"></div><div class="wp-g-rc">' +
      '<label class="wp-g-chk"><input type="checkbox" id="tl-cnt"' + (countOn ? ' checked' : '') + '> Time Access Limit</label>' +
      '<input class="wp-in wp-tl-n" id="tl-ct" value="' + esc(rule.cnt_time || '') + '"><span class="wp-unit">seconds, exceeding</span>' +
      '<input class="wp-in wp-tl-n" id="tl-cn" value="' + esc(rule.cnt_num || '') + '"><span class="wp-unit">Time(s)</span></div></div>' +
      '<div class="wp-tl-t">Response Result</div>' +
      '<div class="wp-g-row"><div class="wp-g-rl">Action Options</div><div class="wp-g-rc">' +
      '<select class="wp-in" id="tl-action" style="width:380px">' + opts(TL_ACTIONS, rule.action) + '</select></div></div>' +
      '<div class="wp-g-row" id="tl-ret-row"><div class="wp-g-rl">Response Page</div><div class="wp-g-rc">' +
      '<select class="wp-in" id="tl-ret" style="width:380px">' + opts(TL_RETURNS, rule.ret) + '</select></div></div>' +
      '</div>';

    var getSites;
    var idx = W.open({
      type: 1, title: edit ? 'Modify Traffic Restriction' : 'Add Traffic Restriction', area: ['640px', 'auto'],
      btn: ['Confirm', 'Cancel'], content: h,
      success: function () {
        getSites = siteMS('tl-sites', S.tlMeta.sites || [], rule.sites);
        function sync() {
          $('#tl-ret-row').toggle($('#tl-action').val() === 'content');
          $('#tl-req').prop('disabled', !$('#tl-sec').is(':checked'));
          $('#tl-ct,#tl-cn').prop('disabled', !$('#tl-cnt').is(':checked'));
        }
        sync();
        $('#tl-action,#tl-sec,#tl-cnt').on('change', sync);
        $('#tl-types').on('change', function () {
          var all = $(this).val() === 'all';
          $('#tl-url').prop('disabled', all).val(all ? '/' : '');
        });
      },
      yes: function () {
        var sec = $('#tl-sec').is(':checked'), cnt = $('#tl-cnt').is(':checked');
        if (!sec && !cnt) { layer.msg('Please select at least one restriction condition', { icon: 2 }); return; }
        var d = {
          rname: $('#tl-name').val() || '', sites: JSON.stringify(getSites()), types: $('#tl-types').val(),
          url: $('#tl-url').val() || '', condition: $('input[name=tl-cond]:checked').val(),
          req: sec ? ($('#tl-req').val() || '') : '', cnt_time: cnt ? ($('#tl-ct').val() || '') : '',
          cnt_num: cnt ? ($('#tl-cn').val() || '') : '', act: $('#tl-action').val(), ret: $('#tl-ret').val()
        };
        if (sec && !(parseInt(d.req, 10) >= 1)) { layer.msg('Access limit per second cannot be less than 1', { icon: 2 }); return; }
        if (edit) d.id = rule.id;
        post(edit ? 'traffic_edit' : 'traffic_add', d, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) { layer.close(idx); route(); }
        });
      }
    });
  }

  // exports
  W.pageTraffic = pageTraffic;
  W.renderTraffic = renderTraffic;
  W.siteMS = siteMS;
  W.tlAction = tlAction;
  W.tlDialog = tlDialog;
  W.tlTrigger = tlTrigger;
})(window.WAFPRO = window.WAFPRO || {});
