(function (W) {
  // generated wiring: names declared in other modules
  var API = W.API;
  var S = W.S;
  function bindPager() { return W.bindPager.apply(this, arguments); }
  function esc() { return W.esc.apply(this, arguments); }
  function pager() { return W.pager.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }

  /* ================= BLACK / WHITE LISTS ================= */
  var LIST_DEFS = [
    { key: 'ip_white', t: 'IP whitelist', kind: 'ip',
      head: 'Add the following IP addresses to the whitelist',
      notes: [
        'All rules are skipped for IPs in the whitelist, including IP blacklist and URL blacklist — the IP whitelist has the highest priority.',
        'Add one IP: enter <b>192.168.10.6</b> or <b>2001:db8::6</b> in Start IP and leave End IP empty.',
        'Add a range: Start IP <b>192.168.100.6</b>, End IP <b>192.168.100.100</b> — or type <b>192.168.100.6-100</b> in Start IP.',
        'Add a segment: <b>192.168.1.0/24</b> or <b>2001:db8::/32</b>.',
        'This server&apos;s own addresses and private networks are always allowed — no need to add them.'
      ] },
    { key: 'ip_black', t: 'IP blacklist', kind: 'ip',
      head: 'Add the following IP addresses to the blacklist',
      notes: [
        'Every request from these IPs is dropped immediately.',
        'The IP whitelist wins: an IP present in both lists is allowed.',
        'Single IP, range (<b>192.168.100.6-100</b>) and CIDR (<b>192.168.1.0/24</b>, <b>2001:db8::/32</b>) are all accepted, IPv4 and IPv6.'
      ] },
    { key: 'ua_white', t: 'UA whitelist', kind: 'ua',
      head: 'Skip filtering for requests whose User-Agent matches',
      ph: 'UptimeRobot|Pingdom',
      notes: [
        'Entries are <b>regular expressions</b> matched (case-insensitive) against the User-Agent header.',
        'Matching requests skip every filter after the IP lists — use it for your own monitoring and payment callbacks.',
        'A User-Agent is trivial to fake: keep these patterns specific.'
      ] },
    { key: 'ua_black', t: 'UA blacklist', kind: 'ua',
      head: 'Block requests whose User-Agent matches',
      ph: 'sqlmap|nikto|masscan',
      notes: [
        'Entries are <b>regular expressions</b> matched (case-insensitive) against the User-Agent header.',
        'Applies to every site, before the per-site filters. The UA whitelist wins over this list.'
      ] },
    { key: 'url_white', t: 'URL whitelist', kind: 'url',
      head: 'Add the following URLs to the whitelist',
      ph: '^/api/callback',
      notes: [
        'These URLs skip filtering entirely — only add paths you control.',
        'Entries are regular expressions matched against the request URI, e.g. <b>^/api/callback</b>.'
      ] },
    { key: 'url_black', t: 'URL blacklist', kind: 'url',
      head: 'Add the following URLs to the blacklist',
      ph: '^/admin\\.php',
      notes: [
        'Requests to these URLs are blocked for everyone.',
        'The IP whitelist still wins over this list.'
      ] },
    { key: 'url_keyword', t: 'URL keyword', kind: 'url',
      head: 'Block requests whose URL contains',
      ph: 'casino|viagra',
      notes: [
        'Matched (case-insensitive, regular expression) against the decoded request line, query string included.',
        'Use it for spam keywords and paths you never serve.'
      ] }
  ];
  function listDef() { return LIST_DEFS.filter(function (x) { return x.key === S.listKey; })[0]; }

  function pageLists() {
    S.listKey = S.listKey || 'ip_white';
    var h = '<div class="wp-subtabs">' + LIST_DEFS.map(function (x) {
      return '<span class="wp-subtab' + (x.key === S.listKey ? ' on' : '') + '" data-k="' + x.key + '">' + x.t + '</span>';
    }).join('') + '</div>';
    h += '<div class="wp-card" style="border-top-left-radius:0"><div id="wp-list-body"><div class="wp-loading">Loading...</div></div></div>';
    $('#wp-body').html(h);
    $('.wp-subtab').on('click', function () {
      S.listKey = $(this).data('k');
      S.listQ = ''; S.listPage = 1;
      $('.wp-subtab').removeClass('on'); $(this).addClass('on');
      loadList();
    });
    loadList();
  }
  function loadList() {
    var def = listDef();
    $('#wp-list-body').html('<div class="wp-loading">Loading...</div>');
    post('list_get', { list_name: def.key }, function (r) {
      if (!r.status) { $('#wp-list-body').html('<div class="wp-empty">' + esc(r.msg || 'error') + '</div>'); return; }
      // backend returns {value,type,remark,index}; the table renders x.display
      S.listRows = (r.data || []).map(function (x) {
        return { display: x.value != null ? x.value : (x.ip || ''), type: x.type,
                 remark: x.remark, index: x.index };
      });
      S.listPage = S.listPage || 1; S.listSize = S.listSize || 10;

      /* ---- add form ---- */
      var h = '<div class="wp-form-t">' + def.head + '</div>';
      if (def.kind === 'ip') {
        h += formRow('Type', '<div class="wp-seg" id="wp-ip-type"><span class="on" data-v="ipv4">IPv4</span>' +
          '<span data-v="ipv6">IPv6</span></div>');
        h += formRow('Start IP', '<input class="wp-in wp-f" id="wp-l-start" placeholder="Please enter start IP address, e.g.: 192.168.1.1">');
        h += formRow('End IP', '<input class="wp-in wp-f" id="wp-l-end" placeholder="Please enter end IP address, e.g.: 192.168.1.24">');
      } else {
        h += formRow(def.kind === 'ua' ? 'User-Agent' : 'URL',
          '<input class="wp-in wp-f" id="wp-l-start" placeholder="' + (def.ph || '') + '">');
      }
      h += formRow('Remarks', '<input class="wp-in wp-f" id="wp-l-remark" placeholder="Please enter remarks">');
      h += formRow('', '<span class="wp-btn primary" id="wp-list-add">Add</span>');

      /* ---- toolbar ---- */
      h += '<div class="wp-list-bar">' +
        '<span class="wp-btn" id="wp-l-import">Import</span>' +
        '<span class="wp-btn" id="wp-l-export">Export</span>' +
        '<span class="wp-btn" id="wp-l-empty">Empty</span>' +
        '<div class="wp-search" style="margin-left:auto">' +
        '<input class="wp-in" id="wp-l-q" placeholder="Please enter IP/remarks" value="' + esc(S.listQ || '') + '">' +
        '<span class="wp-search-i">&#9906;</span></div></div>';
      h += '<div id="wp-list-table"></div>';

      /* ---- notes ---- */
      h += '<ul class="wp-notes">' + def.notes.map(function (n) { return '<li>' + n + '</li>'; }).join('') + '</ul>';
      $('#wp-list-body').html(h);
      renderListTable();

      $('#wp-ip-type span').on('click', function () {
        $('#wp-ip-type span').removeClass('on'); $(this).addClass('on');
        var v6 = $(this).data('v') === 'ipv6';
        $('#wp-l-start').attr('placeholder', v6 ? 'e.g.: 2001:db8::1 or 2001:db8::/48' : 'Please enter start IP address, e.g.: 192.168.1.1');
        $('#wp-l-end').attr('placeholder', v6 ? 'e.g.: 2001:db8::ff (optional)' : 'Please enter end IP address, e.g.: 192.168.1.24');
      });
      function add() {
        var v = ($('#wp-l-start').val() || '').trim();
        if (!v) { layer.msg('Enter a value', { icon: 0 }); return; }
        var d = { list_name: def.key, value: v, remark: ($('#wp-l-remark').val() || '').trim() };
        if (def.kind === 'ip') { d.start_ip = v; d.end_ip = ($('#wp-l-end').val() || '').trim(); }
        post('list_add', d, function (rr) {
          layer.msg((rr && rr.msg) || 'No response', { icon: (rr && rr.status) ? 1 : 2 });
          if (rr && rr.status) loadList();
        });
      }
      $('#wp-list-add').on('click', add);
      $('#wp-l-start,#wp-l-end,#wp-l-remark').on('keydown', function (e) { if (e.keyCode === 13) add(); });
      $('#wp-l-q').on('input', function () { S.listQ = $(this).val() || ''; S.listPage = 1; renderListTable(); });

      $('#wp-l-export').on('click', function () {
        post('list_export', { list_name: def.key }, function (rr) {
          if (!rr.status) { layer.msg(rr.msg || 'Export failed', { icon: 2 }); return; }
          layer.msg(rr.rows + ' rows exported', { icon: 1 });
          window.open(API + 'download_export&filename=' + encodeURIComponent(rr.filename));
        });
      });
      $('#wp-l-import').on('click', function () {
        layer.open({
          type: 1, title: 'Import to ' + def.t, area: ['560px', '400px'],
          content: '<div class="wp-modal" style="padding:18px 22px">' +
            '<div style="color:#5c6470;font-size:12px;line-height:1.7;margin-bottom:10px">' +
            'One entry per line. Optional remark after a comma.<br>' +
            (def.kind === 'ip' ? 'Examples: <code>192.168.1.5</code> · <code>10.0.0.1-10.0.0.9</code> · <code>192.168.1.0/24,office</code>'
                               : 'Example: <code>/api/callback,payment hook</code>') + '</div>' +
            '<textarea class="wp-in" id="wp-imp-body" style="width:100%;height:190px;font-family:ui-monospace,Menlo,monospace;font-size:12px"></textarea>' +
            '<div style="text-align:right;margin-top:12px"><span class="wp-btn primary" id="wp-imp-go">Import</span></div></div>',
          success: function () {
            $('#wp-imp-go').on('click', function () {
              post('list_import', { list_name: def.key, body: $('#wp-imp-body').val() || '' }, function (rr) {
                layer.msg((rr && rr.msg) || 'No response', { icon: (rr && rr.status) ? 1 : 2, time: 4000 });
                layer.closeAll('page'); loadList();
              });
            });
          }
        });
      });
      $('#wp-l-empty').on('click', function () {
        layer.confirm('Remove every entry from <b>' + def.t + '</b>?<br>This cannot be undone.',
          { icon: 3, title: 'Empty list' }, function (i) {
            layer.close(i);
            post('list_empty', { list_name: def.key }, function (rr) {
              layer.msg((rr && rr.msg) || 'No response', { icon: (rr && rr.status) ? 1 : 2 });
              loadList();
            });
          });
      });
    });
  }

  function renderListTable() {
    var def = listDef();
    var q = (S.listQ || '').toLowerCase();
    var all = (S.listRows || []).filter(function (x) {
      return !q || (x.display + ' ' + (x.remark || '')).toLowerCase().indexOf(q) !== -1;
    });
    var pages = Math.max(Math.ceil(all.length / S.listSize), 1);
    if (S.listPage > pages) S.listPage = pages;
    var rows = all.slice((S.listPage - 1) * S.listSize, S.listPage * S.listSize);
    var col1 = def.kind === 'ip' ? 'Start IP - End IP' : (def.kind === 'ua' ? 'User-Agent rule' : 'URL rule');

    var h = '<table class="wp-tbl"><thead><tr><th>' + col1 + '</th>' +
      '<th style="width:90px">Type</th><th style="width:220px">Remarks</th>' +
      '<th style="width:90px">Operate</th></tr></thead><tbody>';
    h += rows.length ? rows.map(function (v) {
      return '<tr><td style="color:var(--wp-text);' +
        (def.kind === 'ua' ? 'font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all' : '') + '">' +
        esc(v.display) + '</td>' +
        '<td>' + esc(v.type || (def.kind === 'ip' ? 'IPv4' : 'URL')) + '</td>' +
        '<td class="ell">' + (v.remark ? esc(v.remark) : '<span style="color:var(--wp-text3)">--</span>') + '</td>' +
        '<td><span class="wp-lnk wp-list-del" data-i="' + v.index + '">Delete</span></td></tr>';
    }).join('') : '<tr><td colspan="4" class="wp-empty">' +
      (S.listRows.length ? 'Nothing matches "' + esc(S.listQ) + '"' : 'List is empty') + '</td></tr>';
    h += '</tbody></table>';
    h += pager(S.listPage, pages, all.length, 'wp-l-pg');
    $('#wp-list-table').html(h);

    bindPager('wp-l-pg', pages, function (p) { S.listPage = p; renderListTable(); });
    $('.wp-list-del').on('click', function () {
      var idx = $(this).data('i');
      layer.confirm('Delete this entry?', { icon: 3, title: 'Delete' }, function (i) {
        layer.close(i);
        post('list_del', { list_name: listDef().key, index: idx }, function (rr) {
          layer.msg((rr && rr.msg) || 'No response', { icon: (rr && rr.status) ? 1 : 2 });
          loadList();
        });
      });
    });
  }
  function formRow(label, ctrl) {
    return '<div class="wp-form-row"><div class="wp-form-lbl">' + label + '</div>' +
      '<div class="wp-form-ctl">' + ctrl + '</div></div>';
  }


  // exports
  W.LIST_DEFS = LIST_DEFS;
  W.formRow = formRow;
  W.listDef = listDef;
  W.loadList = loadList;
  W.pageLists = pageLists;
  W.renderListTable = renderListTable;
})(window.WAFPRO = window.WAFPRO || {});
