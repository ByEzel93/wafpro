(function (W) {
  // generated wiring: names declared in other modules
  var API = W.API;
  var S = W.S;
  function bindPager() { return W.bindPager.apply(this, arguments); }
  function esc() { return W.esc.apply(this, arguments); }
  function pager() { return W.pager.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }

  /* ================= BLACK / WHITE LISTS (six card tabs, as in aaPanel 8) =================
     IP lists get the add form (IPv4 range or one IPv6 address/prefix);
     UA and URL lists add inline from the toolbar. URL keywords live in
     Global › Sensitive words, like the stock WAF. */
  var IP_NOTES = [
    'Add an IP: 192.168.10.6 The starting IP is 192.168.10.6 and the ending IP is 192.168.10.6',
    'Add multiple IPs: 192.168.100.6-100 The starting IP is 192.168.100.6 and the ending IP is 192.168.100.100',
    'Add IP segment: 192.168.1.0/24, starting IP is 192.168.1.1, ending IP is 192.168.1.254',
    'Add IP segment: 172.16.10.1/16, starting IP is 172.16.1.1, ending IP is 172.16.255.255'
  ];
  var UA_NOTES = [
    'Search for keywords in the client UA during the initialization phase. Use with caution.',
    'Entries are regular expressions matched case-insensitively against the User-Agent header.'
  ];
  var URL_EXAMPLES = [
    'Example 1: /admin/admin.php?system=abc Add address: /admin/admin.php',
    'Example 2: /admin/1 1 is variable 1-99 Add address: /admin/[1-99]'
  ];
  var LIST_DEFS = [
    { key: 'ip_white', t: 'IP whitelist', kind: 'ip', head: 'Add the following IP addresses to the whitelist',
      notes: ['All rules are invalid for IP segments in the whitelist, including IP blacklist and URL blacklist. IP whitelist has the highest priority.'].concat(IP_NOTES) },
    { key: 'ip_black', t: 'IP blacklist', kind: 'ip', head: 'Add the following IP addresses to the blacklist',
      notes: ['IP segments in the blacklist will be prohibited from access, except for those already in the IP whitelist.'].concat(IP_NOTES) },
    { key: 'ua_white', t: 'UA whitelist', kind: 'ua',
      notes: UA_NOTES.concat(['Can be used as a secret key in the API interface', 'Skip any interception directly after querying the keyword']) },
    { key: 'ua_black', t: 'UA blacklist', kind: 'ua',
      notes: UA_NOTES.concat(['Requests whose User-Agent matches are blocked on every site; the UA whitelist wins over this list.']) },
    { key: 'url_white', t: 'URL whitelist', kind: 'url',
      notes: ['All rules are invalid for URLs in the whitelist, excluding IP blacklist.',
        'The current URL whitelist does not support parameters.'].concat(URL_EXAMPLES) },
    { key: 'url_black', t: 'URL blacklist', kind: 'url',
      notes: ['A list of URLs that are prohibited from access, except when they exist in the URL whitelist and IP whitelist.'].concat(URL_EXAMPLES) }
  ];
  var IMPORT_FMT = {
    ip: 'The import format is as follows: one line per file (three formats are supported):\n192.168.1.1\n192.168.1.0/24\n192.168.1.1-192.168.1.254',
    ua: 'One line per line, for example:\nuser_agent1\nuser_agent2',
    url: 'One per line, for example:\n/admin.php\n/user.php'
  };
  function listDef() {
    return LIST_DEFS.filter(function (x) { return x.key === S.listKey; })[0] || LIST_DEFS[0];
  }

  function pageLists() {
    if (!LIST_DEFS.some(function (x) { return x.key === S.listKey; })) S.listKey = 'ip_white';
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

  function msg(rr) { layer.msg((rr && rr.msg) || 'No response', { icon: (rr && rr.status) ? 1 : 2 }); }

  function loadList() {
    var def = listDef();
    $('#wp-list-body').html('<div class="wp-loading">Loading...</div>');
    post('list_get', { list_name: def.key }, function (r) {
      if (!r.status) { $('#wp-list-body').html('<div class="wp-empty">' + esc(r.msg || 'error') + '</div>'); return; }
      S.listRows = (r.data || []).map(function (x) {
        return { display: x.value != null ? x.value : (x.ip || ''), type: x.type,
                 remark: x.remark, index: x.index };
      });
      S.listPage = S.listPage || 1; S.listSize = S.listSize || 10;
      var ip = def.kind === 'ip';
      var h = '';

      if (ip) {
        S.ipType = S.ipType || 'ipv4';
        h += '<div class="wp-form-t">' + def.head + '</div>' +
          formRow('Type', '<div class="wp-g-radios" id="wp-ip-type">' +
            ['IPv4', 'IPv6'].map(function (t) {
              return '<label><input type="radio" name="wp-ipt" value="' + t.toLowerCase() + '"' +
                (S.ipType === t.toLowerCase() ? ' checked' : '') + '> ' + t + '</label>';
            }).join('') + '</div>') +
          '<div id="wp-ip4"' + (S.ipType === 'ipv6' ? ' style="display:none"' : '') + '>' +
          formRow('Start IP', '<input class="wp-in wp-f" id="wp-l-start" placeholder="Please enter start IP address, e.g.: 192.168.1.1">') +
          formRow('End IP', '<input class="wp-in wp-f" id="wp-l-end" placeholder="Please enter end IP address, e.g.: 192.168.1.24">') +
          '</div><div id="wp-ip6"' + (S.ipType === 'ipv6' ? '' : ' style="display:none"') + '>' +
          formRow('IPv6 address', '<input class="wp-in wp-f" id="wp-l-v6" placeholder="Enter IP, e.g.: 2606:54c0:19c0:dc02::/63">') +
          '</div>' +
          formRow('Remarks', '<input class="wp-in wp-f" id="wp-l-remark" placeholder="Please enter remarks">') +
          formRow('', '<span class="wp-btn primary" id="wp-list-add">Add</span>');
      }

      // toolbar: [UA/URL inline add] Import Export Empty ............ search
      h += '<div class="wp-list-bar' + (ip ? '' : ' top') + '">';
      if (!ip) {
        h += '<input class="wp-in" id="wp-l-start" style="width:280px" placeholder="' +
          (def.kind === 'ua' ? 'Please enter UA' : 'For example: ^/api/admin/update') + '">' +
          '<span class="wp-btn primary" id="wp-list-add">Add</span>';
      }
      h += '<span class="wp-btn" id="wp-l-import">Import</span><span class="wp-btn" id="wp-l-export">Export</span>' +
        '<span class="wp-btn" id="wp-l-empty">Empty</span>' +
        '<div class="wp-site-search"><input class="wp-in" id="wp-l-q" placeholder="' +
        (ip ? 'Please enter IP/remarks' : def.kind === 'ua' ? 'Please enter UA' : 'Please enter URL') +
        '" value="' + esc(S.listQ || '') + '"></div></div>';
      h += '<div id="wp-list-table"></div>';
      h += '<ul class="wp-notes">' + def.notes.map(function (n) { return '<li>' + esc(n) + '</li>'; }).join('') + '</ul>';
      $('#wp-list-body').html(h);
      renderListTable();

      $('#wp-ip-type input').on('change', function () {
        S.ipType = this.value;
        $('#wp-ip4').toggle(S.ipType === 'ipv4'); $('#wp-ip6').toggle(S.ipType === 'ipv6');
      });
      function add() {
        var d = { list_name: def.key, remark: ($('#wp-l-remark').val() || '').trim() };
        if (ip && S.ipType === 'ipv6') {
          d.start_ip = ($('#wp-l-v6').val() || '').trim();
          if (!d.start_ip) { layer.msg('IPv6 address cannot be empty', { icon: 0 }); return; }
        } else if (ip) {
          d.start_ip = ($('#wp-l-start').val() || '').trim();
          d.end_ip = ($('#wp-l-end').val() || '').trim();
          if (!d.start_ip) { layer.msg('Starting IP cannot be empty', { icon: 0 }); return; }
        } else {
          d.value = ($('#wp-l-start').val() || '').trim();
          if (!d.value) { layer.msg(def.kind === 'ua' ? 'UA cannot be empty' : 'URL cannot be empty', { icon: 0 }); return; }
        }
        if (ip) d.value = d.start_ip;
        post('list_add', d, function (rr) { msg(rr); if (rr && rr.status) loadList(); });
      }
      $('#wp-list-add').on('click', add);
      $('#wp-l-start,#wp-l-end,#wp-l-v6,#wp-l-remark').on('keydown', function (e) { if (e.keyCode === 13) add(); });
      $('#wp-l-q').on('input', function () { S.listQ = $(this).val() || ''; S.listPage = 1; renderListTable(); });

      $('#wp-l-export').on('click', function () {
        post('list_export', { list_name: def.key }, function (rr) {
          if (!rr.status) { layer.msg(rr.msg || 'Export failed', { icon: 2 }); return; }
          layer.msg(rr.rows + ' rows exported', { icon: 1 });
          window.open(API + 'download_export&filename=' + encodeURIComponent(rr.filename));
        });
      });
      $('#wp-l-import').on('click', function () {
        W.open({
          type: 1, title: 'Import ' + def.t, area: ['520px', 'auto'], btn: ['Import', 'Cancel'],
          content: '<div class="wp-g-dlg"><textarea class="wp-in" id="wp-imp-body" style="width:100%;height:200px;' +
            'font-family:ui-monospace,Menlo,monospace;font-size:12px" placeholder="' + esc(IMPORT_FMT[def.kind]) + '"></textarea></div>',
          yes: function (i) {
            var body = ($('#wp-imp-body').val() || '').trim();
            if (!body) { layer.msg('Imported data cannot be empty', { icon: 0 }); return; }
            layer.close(i);
            post('list_import', { list_name: def.key, body: body }, function (rr) {
              layer.msg((rr && rr.msg) || 'No response', { icon: (rr && rr.status) ? 1 : 2, time: 4000 });
              loadList();
            });
          }
        });
      });
      $('#wp-l-empty').on('click', function () {
        W.confirm('Are you sure you want to clear ' + def.t + ' data?', { icon: 3, title: 'Clear ' + def.t }, function (i) {
          layer.close(i);
          post('list_empty', { list_name: def.key }, function (rr) { msg(rr); loadList(); });
        });
      });
    });
  }

  function renderListTable() {
    var def = listDef(), ip = def.kind === 'ip';
    var q = (S.listQ || '').toLowerCase();
    var all = (S.listRows || []).filter(function (x) {
      return !q || (x.display + ' ' + (x.remark || '')).toLowerCase().indexOf(q) !== -1;
    });
    var pages = Math.max(Math.ceil(all.length / S.listSize), 1);
    if (S.listPage > pages) S.listPage = pages;
    var rows = all.slice((S.listPage - 1) * S.listSize, S.listPage * S.listSize);
    var col1 = ip ? 'Start IP - End IP / IPv6 address' : def.kind === 'ua' ? 'UA' : 'URL';

    var h = '<div class="wp-site-box"><table class="wp-site-tbl"><thead><tr><th>' + col1 + '</th>' +
      (ip ? '<th>Type</th><th>Remarks</th>' : '') + '<th class="r">Operate</th></tr></thead><tbody>';
    h += rows.length ? rows.map(function (v) {
      return '<tr><td class="ell" style="color:#303133;max-width:520px" title="' + esc(v.display) + '">' + esc(v.display) + '</td>' +
        (ip ? '<td>' + esc(v.type || (v.display.indexOf(':') !== -1 ? 'IPv6' : 'IPv4')) + '</td>' +
          '<td class="ell">' + (v.remark ? esc(v.remark) : '--') + '</td>' : '') +
        '<td class="r"><span class="wp-lnk wp-list-del" data-i="' + v.index + '">Delete</span></td></tr>';
    }).join('') : '<tr><td colspan="' + (ip ? 4 : 2) + '" class="wp-empty">No Data</td></tr>';
    h += '</tbody></table></div>';
    h += pager(S.listPage, pages, all.length, 'wp-l-pg', S.listSize);
    $('#wp-list-table').html(h);

    bindPager('wp-l-pg', pages, function (p) { S.listPage = p; renderListTable(); },
      function (k) { S.listSize = k; S.listPage = 1; renderListTable(); });
    $('.wp-list-del').on('click', function () {
      var idx = $(this).data('i');
      W.confirm('Delete this entry?', { icon: 3, title: 'Delete' }, function (i) {
        layer.close(i);
        post('list_del', { list_name: listDef().key, index: idx }, function (rr) { msg(rr); loadList(); });
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
