(function (W) {
  // generated wiring: names declared in other modules
  function pickDate() { return W.pickDate.apply(this, arguments); }
  function todayStr() { return W.todayStr.apply(this, arguments); }
  var S = W.S;
  function ec() { return W.ec.apply(this, arguments); }
  function ensureEcharts() { return W.ensureEcharts.apply(this, arguments); }
  function esc() { return W.esc.apply(this, arguments); }
  function icoPie() { return W.icoPie.apply(this, arguments); }
  function icoWarn() { return W.icoWarn.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }

  /* ================= REPORT =================
     Attack analytics from the block log: protection-type donut + country
     leaderboard on the left, IP / URI / Search tables on the right. */
  var RP_COLORS = ['#20a53a', '#3b82f6', '#fa8c16', '#22c3c3', '#8b5cf6', '#ef4d4d',
                   '#eab308', '#ec4899', '#14b8a6', '#6366f1'];

  function pageReport() {
    S.rpSub = S.rpSub || 'ip';
    S.rpDate = S.rpDate || 'today';
    S.rpStart = S.rpStart || ''; S.rpEnd = S.rpEnd || '';
    loadReport();
  }

  function rpDateArgs() {
    return (S.rpStart && S.rpEnd) ? { date: '', start: S.rpStart, end: S.rpEnd } : { date: S.rpDate };
  }

  function loadReport() {
    $('#wp-body').html('<div class="wp-loading">Loading...</div>');
    post('report', rpDateArgs(), function (r) {
      if (!r.status) { $('#wp-body').html('<div class="wp-note">' + esc(r.msg || 'error') + '</div>'); return; }
      S.rpData = r;
      renderReport(r);
    });
  }

  function renderReport(r) {
    var h = '<div class="wp-row wp-main-grid">';

    /* ---- LEFT ---- */
    h += '<div class="wp-col">';
    h += '<div class="wp-card"><div class="wp-card-h">' + icoPie() +
      '<span class="t">Total protection type</span></div>' +
      '<div class="wp-chart" id="rp-donut" style="height:230px"></div></div>';
    h += '<div class="wp-card"><div class="wp-card-h">' + icoWarn() +
      '<span class="t">Attack IP Leader board</span></div><div id="rp-lb"></div></div>';
    h += '</div>';

    /* ---- RIGHT ---- */
    h += '<div class="wp-col">';
    h += '<div class="wp-card">';
    // header: sub-tabs + date filter
    h += '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:14px">' +
      '<div class="wp-subtabs" id="rp-subs" style="margin:0;border:0;flex:1">' +
        [['ip', 'IP Report'], ['uri', 'URI Report'], ['search', 'Search']].map(function (x) {
          return '<span class="wp-subtab' + (x[0] === S.rpSub ? ' on' : '') + '" data-s="' + x[0] + '">' + x[1] + '</span>';
        }).join('') + '</div>' +
      '<div style="display:flex;align-items:center;gap:6px">' +
        '<span class="wp-btn rp-range' + (S.rpDate === 'yesterday' && !S.rpStart ? ' primary' : '') + '" data-d="yesterday">Yesterday</span>' +
        '<span class="wp-btn rp-range' + (S.rpDate === 'today' && !S.rpStart ? ' primary' : '') + '" data-d="today">Today</span>' +
        '<span class="rp-pick" data-for="rp-start"><input class="wp-in" id="rp-start" readonly placeholder="Start date" style="width:130px;cursor:pointer" value="' + esc(S.rpStart) + '"></span>' +
        '<span style="color:var(--wp-text3)">→</span>' +
        '<span class="rp-pick" data-for="rp-end"><input class="wp-in" id="rp-end" readonly placeholder="End date" style="width:130px;cursor:pointer" value="' + esc(S.rpEnd) + '"></span>' +
        '<span class="wp-btn primary" id="rp-apply">Report</span>' +
      '</div></div>';
    h += '<div id="rp-body"></div>';
    h += '</div></div>';

    h += '</div>';
    $('#wp-body').html(h);

    drawReportDonut(r);
    renderLeaderboard(r);
    renderReportBody();

    $('#rp-subs .wp-subtab').on('click', function () {
      S.rpSub = $(this).data('s');
      $('#rp-subs .wp-subtab').removeClass('on'); $(this).addClass('on');
      renderReportBody();
    });
    $('.rp-range').on('click', function () {
      S.rpDate = $(this).data('d'); S.rpStart = ''; S.rpEnd = '';
      loadReport();
    });
    $('.rp-pick').on('click', function () {
      var $i = $('#' + $(this).data('for'));
      pickDate(this, { value: $i.val(), max: todayStr(), done: function (v) { $i.val(v); } });
    });
    $('#rp-apply').on('click', function () {
      var st = $('#rp-start').val(), en = $('#rp-end').val();
      if (st && en) { S.rpStart = st; S.rpEnd = en; }
      else { S.rpStart = ''; S.rpEnd = ''; }
      loadReport();
    });
  }

  function drawReportDonut(r) {
    var data = (r.protection || []).map(function (x, i) {
      return { name: x.name, value: x.count, itemStyle: { color: RP_COLORS[i % RP_COLORS.length] } };
    });
    ensureEcharts(function () {
      ec('rp-donut', {
        tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
        legend: { type: 'scroll', orient: 'horizontal', bottom: 0, textStyle: { fontSize: 11 } },
        series: [{
          type: 'pie', radius: ['45%', '65%'], center: ['50%', '42%'],
          avoidLabelOverlap: true, label: { show: false }, labelLine: { show: false },
          data: data.length ? data : [{ name: 'No data', value: 1, itemStyle: { color: '#eee' } }]
        }]
      });
      var el = document.getElementById('rp-donut');
      if (el && r.total) {
        // center total
        var d = document.createElement('div');
        d.style.cssText = 'position:absolute;top:38%;left:0;right:0;text-align:center;pointer-events:none';
        d.innerHTML = '<div style="font-size:12px;color:var(--wp-text2)">Protection Type</div>' +
          '<div style="font-size:22px;font-weight:700;color:var(--wp-text)">' + num(r.total) + '</div>';
        el.style.position = 'relative'; el.appendChild(d);
      }
    });
  }

  function renderLeaderboard(r) {
    var lb = r.leaderboard || [];
    if (!lb.length) { $('#rp-lb').html('<div class="wp-empty">No attacks in this window</div>'); return; }
    var max = lb[0].count || 1;
    $('#rp-lb').html(lb.map(function (x, i) {
      return '<div class="wp-rank"><span class="n' + (i < 3 ? ' top' : '') + '">' + (i + 1) + '</span>' +
        '<span class="nm" title="' + esc(x.country) + '">' + esc(x.country) + '</span>' +
        '<span class="tr"><i style="width:' + Math.max(x.count / max * 100, 3) + '%"></i></span>' +
        '<span class="v">' + num(x.count) + '</span></div>';
    }).join(''));
  }

  function renderReportBody() {
    var r = S.rpData || {};
    if (S.rpSub === 'search') return renderReportSearch();
    if (S.rpSub === 'uri') {
      var rows = r.uri_report || [];
      var h = '<table class="wp-tbl"><thead><tr><th>Attacked URI</th>' +
        '<th style="width:120px">Num of attacks</th><th style="width:280px">Attack ratio</th></tr></thead><tbody>';
      h += rows.length ? rows.map(function (x) {
        return '<tr><td class="ell" title="' + esc(x.uri) + '">' + esc(x.uri) + '</td>' +
          '<td>' + num(x.count) + '</td><td>' + ratioBar(x.ratio) + '</td></tr>';
      }).join('') : '<tr><td colspan="3" class="wp-empty">No data in this window</td></tr>';
      h += '</tbody></table>';
      $('#rp-body').html(h);
      return;
    }
    // IP report
    var rows = r.ip_report || [];
    var h = '<table class="wp-tbl"><thead><tr><th style="width:150px">Attack IP</th>' +
      '<th style="width:150px">IP Location</th><th style="width:120px">Num of attacks</th>' +
      '<th>Attack ratio</th><th style="width:130px">Operate</th></tr></thead><tbody>';
    h += rows.length ? rows.map(function (x) {
      return '<tr data-ip="' + esc(x.ip) + '"><td style="font-weight:600;color:var(--wp-text)">' + esc(x.ip) + '</td>' +
        '<td>' + esc(x.location) + '</td><td>' + num(x.count) + '</td>' +
        '<td>' + ratioBar(x.ratio) + '</td>' +
        '<td><a href="javascript:;" class="rp-bl" style="color:var(--wp-green)">Blacklist</a> ' +
        '<span style="color:var(--wp-border)">|</span> ' +
        '<a href="javascript:;" class="rp-detail" style="color:var(--wp-green)">Details</a></td></tr>';
    }).join('') : '<tr><td colspan="5" class="wp-empty">No attacks in this window</td></tr>';
    h += '</tbody></table>';
    $('#rp-body').html(h);

    $('#rp-body').on('click', '.rp-bl', function () {
      var ip = $(this).closest('tr').data('ip');
      W.confirm('Add <b>' + esc(ip) + '</b> to the IP blacklist?', { icon: 3, title: 'Blacklist IP' }, function (i) {
        layer.close(i);
        post('list_add', { list_name: 'ip_black', value: ip }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        });
      });
    });
    $('#rp-body').on('click', '.rp-detail', function () {
      reportDetail($(this).closest('tr').data('ip'));
    });
  }

  function renderReportSearch() {
    var h = '<div style="display:flex;gap:8px;margin-bottom:12px">' +
      '<input class="wp-in" id="rp-q" placeholder="Search by IP or URI" style="flex:1" value="' + esc(S.rpQ || '') + '">' +
      '<span class="wp-btn primary" id="rp-search-go">Search</span></div>' +
      '<div id="rp-search-res"><div class="wp-empty">Enter an IP or URI and press Search.</div></div>';
    $('#rp-body').html(h);
    function go() {
      var q = ($('#rp-q').val() || '').trim(); if (!q) return;
      S.rpQ = q;
      $('#rp-search-res').html('<div class="wp-loading">Searching...</div>');
      post('report_search', $.extend(rpDateArgs(), { q: q }), function (rr) {
        if (!rr.status) { $('#rp-search-res').html('<div class="wp-note">' + esc(rr.msg) + '</div>'); return; }
        var rows = rr.data || [];
        var t = '<div style="color:var(--wp-text3);font-size:12px;margin-bottom:8px">' + rr.count + ' match(es)</div>' +
          '<table class="wp-tbl"><thead><tr><th style="width:150px">Time</th><th style="width:140px">IP</th>' +
          '<th>URI</th><th style="width:150px">Type</th><th style="width:60px">Code</th></tr></thead><tbody>' +
          (rows.length ? rows.map(function (x) {
            return '<tr><td>' + esc(fmtTime(x.time)) + '</td><td style="font-weight:600">' + esc(x.ip) + '</td>' +
              '<td class="ell" title="' + esc(x.uri) + '">' + esc(x.uri) + '</td>' +
              '<td>' + esc(x.name) + '</td><td>' + esc(String(x.status)) + '</td></tr>';
          }).join('') : '<tr><td colspan="5" class="wp-empty">No match</td></tr>') + '</tbody></table>';
        $('#rp-search-res').html(t);
      });
    }
    $('#rp-search-go').on('click', go);
    $('#rp-q').on('keydown', function (e) { if (e.keyCode === 13) go(); });
  }

  function reportDetail(ip) {
    post('report_ip_detail', $.extend(rpDateArgs(), { ip: ip }), function (r) {
      if (!r.status) { layer.msg(r.msg || 'error', { icon: 2 }); return; }
      var h = '<div class="wp-modal"><div class="wp-mod-head">' +
        '<div class="wp-mod-site">' + esc(ip) + '</div>' +
        '<div class="wp-mod-meta">' + esc(r.location) + ' · ' + (r.rows.length) + ' block(s) in this window</div></div>' +
        '<div class="wp-mod-body">';
      h += '<div class="wp-mod-sec"><div class="wp-mod-sec-t">By type</div>' +
        (r.breakdown || []).map(function (x) {
          return '<div style="display:flex;justify-content:space-between;padding:4px 0"><span>' + esc(x.name) +
            '</span><span style="font-weight:600">' + num(x.count) + '</span></div>';
        }).join('') + '</div>';
      h += '<div class="wp-mod-sec"><div class="wp-mod-sec-t">Recent blocks</div>' +
        '<table class="wp-tbl"><thead><tr><th style="width:140px">Time</th><th>URI</th>' +
        '<th style="width:140px">Type</th></tr></thead><tbody>' +
        (r.rows || []).map(function (x) {
          return '<tr><td>' + esc(fmtTime(x.time)) + '</td><td class="ell" title="' + esc(x.uri) + '">' + esc(x.uri) + '</td>' +
            '<td>' + esc(x.name) + '</td></tr>';
        }).join('') + '</tbody></table></div>';
      h += '</div><div class="wp-mod-foot">' +
        '<span class="wp-btn" id="rp-d-bl">Add to blacklist</span>' +
        '<span class="wp-btn primary" id="rp-d-close">Close</span></div></div>';
      var idx = W.open({ type: 1, title: false, closeBtn: 1, area: ['680px', '600px'], content: h });
      $('#rp-d-close').on('click', function () { layer.close(idx); });
      $('#rp-d-bl').on('click', function () {
        post('list_add', { list_name: 'ip_black', value: ip }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 }); if (rr.status) layer.close(idx);
        });
      });
    });
  }

  function ratioBar(pct) {
    pct = pct || 0;
    return '<div style="display:flex;align-items:center;gap:8px">' +
      '<div style="flex:1;height:8px;background:var(--wp-bg);border-radius:4px;overflow:hidden">' +
      '<i style="display:block;height:100%;width:' + Math.max(pct, 2) + '%;background:var(--wp-green)"></i></div>' +
      '<span style="width:46px;text-align:right;color:var(--wp-text2);font-size:12px">' + pct + '%</span></div>';
  }
  function fmtTime(t) {
    if (!t) return '-';
    var d = new Date(t * 1000);
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  // exports
  W.RP_COLORS = RP_COLORS;
  W.drawReportDonut = drawReportDonut;
  W.fmtTime = fmtTime;
  W.loadReport = loadReport;
  W.pageReport = pageReport;
  W.ratioBar = ratioBar;
  W.renderLeaderboard = renderLeaderboard;
  W.renderReport = renderReport;
  W.renderReportBody = renderReportBody;
  W.renderReportSearch = renderReportSearch;
  W.reportDetail = reportDetail;
  W.rpDateArgs = rpDateArgs;
})(window.WAFPRO = window.WAFPRO || {});
