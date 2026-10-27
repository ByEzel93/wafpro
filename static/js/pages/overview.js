(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function dayStr() { return W.dayStr.apply(this, arguments); }
  function ec() { return W.ec.apply(this, arguments); }
  function ensureEcharts() { return W.ensureEcharts.apply(this, arguments); }
  function esc() { return W.esc.apply(this, arguments); }
  function mb() { return W.mb.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function renderTabs() { return W.renderTabs.apply(this, arguments); }
  function pickDate() { return W.pickDate.apply(this, arguments); }
  function icoCalendar() { return W.icoCalendar.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }
  function todayStr() { return W.todayStr.apply(this, arguments); }

  /* ================= OVERVIEW (aaPanel 8 dashboard layout) =================
     toolbar · [security overview + real-time stack | trends + map]
     · hourly / client / status codes · referrer / traffic / pages TOP10
     · block types + latest block events */
  var REFRESH = 60;     // seconds between automatic reloads of the page data
  var PALETTE = ['#20a53a', '#3b82f6', '#f59e0b', '#ef5350', '#8b5cf6', '#14b8a6', '#ec4899', '#64748b', '#a3e635', '#0ea5e9'];
  var STATUS_COLORS = { '2': '#20a53a', '3': '#3b82f6', '4': '#f59e0b', '5': '#ef5350' };

  function card(title, body, opt) {
    opt = opt || {};
    return '<section class="ov-card' + (opt.cls ? ' ' + opt.cls : '') + '"><header class="ov-card-h">' +
      '<span class="ov-card-t">' + title + '</span><span class="ov-card-x">' + (opt.extra || '') + '</span></header>' +
      '<div class="ov-card-b">' + body + '</div></section>';
  }
  function delta(cur, prev) {
    if (!prev) return '<span class="ov-delta neutral">--</span>';
    var p = (cur / prev - 1) * 100;
    if (Math.abs(p) < 0.005) return '<span class="ov-delta neutral">0.00%</span>';
    return '<span class="ov-delta ' + (p > 0 ? 'up' : 'down') + '">' + (p > 0 ? '↑' : '↓') + ' ' + Math.abs(p).toFixed(2) + '%</span>';
  }
  function hms() {
    var d = new Date(), p = function (x) { return (x < 10 ? '0' : '') + x; };
    return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function pageOverview() {
    // also called by the refresh countdown itself, not only through route()
    if (S.timer) { clearInterval(S.timer); S.timer = null; }
    S.gen++;
    $('#wp-body').html('<div class="wp-loading">Loading dashboard...</div>');
    post('overview', { date: S.ovDate || '' }, function (d) {
      if (!d.status) { $('#wp-body').html('<div class="wp-note">' + esc(d.msg || 'Failed to load') + '</div>'); return; }
      S.ovData = d;
      var c = d.cards || {}, eng = d.engine || {};
      var h = '<div class="ov">';

      /* ---- toolbar: time filter + auto refresh ---- */
      var named = S.range !== 'day';
      h += '<div class="ov-toolbar"><div class="ov-tf"><span class="ov-tf-l">Time filter</span>' +
        '<div class="wp-seg-btn" id="ov-range"><span class="' + (S.range === 'yesterday' ? 'on' : '') + '" data-r="yesterday">Yesterday</span>' +
        '<span class="' + (S.range === 'today' || !S.range ? 'on' : '') + '" data-r="today">Today</span></div>' +
        '<span class="wp-btn wp-bl-pick ov-date' + (named ? '' : ' on') + '" id="ov-date">' + icoCalendar() +
        (named ? 'Select date' : esc(S.ovDate)) + '</span></div>' +
        '<div class="ov-refresh"><span>Last updated <strong id="ov-upd">' + hms() + '</strong></span>' +
        '<span class="ov-ring" id="ov-ring" title="Refresh now"><svg viewBox="0 0 36 36"><circle cx="18" cy="18" r="15"/>' +
        '<circle class="p" id="ov-ring-p" cx="18" cy="18" r="15"/></svg></span>' +
        '<span>Automatically refresh every ' + REFRESH + ' seconds</span></div></div>';

      if (!eng.wired) {
        h += '<div class="ov-alert"><b>WAF protection is disabled</b><span>The WAF Pro engine is not wired into nginx, so your websites ' +
          'are not protected yet.</span><span class="wp-btn primary" id="ov-wire">Enable protection now</span></div>';
      }

      /* ---- primary layout ---- */
      h += '<div class="ov-primary"><aside class="ov-rail">';
      h += card("Today's security overview",
        '<div class="ov-sec"><div class="ov-metric"><span class="ov-lbl">Request</span><strong class="ov-num">' + num(c.today_request) + '</strong>' +
        '<span class="ov-meta">' + delta(c.today_request, c.yesterday_request) + '<span>Yesterday ' + num(c.yesterday_request) + '</span></span></div>' +
        '<div class="ov-metric danger"><span class="ov-lbl">Malicious request</span><strong class="ov-num">' + num(c.malicious_request) + '</strong>' +
        '<span class="ov-meta">' + delta(c.malicious_request, c.yesterday_malicious) + '<span>Yesterday ' + num(c.yesterday_malicious) + '</span></span></div></div>',
        { cls: 'ov-overview', extra: '<span class="ov-live"><i></i>' + (eng.wired ? 'Protection active' : 'Protection off') + '</span>' });
      h += card('Real-time operation',
        ['qps', 'bw', 'rt'].map(function (k) {
          var n = { qps: ['Real-time QPS', '#20a53a'], bw: ['Real-time website traffic', '#3b82f6'], rt: ['Real-time origin latency', '#f59e0b'] }[k];
          return '<div class="ov-rt"><div class="ov-rt-h"><span class="ov-rt-n"><i style="background:' + n[1] + '"></i>' + n[0] + '</span>' +
            '<span class="ov-rt-c" id="ov-rt-' + k + '-v"><strong>0</strong></span></div><div class="ov-rt-chart" id="ov-rt-' + k + '"></div></div>';
        }).join(''), { cls: 'ov-stack', extra: '<span class="ov-live">Last 5 minutes · 10-second granularity</span>' });
      h += '</aside><div class="ov-stage">';
      h += card('Request and traffic trends', '<div class="ov-trend" id="ov-trend"></div>',
        { cls: 'ov-trendcard', extra: '<span class="ov-chip">Unique IP ' + num(c.today_ips) + '</span><span class="ov-chip">Traffic ' + mb(c.today_bytes) + '</span>' });
      h += card('Access/Block Map',
        '<div class="ov-map-sum"><span class="ov-ms"><span>Requests</span><b>' + num(c.today_request) + '</b></span>' +
        '<span class="ov-ms"><span>Blocks</span><b>' + num(c.malicious_request) + '</b></span>' +
        '<span class="ov-ms"><span>IP count</span><b>' + num(c.today_ips) + '</b></span></div>' +
        '<div class="ov-map-c"><div class="ov-map-p"><div class="ov-map-ctl"><div class="wp-seg-btn" id="ov-map-mode">' +
        '<span data-m="requests">Requests</span><span data-m="blocks">Blocks</span></div></div><div class="ov-map" id="ov-map"></div></div>' +
        '<div class="ov-rank"><div class="ov-rank-t"><span>Source ranking</span><span class="ov-rank-n">TOP 10</span></div>' +
        '<div class="ov-rank-tbl" id="ov-src"></div></div></div>',
        { cls: 'ov-mapcard', extra: '<span class="ov-live">Data uses top 10k records · updates every 60 seconds</span>' +
          '<span class="wp-lnk ov-go" data-to="report" style="margin-left:12px">Today\'s Block report &gt;&gt;</span>' });
      h += '</div></div>';

      /* ---- detail row ---- */
      var hourTotal = (d.chart && d.chart.traffic_mb || []).reduce(function (a, b) { return a + b; }, 0);
      h += '<div class="ov-row">';
      h += card('Hourly traffic trend', '<div class="ov-chart" id="ov-hourly"></div>',
        { cls: 'ov-detail', extra: '<span class="ov-cmeta">Total ' + mb(hourTotal * 1048576) + '</span>' });
      h += card('Client distribution', '<div class="ov-dist"><div><h3>Browser / client</h3><div id="ov-br"></div></div>' +
        '<div><h3>Operating system</h3><div id="ov-os"></div></div></div>',
        { cls: 'ov-detail', extra: '<span class="wp-lnk" id="ov-client-more">More</span>' });
      h += card('Status code distribution', '<div class="ov-status"><div class="ov-status-l" id="ov-st-l"></div>' +
        '<div class="ov-status-t" id="ov-st-t"></div></div>', { cls: 'ov-detail', extra: '<span class="ov-cmeta">Sorted by request count</span>' });
      h += '</div>';

      /* ---- ranking row ---- */
      h += '<div class="ov-row">';
      h += card('Referrer TOP 10', '<ul class="ov-top" id="ov-ref"></ul>', { cls: 'ov-topcard', extra: '<span class="wp-lnk" id="ov-ref-more">More</span>' });
      h += card('Traffic ranking TOP 10', '<ul class="ov-top" id="ov-ipt"></ul>', { cls: 'ov-topcard', extra: '<span class="wp-lnk" id="ov-ipt-more">More</span>' });
      h += card('Visited pages TOP 10', '<ul class="ov-top" id="ov-url"></ul>', { cls: 'ov-topcard', extra: '<span class="wp-lnk" id="ov-url-more">More</span>' });
      h += '</div>';

      /* ---- interception row ---- */
      h += '<div class="ov-row ov-int">';
      h += card('Block type', '<div class="ov-bt"><div class="ov-bt-chart"><div id="ov-bt" style="width:100%;height:100%"></div>' +
        '<div class="ov-bt-core"><span>Today\'s blocks</span><strong>' + num(c.malicious_request) + '</strong>' +
        '<span class="ov-bt-st' + (eng.wired ? '' : ' off') + '"><i></i>' + (eng.wired ? 'Protection active' : 'WAF protection is disabled') + '</span></div></div>' +
        '<div class="ov-bt-legend"><div class="ov-bt-head"><span>Block type</span><span>Blocks</span></div><ul id="ov-bt-l"></ul></div></div>',
        { cls: 'ov-btcard' });
      h += card('Latest block events', '<div class="ov-events" id="ov-ev"></div>', { cls: 'ov-evcard' });
      h += '</div></div>';

      $('#wp-body').html(h);
      fillOverview(d);
      bindOverview();
      ensureEcharts(function () {
        drawTrend(d); drawHourly(d); drawBlockTypes(d);
        loadWorld(function () { drawMap(d); });
        startRealtime();
      });
    });
  }

  function bindOverview() {
    $('#ov-range span').on('click', function () {
      S.range = $(this).data('r');
      S.ovDate = S.range === 'yesterday' ? dayStr(-1) : '';
      pageOverview();
    });
    $('#ov-date').on('click', function () {
      pickDate(this, { value: S.ovDate || '', max: todayStr(), done: function (v) {
        S.ovDate = v === todayStr() ? '' : v;
        S.range = S.ovDate ? 'day' : 'today';
        pageOverview();
      } });
    });
    $('#ov-ring').on('click', pageOverview);
    $('.ov-go').on('click', function () { S.tab = $(this).data('to'); renderTabs(); route(); });
    $('#ov-wire').on('click', function () { S.tab = 'global'; renderTabs(); route(); });
    $('#ov-map-mode span').on('click', function () { S.mapMode = $(this).data('m'); drawMap(S.ovData); });
    $('#ov-client-more').on('click', clientMore);
    $('#ov-ref-more').on('click', function () {
      moreTable('Referrer Top 50', ['Referrer', 'Visits'], (S.ovData.referrers || []).map(function (x) { return [esc(x[0]), num(x[1])]; }));
    });
    $('#ov-ipt-more').on('click', function () {
      moreTable('Traffic ranking TOP100', ['Domain', 'IP', 'Visits', 'Traffic', 'Static requests', 'Static traffic'],
        (S.ovData.ip_traffic || []).map(function (x) {
          return [esc(x.site), esc(x.ip), num(x.count), mb(x.bytes), num(x.static), mb(x.static_bytes)];
        }));
    });
    $('#ov-url-more').on('click', function () {
      moreTable('Visited pages TOP100', ['Domain', 'URL', 'Visits', 'Traffic', 'Static requests', 'Static traffic'],
        (S.ovData.url_traffic || []).map(function (x) {
          return [esc(x.site), esc(x.url), num(x.count), mb(x.bytes), num(x.static), mb(x.static_bytes)];
        }));
    });
  }

  function moreTable(title, cols, rows) {
    W.open({
      type: 1, title: title, area: ['860px', 'auto'],
      content: '<div class="wp-g-dlg"><div class="ov-more"><table class="wp-site-tbl ov-more-t"><thead><tr>' +
        cols.map(function (c, i) { return '<th' + (i > 1 || cols.length === 2 && i ? ' class="r"' : '') + '>' + c + '</th>'; }).join('') +
        '</tr></thead><tbody>' + (rows.length ? rows.map(function (r) {
          return '<tr>' + r.map(function (v, i) { return '<td' + (i > 1 || r.length === 2 && i ? ' class="r"' : ' class="ell"') + '>' + v + '</td>'; }).join('') + '</tr>';
        }).join('') : '<tr><td colspan="' + cols.length + '" class="wp-empty">No Data</td></tr>') + '</tbody></table></div></div>'
    });
  }
  function clientMore() {
    var d = S.ovData;
    function tbl(list) {
      var tot = list.reduce(function (a, x) { return a + x[1]; }, 0) || 1;
      return '<table class="wp-site-tbl ov-more-t"><thead><tr><th>Name</th><th class="r">Visits</th><th class="r">Percentage</th></tr></thead><tbody>' +
        (list.length ? list.map(function (x) {
          return '<tr><td>' + esc(x[0]) + '</td><td class="r">' + num(x[1]) + '</td><td class="r">' + (x[1] / tot * 100).toFixed(1) + '%</td></tr>';
        }).join('') : '<tr><td colspan="3" class="wp-empty">No Data</td></tr>') + '</tbody></table>';
    }
    W.open({
      type: 1, title: 'Client distribution details', area: ['760px', 'auto'],
      content: '<div class="wp-g-dlg ov-client"><div><h3>Browser / client</h3>' + tbl(d.browsers || []) + '</div>' +
        '<div><h3>Operating system</h3>' + tbl(d.oses || []) + '</div></div>'
    });
  }

  /* ---- bars / lists ---- */
  function bars(list, max) {
    if (!list.length) return '<div class="ov-empty">No Data</div>';
    var tot = list.reduce(function (a, x) { return a + x[1]; }, 0) || 1;
    return list.slice(0, max || 6).map(function (x, i) {
      return '<div class="ov-bar"><div class="ov-bar-m"><span>' + esc(x[0]) + '</span><span>' + num(x[1]) + ' · ' +
        (x[1] / tot * 100).toFixed(1) + '%</span></div><div class="ov-bar-t"><i class="l' + Math.min(i + 1, 6) + '" style="width:' +
        Math.max(x[1] / list[0][1] * 100, 2) + '%"></i></div></div>';
    }).join('');
  }
  function topList(sel, items) {
    if (!items.length) { $(sel).html('<li class="ov-empty">No Data</li>'); return; }
    var max = items[0].v || 1;
    $(sel).html(items.slice(0, 10).map(function (x, i) {
      return '<li class="ov-top-r" style="--w:' + Math.max(x.v / max * 100, 2) + '%"><span class="ov-no' + (i < 3 ? ' top' : '') + '">' + (i + 1) + '</span>' +
        '<span class="ov-top-n" title="' + esc(x.n) + '">' + esc(x.n) + '</span><span class="ov-top-v">' + (x.f || num(x.v)) + '</span></li>';
    }).join(''));
  }

  function fillOverview(d) {
    $('#ov-br').html(bars(d.browsers || []));
    $('#ov-os').html(bars(d.oses || []));

    // status codes: coloured bars by class + a small table
    var st = d.status_codes || [], stTot = st.reduce(function (a, x) { return a + x[1]; }, 0) || 1;
    $('#ov-st-l').html(st.length ? st.slice(0, 5).map(function (x) {
      var col = STATUS_COLORS[String(x[0]).charAt(0)] || '#64748b';
      return '<div class="ov-sbar" style="--c:' + col + '"><div class="ov-sbar-m"><span><i></i>' + esc(x[0]) + '</span><span>' +
        (x[1] / stTot * 100).toFixed(1) + '%</span></div><div class="ov-bar-t"><i style="width:' + Math.max(x[1] / stTot * 100, 2) + '%;background:' + col + '"></i></div></div>';
    }).join('') : '<div class="ov-empty">No Data</div>');
    $('#ov-st-t').html('<table class="ov-mini"><thead><tr><th>Status code</th><th class="r">Requests</th><th class="r">Percentage</th></tr></thead><tbody>' +
      (st.length ? st.slice(0, 7).map(function (x) {
        return '<tr><td>' + esc(x[0]) + '</td><td class="r">' + num(x[1]) + '</td><td class="r">' + (x[1] / stTot * 100).toFixed(1) + '%</td></tr>';
      }).join('') : '<tr><td colspan="3" class="ov-empty">No Data</td></tr>') + '</tbody></table>');

    topList('#ov-ref', (d.referrers || []).map(function (x) { return { n: x[0], v: x[1] }; }));
    topList('#ov-ipt', (d.ip_traffic || []).map(function (x) { return { n: x.ip, v: x.bytes, f: mb(x.bytes) }; }));
    topList('#ov-url', (d.url_traffic || []).map(function (x) { return { n: x.url, v: x.count }; }));

    // latest block events
    var ev = d.recent_attacks || [];
    S.ovEv = ev;
    $('#ov-ev').html('<table class="wp-site-tbl"><thead><tr><th>Time</th><th>IP address</th><th>Domain</th><th>Attack type</th><th>URL</th>' +
      '<th class="r">Operate</th></tr></thead><tbody>' + (ev.length ? ev.slice(0, 20).map(function (x, i) {
        return '<tr><td>' + esc(x.time) + '</td><td>' + esc(x.ip) + '</td><td class="ell">' + esc(x.site) + '</td>' +
          '<td class="ell">' + esc(ruleLabel(x.type)) + '</td><td class="ell" style="max-width:280px" title="' + esc(x.url) + '">' + esc(x.url) + '</td>' +
          '<td class="wp-ops"><span class="wp-lnk ov-ev-ip" data-i="' + i + '">Block IP</span><span class="wp-ops-sep">|</span>' +
          '<span class="wp-lnk ov-ev-url" data-i="' + i + '">White URL</span><span class="wp-ops-sep">|</span>' +
          '<span class="wp-lnk ov-ev-det" data-i="' + i + '">Details</span></td></tr>';
      }).join('') : '<tr><td colspan="6" class="wp-empty">No Data</td></tr>') + '</tbody></table>');
    $('.ov-ev-ip').on('click', function () { W.blockIp(S.ovEv[$(this).data('i')].ip); });
    $('.ov-ev-url').on('click', function () { W.whiteUrl(esc(S.ovEv[$(this).data('i')].url)); });
    $('.ov-ev-det').on('click', function () {
      var x = S.ovEv[$(this).data('i')];
      W.interceptDetail({ time: esc(x.time), ip: esc(x.ip), location: esc(x.country || 'Unknown'), method: esc(x.method),
        filter_name: esc(ruleLabel(x.type)), url: esc(x.url), rx: esc(x.rx || ''), rule: esc(x.payload || ''),
        type: esc(x.type), ua: esc(x.ua) });
    });

    // source ranking: requests or blocks, depending on the map mode
    srcRank(d);
  }

  function srcRank(d) {
    var blocks = S.mapMode === 'blocks';
    var list = blocks ? (d.top_attack_ips || []) : (d.top_request_ips || []);
    var traffic = {};
    (d.ip_traffic || []).forEach(function (x) { traffic[x.ip] = x.bytes; });
    var max = list.length ? list[0].count : 1;
    $('#ov-src').html('<table class="ov-mini ov-srct"><thead><tr><th>Req IP</th><th class="r">' + (blocks ? 'Blocks' : 'Requests') + '</th>' +
      '<th class="r">Traffic</th><th>IP attribution</th></tr></thead><tbody>' + (list.length ? list.slice(0, 10).map(function (x) {
        return '<tr><td class="ell" style="max-width:130px"><span class="ov-iplink">' + esc(x.ip) + '</span></td>' +
          '<td class="r"><span class="ov-cnt"><i style="width:' + Math.max(x.count / max * 100, 3) + '%"></i>' + num(x.count) + '</span></td>' +
          '<td class="r">' + (traffic[x.ip] ? mb(traffic[x.ip]) : '-') + '</td>' +
          '<td class="ell" style="max-width:120px">' + esc(x.country ? x.country + (x.city ? ' / ' + x.city : '') : 'Unknown') + '</td></tr>';
      }).join('') : '<tr><td colspan="4" class="ov-empty">No Data</td></tr>') + '</tbody></table>');
  }

  /* ---- charts ---- */
  var AX = { axisLine: { lineStyle: { color: '#e5e7eb' } }, axisTick: { show: false }, axisLabel: { color: '#94a3b8', fontSize: 10 } };
  var SPLIT = { lineStyle: { color: '#f1f5f9', type: 'dashed' } };
  function drawTrend(d) {
    var ch = d.chart || {};
    ec('ov-trend', {
      tooltip: { trigger: 'axis' },
      legend: { right: 0, top: 0, icon: 'circle', itemWidth: 7, itemHeight: 7, textStyle: { fontSize: 11, color: '#64748b' },
        data: ['Total requests', 'After filtering', 'Traffic', 'IP count'] },
      grid: { left: 44, right: 56, top: 28, bottom: 20 },
      xAxis: $.extend({ type: 'category', data: ch.hours || [], boundaryGap: false }, AX),
      yAxis: [$.extend({ type: 'value', splitLine: SPLIT }, AX, { axisLine: { show: false } }),
        $.extend({ type: 'value', splitLine: { show: false } }, AX, { axisLine: { show: false }, axisLabel: { color: '#94a3b8', fontSize: 10, formatter: '{value} MB' } })],
      series: [
        { name: 'Total requests', type: 'line', smooth: true, symbol: 'none', data: ch.total || [], color: '#20a53a', lineStyle: { width: 2 },
          areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(32,165,58,.18)' }, { offset: 1, color: 'rgba(32,165,58,0)' }]) } },
        { name: 'After filtering', type: 'line', smooth: true, symbol: 'none', data: ch.after_filter || [], color: '#3b82f6', lineStyle: { width: 1.5 } },
        { name: 'Traffic', type: 'line', smooth: true, symbol: 'none', yAxisIndex: 1, data: ch.traffic_mb || [], color: '#f59e0b', lineStyle: { width: 1.5 } },
        { name: 'IP count', type: 'line', smooth: true, symbol: 'none', data: ch.ips || [], color: '#8b5cf6', lineStyle: { width: 1.5 } }
      ]
    });
  }
  function drawHourly(d) {
    var ch = d.chart || {};
    ec('ov-hourly', {
      tooltip: { trigger: 'axis', valueFormatter: function (v) { return v + ' MB'; } },
      grid: { left: 64, right: 10, top: 12, bottom: 22 },
      xAxis: $.extend({ type: 'category', data: (ch.hours || []).map(function (x) { return x.slice(0, 2); }) }, AX),
      yAxis: $.extend({ type: 'value', splitLine: SPLIT }, AX, { axisLine: { show: false }, axisLabel: { color: '#94a3b8', fontSize: 10, formatter: '{value} MB' } }),
      series: [{ name: 'Traffic', type: 'bar', barMaxWidth: 12, data: ch.traffic_mb || [],
        itemStyle: { borderRadius: [3, 3, 0, 0], color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: '#3fc160' }, { offset: 1, color: 'rgba(32,165,58,.35)' }]) } }]
    });
  }
  function drawBlockTypes(d) {
    var by = d.by_rule || {};
    var items = Object.keys(by).map(function (k) { return { name: ruleLabel(k), value: by[k] }; })
      .sort(function (a, b) { return b.value - a.value; });
    var tot = items.reduce(function (a, x) { return a + x.value; }, 0) || 1;
    $('#ov-bt-l').html(items.length ? items.map(function (x, i) {
      var col = PALETTE[i % PALETTE.length];
      return '<li style="--c:' + col + '"><span class="n"><i></i><span>' + esc(x.name) + '</span></span>' +
        '<span class="v"><strong>' + num(x.value) + '</strong><small>' + Math.round(x.value / tot * 100) + '%</small></span></li>';
    }).join('') : '<li class="ov-empty">No Data</li>');
    ec('ov-bt', {
      color: PALETTE,
      tooltip: { trigger: 'item', formatter: function (p) { return esc(p.name) + '<br>' + num(p.value) + ' times, ' + p.percent + '%'; } },
      series: [{ type: 'pie', radius: ['76%', '94%'], label: { show: false }, labelLine: { show: false },
        data: items.length ? items : [{ name: 'None', value: 0, itemStyle: { color: '#eef1f4' } }], silent: !items.length }]
    });
  }

  /* ---- world map ---- */
  function loadWorld(cb) {
    if (typeof echarts === 'undefined') return cb();
    if (echarts.getMap && echarts.getMap('world')) return cb();
    // the panel already ships the world geojson — no external CDN needed
    $.getJSON('/static/vite/data/world.json').done(function (geo) {
      try { echarts.registerMap('world', geo); } catch (e) {}
      cb();
    }).fail(function () { cb(); });
  }
  function drawMap(d) {
    if (!S.mapMode) S.mapMode = (d.attack_map && d.attack_map.length) ? 'blocks' : 'requests';
    $('#ov-map-mode span').removeClass('on').filter('[data-m="' + S.mapMode + '"]').addClass('on');
    srcRank(d);
    var blocks = S.mapMode === 'blocks';
    var pts = (blocks ? d.attack_map : d.request_map) || [];
    var el = document.getElementById('ov-map');
    if (!el) return;
    if (typeof echarts === 'undefined' || !echarts.getMap || !echarts.getMap('world')) {
      el.innerHTML = '<div class="ov-empty">World map data unavailable</div>';
      return;
    }
    var max = Math.max.apply(null, pts.map(function (p) { return p.count; }).concat([1]));
    var color = blocks ? '#ef5350' : '#20a53a';
    ec('ov-map', {
      tooltip: { trigger: 'item', formatter: function (p) {
        if (!p.data || !p.data.meta) return p.name || '';
        var m = p.data.meta;
        return esc(m.country || 'Unknown') + (m.city ? ' / ' + esc(m.city) : '') + '<br/>' + (blocks ? 'Blocks: ' : 'Requests: ') + num(m.count);
      } },
      geo: { map: 'world', roam: true, zoom: 1.15, center: [10, 22],
        itemStyle: { areaColor: '#eef1f4', borderColor: '#dde3e8' },
        emphasis: { itemStyle: { areaColor: '#e3ece5' }, label: { show: false } } },
      series: [{
        type: 'effectScatter', coordinateSystem: 'geo', rippleEffect: { brushType: 'stroke', scale: 2.6 },
        symbolSize: function (v) { return Math.max(6, Math.min(18, 6 + (v[2] / max) * 12)); },
        itemStyle: { color: color },
        data: pts.map(function (p) { return { name: p.country || '', value: [p.lon, p.lat, p.count], meta: p }; })
      }]
    });
  }

  /* ---- real-time stack + auto refresh ---- */
  function rtOpt(points, color) {
    return {
      tooltip: { trigger: 'axis' },
      grid: { left: 38, right: 6, top: 6, bottom: 18 },
      xAxis: $.extend({ type: 'category', boundaryGap: false, data: points.map(function (x) { return x.t; }) }, AX,
        { axisLabel: { color: '#94a3b8', fontSize: 9, interval: 'auto' } }),
      yAxis: $.extend({ type: 'value', splitLine: SPLIT, minInterval: 1 }, AX, { axisLine: { show: false }, axisLabel: { color: '#94a3b8', fontSize: 9 } }),
      series: [{ type: 'line', smooth: true, symbol: 'none', data: points.map(function (x) { return x.v; }), color: color, lineStyle: { width: 1.6 },
        areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: color + '33' }, { offset: 1, color: color + '00' }]) } }]
    };
  }
  function startRealtime() {
    var left = REFRESH;
    function tick() {
      post('realtime', {}, function (r) {
        if (!r.status || !r.qps) return;
        var q = r.qps;
        $('#ov-rt-qps-v').html('<strong>' + (q.now || 0) + '</strong>req/s');
        ec('ov-rt-qps', rtOpt(q.points || [], '#20a53a'));
        $('#ov-rt-bw-v').html('<strong>' + mb(q.bw_now || 0).replace(' ', '</strong>') + '/s');
        ec('ov-rt-bw', rtOpt((q.bw_points || []).map(function (x) { return { t: x.t, v: Math.round(x.v / 1024) }; }), '#3b82f6'));
        if (q.rt_tracked) {
          $('#ov-rt-rt-v').html('<strong>' + (q.rt_now || 0) + '</strong>ms');
          ec('ov-rt-rt', rtOpt(q.rt_points || [], '#f59e0b'));
        } else if (!$('#ov-rt-en').length) {
          $('#ov-rt-rt-v').html('<strong>--</strong>');
          $('#ov-rt-rt').html('<div class="ov-rt-off">Nginx does not log the origin latency by default. ' +
            '<span class="wp-lnk" id="ov-rt-en">Enable tracking</span></div>');
          $('#ov-rt-en').on('click', enableRt);
        }
      });
    }
    tick();
    var n = 0;
    var me = S.timer = setInterval(function () {
      // stop once this page is gone: another tab, or the plugin was closed
      // or reopened (a reopen loads a fresh copy of every module)
      if (W.S !== S || S.tab !== 'overview' || !document.getElementById('ov-ring-p')) {
        clearInterval(me);
        if (S.timer === me) S.timer = null;
        return;
      }
      n++; left--;
      $('#ov-ring-p').css('stroke-dashoffset', (94.25 * (1 - left / REFRESH)).toFixed(2));
      if (n % 10 === 0) tick();
      if (left <= 0) { left = REFRESH; pageOverview(); }
    }, 1000);
  }
  function enableRt() {
    W.confirm('Add the origin-response field to your nginx access logs?<br><br>' +
      'This edits nginx.conf and the site configs (both are backed up, nginx is ' +
      'syntax-checked and rolled back automatically if anything fails).',
      { title: 'Enable origin response tracking' }, function (i) {
        layer.close(i);
        var ld = layer.msg('Applying...', { icon: 16, time: 0, shade: 0.3 });
        post('enable_rt', {}, function (rr) {
          layer.close(ld);
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2, time: 5000 });
        });
      });
  }

  /* The engine logs rule ids ('get', 'upload-ext', 'region:pass'); nobody
     reads those as attack types, so map them to what actually happened. */
  var RULE_LABELS = {
    'get': 'SQL/XSS in query', 'post': 'SQL/XSS in body', 'cookie': 'Cookie attack',
    'user-agent': 'Scanner', 'scan': 'Sensitive path probe', 'cc': 'CC flood',
    'cc-blocked': 'CC flood', 'banned': 'Auto-banned IP', 'ip-black': 'IP blacklist',
    'url-black': 'URL blacklist', 'deny-ext': 'Forbidden file', 'upload-ext': 'Webshell upload',
    'php-path': 'PHP in upload dir', 'method': 'Bad HTTP method', 'header': 'Oversized header',
    'region:intercept': 'Region blocked', 'region:pass': 'Region not allowed',
    'ua-black': 'UA blacklist', 'url-keyword': 'URL keyword', 'http-package': 'Oversized body',
    'deny-path': 'Forbidden URL', 'hotlink': 'Anti-leech', 'protected-url': 'Protected URL',
    'api': 'API defense', 'php2shell': 'PHP2Shell guard', 'form-data': 'Malformed form-data',
    'challenge': 'Browser verification', 'malicious-ip': 'Malicious IP feed', 'nday': 'Known exploit (N-day)',
    'idc': 'Datacenter (IDC) IP', 'url-cc': 'URL CC defense', 'url-method': 'URL request type',
    'sqli': 'SQL injection', 'xss': 'XSS', 'cmdi': 'Command execution', 'lfi': 'File access / traversal',
    'weak-password': 'Weak password', 'dir-scan': 'Directory scan',
    'fake-spider': 'Fake spider', 'smart-cc': 'Smart CC', 'crawl': 'Crawl limit',
    'waiting-room': 'Waiting room', 'sensitive': 'Sensitive word', 'traffic': 'Traffic limit',
    'traffic-block': 'Traffic limit (block)', 'custom': 'Custom rule'
  };
  // custom:<id> and similar carry a suffix; region:* keeps its own labels
  function ruleLabel(k) { return RULE_LABELS[k] || RULE_LABELS[String(k).split(':')[0]] || k; }

  // exports
  W.RULE_LABELS = RULE_LABELS;
  W.drawMap = drawMap;
  W.fillOverview = fillOverview;
  W.loadWorld = loadWorld;
  W.pageOverview = pageOverview;
  W.ruleLabel = ruleLabel;
})(window.WAFPRO = window.WAFPRO || {});
