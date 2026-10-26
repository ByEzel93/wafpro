(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function dayStr() { return W.dayStr.apply(this, arguments); }
  function ec() { return W.ec.apply(this, arguments); }
  function ensureEcharts() { return W.ensureEcharts.apply(this, arguments); }
  function esc() { return W.esc.apply(this, arguments); }
  function icoChart() { return W.icoChart.apply(this, arguments); }
  function icoClock() { return W.icoClock.apply(this, arguments); }
  function icoDoc() { return W.icoDoc.apply(this, arguments); }
  function icoFilter() { return W.icoFilter.apply(this, arguments); }
  function icoGlobe() { return W.icoGlobe.apply(this, arguments); }
  function icoPie() { return W.icoPie.apply(this, arguments); }
  function icoPulse() { return W.icoPulse.apply(this, arguments); }
  function icoWarn() { return W.icoWarn.apply(this, arguments); }
  function mb() { return W.mb.apply(this, arguments); }
  function num() { return W.num.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function renderTabs() { return W.renderTabs.apply(this, arguments); }
  function pickDate() { return W.pickDate.apply(this, arguments); }
  function icoCalendar() { return W.icoCalendar.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }
  function svgBugBg() { return W.svgBugBg.apply(this, arguments); }
  function svgShieldBg() { return W.svgShieldBg.apply(this, arguments); }
  function todayStr() { return W.todayStr.apply(this, arguments); }

  /* ================= OVERVIEW ================= */
  function pageOverview() {
    $('#wp-body').html('<div class="wp-loading">Loading dashboard...</div>');
    post('overview', { date: S.ovDate || '' }, function (d) {
      if (d.engine_installed === false) {
        $('#wp-body').html('<div class="wp-note">The WAF Pro engine files are missing from /www/server/wafpro. ' +
          'Reinstall the plugin (App Store &rsaquo; WAF Pro &rsaquo; Repair/Update).</div>');
        return;
      }
      if (!d.status) { $('#wp-body').html('<div class="wp-note">' + esc(d.msg || 'Failed to load') + '</div>'); return; }
      var c = d.cards || {};
      var h = '';

      /* ---- Pro layout: narrow left column, wide right column ---- */
      h += '<div class="wp-row wp-main-grid">';

      // ---- LEFT column ----
      h += '<div class="wp-col">';
      h += '<div class="wp-daterow">' +
        '<div class="wp-seg" id="wp-range"><span class="' + (S.range === 'yesterday' ? 'on' : '') + '" data-r="yesterday">Yesterday</span>' +
        '<span class="' + (S.range === 'today' ? 'on' : '') + '" data-r="today">Today</span>' +
        '<span class="wp-date' + (S.range === 'day' ? ' on' : '') + '" id="wp-ov-date">' +
          (S.range === 'day' && S.ovDate ? esc(S.ovDate) : 'Select Date') + icoCalendar() + '</span></div>' +
        '<span class="wp-count" title="Blocked on the selected day">' + num(c.malicious_request) + '</span>' +
        '<span class="wp-btn wp-ref" id="wp-refresh" title="Refresh">&#8635;</span></div>';
      h += '<div class="wp-stat-2">' +
        statCard('Today request', c.today_request, c.today_request_pct, 'Yesterday: ' + num(c.yesterday_request), false) +
        statCard('Malicious request', c.malicious_request, c.malicious_request_pct, 'Yesterday: ' + num(c.yesterday_malicious), true) +
        '</div>';
      h += '<div class="wp-card"><div class="wp-card-h">' + icoPulse() +
        '<span class="t" id="wp-qps-t">Real-time QPS: 0/s</span></div>' +
        '<div class="wp-chart sm" id="wp-qps-chart"></div></div>';
      h += '<div class="wp-card"><div class="wp-card-h">' + icoClock() +
        '<span class="t" id="wp-rt-t">Real-time origin response: 0ms</span></div>' +
        '<div id="wp-rt-holder"><div class="wp-chart sm" id="wp-rt-chart"></div></div></div>';
      // what kind of attacks are landing — the engine already counts this per
      // rule, and it is the first thing you want when a number spikes
      h += '<div class="wp-card"><div class="wp-card-h">' + icoPie() +
        '<span class="t">Intercept types</span></div>' +
        '<div id="wp-by-rule"></div></div>';
      h += '</div>';

      // ---- RIGHT column ----
      h += '<div class="wp-col">';
      h += '<div class="wp-card"><div class="wp-card-h">' + icoFilter() +
        '<span class="t">Traffic filtering request chart</span>' +
        '<span class="r"><span class="wp-chip">Unique IP: ' + num(c.today_ips) + '</span>' +
        '<span class="wp-chip">Traffic: ' + mb(c.today_bytes) + '</span></span></div>' +
        '<div class="wp-chart" id="wp-main-chart"></div></div>';
      // map card holds the map AND the attacker table, like the Pro UI
      h += '<div class="wp-card"><div class="wp-card-h">' + icoGlobe() +
        '<span class="t">Access / Block Map</span>' +
        '<span class="r"><span style="color:var(--wp-text3);font-size:12px">(*Only shows TOP coordinates)</span>' +
        '<div class="wp-seg" id="wp-map-mode">' +
        '<span data-m="requests">Requests</span><span class="on" data-m="blocks">Blocks</span></div>' +
        '<span class="wp-lnk" id="wp-to-report">Today&apos;s Block report &gt;&gt;</span></span></div>' +
        '<div class="wp-map-wrap">' +
        '<div><div class="wp-chart" style="height:320px" id="wp-map"></div>' +
        '<div class="wp-legend"><span>Low</span><i class="g1"></i><i class="g2"></i><i class="g3"></i><span>High</span></div></div>' +
        '<div class="wp-attack-side"><div class="wp-scroll" style="max-height:352px">' +
        '<table class="wp-tbl"><thead><tr><th>Attack IP</th><th style="width:76px">Times</th>' +
        '<th style="width:118px">IP attribution</th></tr></thead>' +
        '<tbody id="wp-attack-ips"></tbody></table></div></div>' +
        '</div></div>';
      h += '</div>';
      h += '</div>';

      // ---- bottom: the three TOP10 panels side by side, as in the stock dashboard ----
      h += '<div class="wp-row wp-top3">';
      h += '<div class="wp-card"><div class="wp-card-h">' + icoWarn() + '<span class="t">Attacked domains TOP10</span>' +
        '<span class="r"><span class="wp-lnk wp-more" data-to="blockade">More&gt;&gt;</span></span></div>' +
        '<div id="wp-top-domains"></div></div>';
      h += '<div class="wp-card"><div class="wp-card-h">' + icoChart() + '<span class="t">Traffic ranking TOP10</span>' +
        '<span class="wp-q" title="Bytes served per site today, from the nginx access logs">?</span>' +
        '<span class="r"><span class="wp-lnk wp-more" data-to="website">More&gt;&gt;</span></span></div>' +
        '<div id="wp-top-traffic"></div></div>';
      h += '<div class="wp-card"><div class="wp-card-h">' + icoDoc() + '<span class="t">Visited pages TOP10</span>' +
        '<span class="wp-q" title="Most requested paths today, from the nginx access logs">?</span>' +
        '<span class="r"><span class="wp-lnk wp-more" data-to="report">More&gt;&gt;</span></span></div>' +
        '<div id="wp-top-urls"></div></div>';
      h += '</div>';

      // ---- latest intercepts ----
      h += '<div class="wp-row" style="grid-template-columns:1fr">';
      h += '<div class="wp-card"><div class="wp-card-h">' + icoClock() + '<span class="t">Latest intercepts</span></div>' +
        '<div class="wp-scroll" style="max-height:200px"><table class="wp-tbl"><thead><tr>' +
        '<th style="width:150px">Time</th><th style="width:130px">IP</th><th style="width:120px">Country</th>' +
        '<th>URL</th><th style="width:100px">Type</th>' +
        '</tr></thead><tbody id="wp-recent"></tbody></table></div></div>';
      h += '</div>';

      $('#wp-body').html(h);
      fillOverview(d);

      $('#wp-refresh').on('click', pageOverview);
      $('#wp-ov-date').on('click', function () {
        pickDate(this, { value: S.ovDate || '', max: todayStr(), done: function (v) {
          S.ovDate = v === todayStr() ? '' : v;
          S.range = S.ovDate ? 'day' : 'today';
          pageOverview();
        } });
      });
      $('#wp-to-report, .wp-more').on('click', function () {
        S.tab = $(this).data('to') || 'report'; renderTabs(); route();
      });
      // only the date switch — the map has its own segmented control
      $('#wp-range span[data-r]').on('click', function () {
        S.range = $(this).data('r');
        S.ovDate = S.range === 'yesterday' ? dayStr(-1) : '';
        pageOverview();
      });

      $('#wp-map-mode span').on('click', function () {
        $('#wp-map-mode span').removeClass('on');
        $(this).addClass('on');
        S.mapMode = $(this).data('m');
        drawMap(d);
      });

      // default to whichever map mode actually has points to show
      if (!S.mapMode) {
        S.mapMode = (d.attack_map && d.attack_map.length) ? 'blocks' : 'requests';
        $('#wp-map-mode span').removeClass('on')
          .filter('[data-m="' + S.mapMode + '"]').addClass('on');
      }

      ensureEcharts(function () {
        drawMainChart(d);
        loadWorld(function () { drawMap(d); });
        startQps();
      });
    });
  }

  /* ---------- world map ---------- */
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
    var mode = S.mapMode || 'blocks';
    var pts = (mode === 'blocks' ? d.attack_map : d.request_map) || [];
    var countries = (mode === 'blocks' ? d.by_country : d.request_countries) || [];
    rankCountries(countries);

    var el = document.getElementById('wp-map');
    if (!el) return;
    if (typeof echarts === 'undefined' || !echarts.getMap || !echarts.getMap('world')) {
      el.innerHTML = '<div class="wp-empty">World map data unavailable</div>';
      return;
    }
    if (!pts.length) {
      el.innerHTML = '<div class="wp-empty">No ' + (mode === 'blocks' ? 'blocked' : 'request') + ' locations today</div>';
      return;
    }
    var max = Math.max.apply(null, pts.map(function (p) { return p.count; })) || 1;
    var color = mode === 'blocks' ? '#ef4d4d' : '#20a53a';
    ec('wp-map', {
      tooltip: {
        trigger: 'item',
        formatter: function (p) {
          if (!p.data || !p.data.meta) return p.name || '';
          var m = p.data.meta;
          return (m.country || 'Unknown') + (m.city ? ' / ' + m.city : '') +
            '<br/>' + (mode === 'blocks' ? 'Blocks: ' : 'Requests: ') + m.count;
        }
      },
      geo: {
        map: 'world', roam: true, zoom: 1.2, center: [10, 20],
        itemStyle: { areaColor: '#eef1f3', borderColor: '#dfe4e8' },
        emphasis: { itemStyle: { areaColor: '#e3ece5' }, label: { show: false } }
      },
      // numbered pins for the busiest spots (like the stock map), plain
      // dots for the long tail so the map does not turn into a carpet
      series: [{
        type: 'scatter', coordinateSystem: 'geo', zlevel: 3, symbol: 'pin',
        symbolSize: function (v) { return Math.max(30, Math.min(44, 30 + (v[2] / max) * 14)); },
        itemStyle: { color: mode === 'blocks' ? '#5864d6' : '#20a53a' },
        label: { show: true, color: '#fff', fontSize: 10, fontWeight: 600,
                 formatter: function (p) { return p.data.meta.count > 999 ? '999+' : p.data.meta.count; } },
        data: pts.slice(0, 5).map(function (p) {
          return { name: p.country || '', value: [p.lon, p.lat, p.count], meta: p };
        })
      }, {
        type: 'effectScatter', coordinateSystem: 'geo', zlevel: 2,
        rippleEffect: { brushType: 'stroke', scale: 2.5 },
        symbolSize: function (v) { return Math.max(5, Math.min(14, 5 + (v[2] / max) * 10)); },
        itemStyle: { color: color },
        data: pts.slice(5).map(function (p) {
          return { name: p.country || '', value: [p.lon, p.lat, p.count], meta: p };
        })
      }]
    });
  }

  function rankCountries(list) {
    // the country panel only exists in some layouts — skip quietly if absent
    if (!$('#wp-country-rank').length) return;
    if (!list.length) { $('#wp-country-rank').html('<div class="wp-empty">No data</div>'); return; }
    var max = Math.max.apply(null, list.map(function (x) { return x.count; })) || 1;
    $('#wp-country-rank').html(list.slice(0, 15).map(function (x, i) {
      return '<div class="wp-rank"><span class="n' + (i < 3 ? ' top' : '') + '">' + (i + 1) + '</span>' +
        '<span class="nm" style="flex:0 0 46px">' + esc(x.code || '??') + '</span>' +
        '<span class="tr"><i style="width:' + Math.max(x.count / max * 100, 2) + '%"></i></span>' +
        '<span class="v">' + num(x.count) + '</span></div>';
    }).join(''));
  }

  function statCard(label, val, pct, sub, isRed) {
    var cls = (pct > 0) ? 'up' : 'down';
    var arrow = (pct > 0) ? '&#8593;' : '&#8595;';
    return '<div class="wp-stat">' +
      '<div class="lbl"><span class="bar' + (isRed ? ' red' : '') + '"></span>' + label + '</div>' +
      '<div class="val" style="color:' + (isRed ? 'var(--wp-red)' : 'var(--wp-text)') + '">' + num(val) + '</div>' +
      '<div class="pct ' + cls + '">' + arrow + ' ' + Math.abs(pct || 0) + '%</div>' +
      '<div class="sub">' + sub + '</div>' +
      (isRed ? svgShieldBg() : svgBugBg()) + '</div>';
  }

  function fillOverview(d) {
    // attack IPs
    var ips = d.top_attack_ips || [];
    var recent = d.recent_attacks || [];
    var lastBy = {};
    recent.forEach(function (r) { if (!lastBy[r.ip]) lastBy[r.ip] = r; });
    $('#wp-attack-ips').html(ips.length ? ips.map(function (x) {
      var attr = x.country ? (x.country + (x.city ? ' / ' + x.city : '')) : 'Unknown';
      return '<tr><td class="ell" style="color:var(--wp-text);font-weight:600" title="' + esc(x.ip) + '">' + esc(x.ip) + '</td>' +
        '<td style="color:var(--wp-red);font-weight:600">' + x.count + '</td>' +
        '<td class="ell" title="' + esc(attr) + '">' + esc(attr) + '</td></tr>';
    }).join('') : '<tr><td colspan="3" class="wp-empty">No attacks recorded today</td></tr>');

    rank('#wp-top-domains', (d.attacked_domains || []).map(function (x) {
      return { name: x.domain, value: x.count };
    }), '');
    renderByRule(d.by_rule || {});
    rank('#wp-top-traffic', (d.top_domains_traffic || []).map(function (x) {
      return { name: x.domain, value: x.bytes, fmt: mb(x.bytes) };
    }), '');
    rank('#wp-top-urls', (d.top_urls || []).map(function (x) {
      return { name: x.url, value: x.count };
    }), '');

    $('#wp-recent').html(recent.length ? recent.slice(0, 20).map(function (r) {
      return '<tr><td>' + esc(r.time) + '</td><td>' + esc(r.ip) + '</td>' +
        '<td class="ell">' + esc(r.country || '-') + '</td>' +
        '<td class="ell" title="' + esc(r.url) + '">' + esc(r.url) + '</td>' +
        '<td><span class="wp-chip ' + esc(r.type) + '">' + esc(r.type) + '</span></td></tr>';
    }).join('') : '<tr><td colspan="5" class="wp-empty">No intercepts today</td></tr>');
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
    'idc': 'Datacenter (IDC) IP',
    'fake-spider': 'Fake spider', 'smart-cc': 'Smart CC', 'crawl': 'Crawl limit',
    'waiting-room': 'Waiting room', 'sensitive': 'Sensitive word', 'traffic': 'Traffic limit',
    'traffic-block': 'Traffic limit (block)', 'custom': 'Custom rule'
  };
  // custom:<id> and similar carry a suffix; region:* keeps its own labels
  function ruleLabel(k) { return RULE_LABELS[k] || RULE_LABELS[String(k).split(':')[0]] || k; }

  function renderByRule(by) {
    var items = Object.keys(by).map(function (k) {
      return { name: ruleLabel(k), value: by[k] };
    }).sort(function (a, b) { return b.value - a.value; });
    rank('#wp-by-rule', items, '');
  }

  function rank(sel, items, unit) {
    if (!items.length) { $(sel).html('<div class="wp-empty">No data</div>'); return; }
    var max = Math.max.apply(null, items.map(function (x) { return x.value; })) || 1;
    $(sel).html(items.slice(0, 10).map(function (x, i) {
      return '<div class="wp-rank"><span class="n' + (i < 3 ? ' top' : '') + '">' + (i + 1) + '</span>' +
        '<span class="nm" title="' + esc(x.name) + '">' + esc(x.name) + '</span>' +
        '<span class="tr"><i style="width:' + Math.max(x.value / max * 100, 2) + '%"></i></span>' +
        '<span class="v">' + (x.fmt || num(x.value)) + unit + '</span></div>';
    }).join(''));
  }

  function drawMainChart(d) {
    var ch = d.chart || {};
    ec('wp-main-chart', {
      tooltip: { trigger: 'axis', axisPointer: { type: 'line' } },
      legend: { data: ['Total requests', 'After filtering', 'Traffic', 'IP count'], top: 0, icon: 'circle', itemWidth: 8, textStyle: { fontSize: 11, color: '#5c6470' } },
      grid: { left: 48, right: 64, top: 32, bottom: 24 },
      xAxis: { type: 'category', data: ch.hours || [], boundaryGap: false, axisLine: { lineStyle: { color: '#ebedf0' } }, axisLabel: { color: '#9aa1ab', fontSize: 11 } },
      yAxis: [
        { type: 'value', splitLine: { lineStyle: { color: '#f4f5f6', type: 'dashed' } }, axisLabel: { color: '#9aa1ab', fontSize: 11 } },
        { type: 'value', splitLine: { show: false }, axisLabel: { color: '#9aa1ab', fontSize: 11, formatter: '{value} MB' } }
      ],
      series: [
        { name: 'Total requests', type: 'line', smooth: true, symbol: 'none', data: ch.total || [], lineStyle: { width: 2, color: '#20a53a' }, itemStyle: { color: '#20a53a' }, areaStyle: { color: 'rgba(32,165,58,.08)' } },
        { name: 'After filtering', type: 'line', smooth: true, symbol: 'none', data: ch.after_filter || [], lineStyle: { width: 1.5, color: '#a3c9f5' }, itemStyle: { color: '#a3c9f5' } },
        { name: 'Traffic', type: 'line', smooth: true, symbol: 'none', yAxisIndex: 1, data: ch.traffic_mb || [], lineStyle: { width: 1.5, color: '#3b82f6' }, itemStyle: { color: '#3b82f6' } },
        { name: 'IP count', type: 'line', smooth: true, symbol: 'none', data: ch.ips || [], lineStyle: { width: 1.5, color: '#7fd196' }, itemStyle: { color: '#7fd196' } }
      ]
    });
  }


  function lineOpt(data, labels, color) {
    return {
      tooltip: { trigger: 'axis' },
      grid: { left: 40, right: 10, top: 10, bottom: 22 },
      xAxis: { type: 'category', data: labels, boundaryGap: false, axisLine: { lineStyle: { color: '#ebedf0' } }, axisLabel: { color: '#9aa1ab', fontSize: 10 } },
      yAxis: { type: 'value', splitLine: { lineStyle: { color: '#f4f5f6', type: 'dashed' } }, axisLabel: { color: '#9aa1ab', fontSize: 10 } },
      series: [{ type: 'line', smooth: true, symbol: 'none', data: data, lineStyle: { width: 2, color: color }, areaStyle: { color: color === '#20a53a' ? 'rgba(32,165,58,.1)' : 'rgba(59,130,246,.1)' } }]
    };
  }
  function startQps() {
    function tick() {
      post('realtime', {}, function (r) {
        if (!r.status || !r.qps) return;
        var q = r.qps;
        var labels = (q.points || []).map(function (x) { return x.t; });
        $('#wp-qps-t').text('Real-time QPS: ' + (q.now || 0) + '/s');
        ec('wp-qps-chart', lineOpt((q.points || []).map(function (x) { return x.v; }), labels, '#20a53a'));

        // origin response: only real data — otherwise offer to switch it on
        if (q.rt_tracked) {
          $('#wp-rt-t').text('Real-time origin response: ' + (q.rt_now || 0) + 'ms');
          if (!$('#wp-rt-chart').length) {
            $('#wp-rt-holder').html('<div class="wp-chart sm" id="wp-rt-chart"></div>');
          }
          ec('wp-rt-chart', lineOpt((q.rt_points || []).map(function (x) { return x.v; }), labels, '#3b82f6'));
        } else {
          $('#wp-rt-t').text('Real-time origin response');
          if (!$('#wp-rt-enable').length) {
            $('#wp-rt-holder').html(
              '<div style="padding:18px 4px;text-align:center">' +
              '<div style="color:var(--wp-text3);font-size:12px;line-height:1.7;margin-bottom:12px">' +
              'Nginx does not log the origin response time by default, so there is no data to chart.<br>' +
              'Enabling adds an <b>upstream_response_time</b> field to your access logs.</div>' +
              '<span class="wp-btn primary" id="wp-rt-enable">Enable tracking</span></div>');
            $('#wp-rt-enable').on('click', function () {
              layer.confirm('Add the origin-response field to your nginx access logs?<br><br>' +
                'This edits nginx.conf and the site configs (both are backed up, nginx is ' +
                'syntax-checked and rolled back automatically if anything fails).',
                { icon: 3, title: 'Enable origin response tracking' }, function (i) {
                  layer.close(i);
                  var ld = layer.msg('Applying...', { icon: 16, time: 0, shade: 0.3 });
                  post('enable_rt', {}, function (rr) {
                    layer.close(ld);
                    layer.msg(rr.msg, { icon: rr.status ? 1 : 2, time: 5000 });
                  });
                });
            });
          }
        }
      });
    }
    tick();
    S.timer = setInterval(tick, 10000);
  }


  // exports
  W.RULE_LABELS = RULE_LABELS;
  W.drawMainChart = drawMainChart;
  W.drawMap = drawMap;
  W.fillOverview = fillOverview;
  W.lineOpt = lineOpt;
  W.loadWorld = loadWorld;
  W.pageOverview = pageOverview;
  W.rank = rank;
  W.rankCountries = rankCountries;
  W.renderByRule = renderByRule;
  W.ruleLabel = ruleLabel;
  W.startQps = startQps;
  W.statCard = statCard;
})(window.WAFPRO = window.WAFPRO || {});
