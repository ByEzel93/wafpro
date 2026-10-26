(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function ec() { return W.ec.apply(this, arguments); }
  function esc() { return W.esc.apply(this, arguments); }
  function loadWorld() { return W.loadWorld.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }

  /* ================= ATTACK MAP =================
     World map with animated lines from each attacker's location to the
     server (Local IP). Uses the panel's world.json + ECharts lines/effect. */
  function pageAttackMap() {
    $('#wp-body').html('<div class="wp-loading">Loading...</div>');
    post('attack_map', { date: 'today' }, function (r) {
      if (!r.status) { $('#wp-body').html('<div class="wp-note">' + esc(r.msg || 'error') + '</div>'); return; }
      S.amData = r;
      renderAttackMap(r);
    });
  }

  function renderAttackMap(r) {
    var sv = r.server || {};
    var h = '<div class="wp-card" style="padding:0;overflow:hidden">';
    h += '<div style="display:flex;align-items:center;gap:14px;padding:12px 16px;border-bottom:1px solid var(--wp-border);flex-wrap:wrap">' +
      '<span style="font-weight:600;color:var(--wp-text)">Attack map</span>' +
      '<span style="color:var(--wp-text3);font-size:12px">(map for reference only)</span>' +
      '<span style="color:var(--wp-text2);font-size:13px">Longitude: <b id="am-lon">' + (sv.lon != null ? (+sv.lon).toFixed(3) : '-') + '</b></span>' +
      '<span style="color:var(--wp-text2);font-size:13px">Latitude: <b id="am-lat">' + (sv.lat != null ? (+sv.lat).toFixed(3) : '-') + '</b></span>' +
      '<span class="wp-lnk" id="am-modify">Modify</span>' +
      '<span style="margin-left:auto;color:var(--wp-text2);font-size:12px">' +
        'Local IP: <b>' + esc(sv.ip || '-') + '</b>' + (sv.city ? ' · ' + esc(sv.city) + ', ' + esc(sv.country) : '') + '</span>' +
      '<span class="wp-lnk" id="am-full">&#10530; Full-screen</span>' +
      '</div>';
    h += '<div id="am-map" style="height:620px;width:100%"></div>';
    h += '</div>';
    $('#wp-body').html(h);

    loadWorld(function () { drawAttackMap(r); });

    $('#am-modify').on('click', function () { amModifyDialog(sv); });
    $('#am-full').on('click', function () {
      var el = document.getElementById('am-map');
      if (!el) return;
      if (el.requestFullscreen) el.requestFullscreen();
      else if (el.webkitRequestFullscreen) el.webkitRequestFullscreen();
      setTimeout(function () { if (S.charts['am-map']) try { S.charts['am-map'].resize(); } catch (e) {} }, 300);
    });
  }

  function drawAttackMap(r) {
    var el = document.getElementById('am-map');
    if (!el) return;
    if (typeof echarts === 'undefined' || !echarts.getMap || !echarts.getMap('world')) {
      el.innerHTML = '<div class="wp-empty">World map data unavailable</div>'; return;
    }
    var sv = r.server || {};
    var pts = r.points || [];
    if (sv.lat == null || sv.lon == null) {
      el.innerHTML = '<div class="wp-empty">Server location unknown — set it with Modify.</div>'; return;
    }
    var target = [sv.lon, sv.lat];
    var max = Math.max.apply(null, pts.map(function (p) { return p.count; }).concat([1]));

    var scatter = pts.map(function (p) {
      return { name: (p.country || '') + (p.city ? ' / ' + p.city : ''),
               value: [p.lon, p.lat, p.count] };
    });
    var lines = pts.map(function (p) {
      return { coords: [[p.lon, p.lat], target], value: p.count };
    });

    ec('am-map', {
      tooltip: {
        trigger: 'item',
        formatter: function (p) {
          if (p.seriesType === 'lines') return '';
          if (p.data && p.data.value) return (p.name || 'Unknown') + '<br/>Attacks: ' + p.data.value[2];
          return p.name || '';
        }
      },
      geo: {
        map: 'world', roam: true, zoom: 1.2, center: [30, 20],
        itemStyle: { areaColor: '#eef1f3', borderColor: '#dfe4e8' },
        emphasis: { itemStyle: { areaColor: '#e3ece5' }, label: { show: false } }
      },
      series: [
        {
          type: 'lines', coordinateSystem: 'geo', zlevel: 1,
          effect: { show: true, period: 5, trailLength: 0.5, symbol: 'arrow', symbolSize: 5, color: '#fa8c16' },
          lineStyle: { color: '#fa8c16', width: 1, opacity: 0.5, curveness: 0.3 },
          data: lines
        },
        {
          type: 'effectScatter', coordinateSystem: 'geo', zlevel: 2,
          rippleEffect: { brushType: 'stroke', scale: 2.5 },
          symbolSize: function (v) { return Math.max(6, Math.min(24, 6 + (v[2] / max) * 18)); },
          itemStyle: { color: '#ef4d4d' },
          data: scatter
        },
        {
          // the server marker (Local IP)
          type: 'effectScatter', coordinateSystem: 'geo', zlevel: 3,
          rippleEffect: { brushType: 'fill', scale: 4, period: 3 },
          symbolSize: 16, itemStyle: { color: '#e04322' },
          label: { show: true, formatter: 'Local IP', position: 'right',
                   color: '#e04322', fontWeight: 600, fontSize: 11 },
          data: [{ name: 'Local IP: ' + (sv.ip || ''), value: [sv.lon, sv.lat, 0] }]
        }
      ]
    });
  }

  function amModifyDialog(sv) {
    var h = '<div class="wp-modal"><div class="wp-mod-head">' +
      '<div class="wp-mod-site">Server location</div>' +
      '<div class="wp-mod-meta">Where the Local IP marker sits on the map. Reference only.</div></div>' +
      '<div class="wp-mod-body"><div class="wp-mod-sec">' +
        '<div class="wp-mod-row"><div class="wp-mod-lbl">Latitude</div>' +
          '<div class="wp-mod-ctl"><input class="wp-in" id="am-in-lat" style="width:180px" value="' + (sv.lat != null ? sv.lat : '') + '" placeholder="-90 to 90"></div></div>' +
        '<div class="wp-mod-row"><div class="wp-mod-lbl">Longitude</div>' +
          '<div class="wp-mod-ctl"><input class="wp-in" id="am-in-lon" style="width:180px" value="' + (sv.lon != null ? sv.lon : '') + '" placeholder="-180 to 180"></div></div>' +
      '</div></div>' +
      '<div class="wp-mod-foot"><span class="wp-btn" id="am-cancel">Cancel</span>' +
        '<span class="wp-btn primary" id="am-ok">Save</span></div></div>';
    var idx = W.open({ type: 1, title: false, closeBtn: 1, area: ['440px', '320px'], content: h });
    $('#am-cancel').on('click', function () { layer.close(idx); });
    $('#am-ok').on('click', function () {
      post('set_map_location', { lat: $('#am-in-lat').val(), lon: $('#am-in-lon').val() }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        if (rr.status) { layer.close(idx); route(); }
      });
    });
  }

  // exports
  W.amModifyDialog = amModifyDialog;
  W.drawAttackMap = drawAttackMap;
  W.pageAttackMap = pageAttackMap;
  W.renderAttackMap = renderAttackMap;
})(window.WAFPRO = window.WAFPRO || {});
