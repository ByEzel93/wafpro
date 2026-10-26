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
    var h = '<div class="wp-card am-card"><div class="am-bar"><div class="am-info">' +
      '<span class="am-t">Attack map details (map for reference only)</span>' +
      '<span>Longitude: <b>' + (sv.lon != null ? (+sv.lon).toFixed(3) : '-') + '</b></span>' +
      '<span>Latitude: <b>' + (sv.lat != null ? (+sv.lat).toFixed(3) : '-') + '</b></span>' +
      '<span class="wp-lnk" id="am-modify">Set</span>' +
      '<span class="am-ip">Local IP: <b>' + esc(sv.ip || '-') + '</b></span></div>' +
      '<span class="wp-btn" id="am-full"><svg class="wp-ico" viewBox="0 0 24 24"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/></svg>Full-screen</span></div>' +
      '<div class="am-body" id="am-wrap"><div id="am-map" style="height:100%;width:100%"></div>' +
      '<div class="am-zoom"><span id="am-zi" title="Zoom in">+</span><span id="am-zo" title="Zoom out">&minus;</span></div>' +
      '<div class="am-legend"><span>Low</span><i></i><span>High</span></div></div></div>';
    $('#wp-body').html(h);

    loadWorld(function () { drawAttackMap(r); });

    $('#am-modify').on('click', function () { amModifyDialog(sv); });
    $('#am-zi, #am-zo').on('click', function () {
      var c = S.charts['am-map'];
      if (!c) return;
      var z = (c.getOption().geo[0].zoom || 1.2) * (this.id === 'am-zi' ? 1.3 : 1 / 1.3);
      c.setOption({ geo: { zoom: Math.max(0.8, Math.min(z, 12)) } });
    });
    $('#am-full').on('click', function () {
      var el = document.getElementById('am-wrap');
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
    var pts = (r.points || []).filter(function (p) {
      return p.lat != null && p.lon != null && !(+p.lat === 0 && +p.lon === 0);
    });
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
          itemStyle: { color: function (p) {
            var t = p.value[2] / max;
            return t > 0.66 ? '#e53935' : t > 0.33 ? '#fb8c00' : '#fdd835';
          } },
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
    var idx = W.open({
      type: 1, title: 'Set location', area: ['420px', 'auto'], btn: ['Confirm', 'Cancel'],
      content: '<div class="wp-g-dlg"><div class="wp-g-row"><div class="wp-g-rl" style="width:80px">Longitude</div><div class="wp-g-rc">' +
        '<input class="wp-in" id="am-in-lon" style="width:260px" placeholder="Please enter longitude" value="' + (sv.lon != null ? sv.lon : '') + '"></div></div>' +
        '<div class="wp-g-row"><div class="wp-g-rl" style="width:80px">Latitude</div><div class="wp-g-rc">' +
        '<input class="wp-in" id="am-in-lat" style="width:260px" placeholder="Please enter latitude" value="' + (sv.lat != null ? sv.lat : '') + '"></div></div>' +
        '<div style="color:#909399;font-size:12px;padding-left:94px">The location is for reference only!</div></div>',
      yes: function () {
        post('set_map_location', { lat: $('#am-in-lat').val(), lon: $('#am-in-lon').val() }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) { layer.close(idx); route(); }
        });
      }
    });
  }

  // exports
  W.amModifyDialog = amModifyDialog;
  W.drawAttackMap = drawAttackMap;
  W.pageAttackMap = pageAttackMap;
  W.renderAttackMap = renderAttackMap;
})(window.WAFPRO = window.WAFPRO || {});
