(function (W) {
  // generated wiring: names declared in other modules
  function pageAttackMap() { return W.pageAttackMap.apply(this, arguments); }
  function pageBlockade() { return W.pageBlockade.apply(this, arguments); }
  function pageGlobal() { return W.pageGlobal.apply(this, arguments); }
  function pageLists() { return W.pageLists.apply(this, arguments); }
  function pageOverview() { return W.pageOverview.apply(this, arguments); }
  function pageRegion() { return W.pageRegion.apply(this, arguments); }
  function pageReport() { return W.pageReport.apply(this, arguments); }
  function pageRules() { return W.pageRules.apply(this, arguments); }
  function pageTraffic() { return W.pageTraffic.apply(this, arguments); }
  function pageWebshell() { return W.pageWebshell.apply(this, arguments); }
  function pageWebsite() { return W.pageWebsite.apply(this, arguments); }
  function selfTestDialog() { return W.selfTestDialog.apply(this, arguments); }

  var API = '/plugin?action=a&name=wafpro&s=';
  var S = { tab: 'overview', charts: {}, timer: null, range: 'today' };

  // The panel merges form fields over the query string, so a payload key
  // named action/name/s would replace the route itself (issue #1).
  var RESERVED = ['action', 'name', 's'];
  function post(m, d, cb) {
    RESERVED.forEach(function (k) {
      if (d && Object.prototype.hasOwnProperty.call(d, k)) {
        console.error('[WAF Pro] payload key "' + k + '" is reserved by the panel router (' + m + ')');
      }
    });
    $.post(API + m, d || {}, function (r) { cb(r); }, 'json')
      .fail(function (x) { layer.msg('Request failed: ' + x.status, { icon: 2 }); });
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }
  function dayStr(offset) {
    var d = new Date(Date.now() + (offset || 0) * 86400000);
    var p = function (x) { return (x < 10 ? '0' : '') + x; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }
  function todayStr() { return dayStr(0); }
  function num(n) { return (n || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
  function mb(b) {
    b = b || 0;
    if (b > 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
    if (b > 1048576) return (b / 1048576).toFixed(2) + ' MB';
    if (b > 1024) return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
  }

  /* ---------- fit into the panel dialog ---------- */
  function fit() {
    var app = document.getElementById('wafpro-app');
    if (!app) return;
    var n = app.parentElement, box = null;
    while (n && n !== document.body) {
      if (n.clientHeight && n.clientHeight > 150) { box = n; break; }
      n = n.parentElement;
    }
    var h = box ? box.clientHeight - Math.max(app.getBoundingClientRect().top - box.getBoundingClientRect().top, 0)
                : Math.max(window.innerHeight - 120, 480);
    app.style.height = Math.max(h, 420) + 'px';
    if (app.parentElement) app.parentElement.style.overflow = 'hidden';
    resizeCharts();
  }
  function widen() {
    var app = document.getElementById('wafpro-app');
    if (!app) return;
    var vw = window.innerWidth, vh = window.innerHeight;
    var W = Math.min(1500, vw - 40), H = Math.min(900, vh - 40);
    var el = app.parentElement, prev = app, target = null, narrow = null, nw = 1e9;
    while (el && el !== document.body && el !== document.documentElement) {
      var cs = getComputedStyle(el);
      if (cs.position === 'fixed' && el.clientWidth >= vw * 0.95 && el.clientHeight >= vh * 0.9) { target = prev; break; }
      if (el.clientWidth >= 300 && el.clientWidth < nw) { nw = el.clientWidth; narrow = el; }
      prev = el; el = el.parentElement;
    }
    if (!target) target = narrow;
    if (target && target !== app) {
      var st = target.style;
      st.setProperty('width', W + 'px', 'important');
      st.setProperty('max-width', 'none', 'important');
      st.setProperty('height', H + 'px', 'important');
      st.setProperty('max-height', 'none', 'important');
      var tcs = getComputedStyle(target);
      if (tcs.position === 'fixed' || tcs.position === 'absolute') {
        st.setProperty('left', Math.max((vw - W) / 2, 10) + 'px', 'important');
        st.setProperty('top', Math.max((vh - H) / 2, 10) + 'px', 'important');
        st.setProperty('right', 'auto', 'important'); st.setProperty('bottom', 'auto', 'important');
        st.setProperty('margin', '0', 'important'); st.setProperty('transform', 'none', 'important');
      }
      var mid = app.parentElement;
      while (mid && mid !== target) {
        mid.style.setProperty('width', '100%', 'important');
        mid.style.setProperty('max-width', 'none', 'important');
        mid = mid.parentElement;
      }
    }
    fit();
  }
  function resizeCharts() {
    Object.keys(S.charts).forEach(function (k) { try { S.charts[k].resize(); } catch (e) {} });
  }

  /* ---------- echarts ---------- */
  function ec(id, opt) {
    var el = document.getElementById(id);
    if (!el || typeof echarts === 'undefined') return null;
    if (S.charts[id]) { try { S.charts[id].dispose(); } catch (e) {} }
    var c = echarts.init(el);
    c.setOption(opt);
    S.charts[id] = c;
    return c;
  }
  function ensureEcharts(cb) {
    if (typeof echarts !== 'undefined') return cb();
    $.getScript('/static/js/echarts.min.js').done(cb).fail(function () {
      layer.msg('ECharts yüklenemedi', { icon: 2 }); cb();
    });
  }

  /* ---------- tabs ---------- */
  var TABS = [
    { id: 'overview', t: 'Overview' },
    { id: 'website', t: 'WebSite' },
    { id: 'blockade', t: 'Blockade' },
    { id: 'lists', t: 'Black/White List' },
    { id: 'region', t: 'Region' },
    { id: 'traffic', t: 'Traffic Limit' },
    { id: 'rules', t: 'Custom rules' },
    { id: 'webshell', t: 'Webshell' },
    { id: 'attackmap', t: 'Attack Map' },
    { id: 'report', t: 'Report' },
    { id: 'global', t: 'Global' }
  ];
  function renderTabs() {
    $('#wp-tabs').html(TABS.map(function (x) {
      return '<div class="wp-tab' + (x.id === S.tab ? ' on' : '') + '" data-t="' + x.id + '">' + x.t + '</div>';
    }).join('') +
      '<span class="wp-btn primary wp-tab-act" id="wp-simulate" title="Send attack-shaped test requests to your sites">Simulated attack</span>');
  }
  $('#wp-tabs').on('click', '#wp-simulate', function () { selfTestDialog(''); });
  $('#wp-tabs').on('click', '.wp-tab', function () {
    var t = $(this).data('t');
    if (t === S.tab) return;
    S.tab = t; renderTabs(); route();
  });

  function route() {
    if (S.timer) { clearInterval(S.timer); S.timer = null; }
    // Pages bind delegated handlers on #wp-body; without this every visit
    // stacked another copy, so one click on Delete fired N confirms/requests.
    $('#wp-body').off();
    Object.keys(S.charts).forEach(function (k) { try { S.charts[k].dispose(); } catch (e) {} });
    S.charts = {};
    $('#wp-body').scrollTop(0);
    if (S.tab === 'overview') return pageOverview();
    if (S.tab === 'website') return pageWebsite();
    if (S.tab === 'blockade') return pageBlockade();
    if (S.tab === 'lists') return pageLists();
    if (S.tab === 'rules') return pageRules();
    if (S.tab === 'region') return pageRegion();
    if (S.tab === 'traffic') return pageTraffic();
    if (S.tab === 'attackmap') return pageAttackMap();
    if (S.tab === 'report') return pageReport();
    if (S.tab === 'global') return pageGlobal();
    if (S.tab === 'webshell') return pageWebshell();
  }

  /* ---------- date picker ----------
     The panel's own laydate (same calendar as the rest of aaPanel). A native
     <input type="date"> laid over a label does not work: Chrome opens its
     picker only from the tiny calendar glyph, so clicks did nothing.
     anchor: element to open under; opts: { value, max, min, done(YYYY-MM-DD) } */
  var LAYDATE_DIR = '/static/laydate/';
  // laydate derives its theme URL from the <script> tag that loaded it; via
  // $.ajax/eval there is none, it guessed our own js/ dir, waited forever for
  // a stylesheet that 404s, and never opened. Load it with a real tag and
  // point it at its own directory.
  function withLaydate(cb) {
    function fix() {
      if (window.laydate) laydate.path = LAYDATE_DIR;
      var l = document.getElementById('layuicss-laydate');
      if (l && l.href.indexOf(LAYDATE_DIR) === -1) l.parentNode.removeChild(l);
    }
    if (window.laydate) { fix(); return cb(true); }
    var s = document.createElement('script');
    s.src = LAYDATE_DIR + 'laydate.js';
    s.onload = function () { fix(); cb(!!window.laydate); };
    s.onerror = function () { cb(false); };
    document.body.appendChild(s);
  }
  function pickDate(anchor, opts) {
    opts = opts || {};
    var $a = $(anchor);
    // laydate writes the picked value into its element; give it a throwaway
    // input sitting on the anchor so the visible label stays ours. A fresh
    // one per opening keeps laydate from stacking bindings on one element.
    $a.find('input.wp-date-proxy').remove();
    var $in = $('<input class="wp-date-proxy" type="text" readonly>').css({
      position: 'absolute', left: 0, top: '100%', width: '100%', height: 1, padding: 0,
      border: 0, opacity: 0
    });
    if ($a.css('position') === 'static') $a.css('position', 'relative');
    // the proxy sits inside the anchor: its clicks must not bubble back up
    // to the anchor's own handler (that would reopen the picker forever)
    $in.on('click', function (e) { e.stopPropagation(); });
    $a.append($in);
    withLaydate(function (ok) {
      if (ok) {
        var conf = {
          elem: $in[0], show: true, theme: '#20a53a', btns: ['clear', 'now', 'confirm'],
          value: opts.value || '', done: function (v) { if (opts.done) opts.done(v || ''); }
        };
        if (opts.max) conf.max = opts.max;
        if (opts.min) conf.min = opts.min;
        // after the click that got us here has finished bubbling: laydate
        // closes itself on a document click outside its element
        setTimeout(function () { laydate.render(conf); }, 0);
        return;
      }
      // no laydate on this panel: the browser's own picker, opened explicitly
      var nat = $('<input type="date">').css({ position: 'absolute', opacity: 0, width: 1, height: 1 })
        .attr({ value: opts.value || '', max: opts.max || '' }).appendTo($a);
      nat.on('change', function () { if (opts.done) opts.done(this.value || ''); nat.remove(); });
      try { nat[0].showPicker(); } catch (e) { nat[0].focus(); nat[0].click(); }
    });
  }
  function icoCalendar() {
    return '<svg class="wp-ico" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="16" rx="2"/>' +
      '<path d="M3 10h18M8 3v4M16 3v4"/></svg>';
  }


  /* ---------- dialogs ----------
     Every dialog of ours goes through these so it gets the aaPanel 8 modal
     look (skin 'wp-layer'); the panel's own popups keep their skin. */
  function open(o) {
    o.skin = ((o.skin || '') + ' wp-layer').trim();
    return layer.open(o);
  }
  function confirm(msg, opt, yes) {
    if (typeof opt === 'function') { yes = opt; opt = {}; }
    opt = $.extend({ title: 'Tips', btn: ['Confirm', 'Cancel'] }, opt || {});
    delete opt.icon;
    return open($.extend(opt, {
      type: 1, area: opt.area || ['440px', 'auto'],
      content: '<div class="wp-g-dlg wp-confirm">' + msg + '</div>',
      yes: function (i) { if (yes) yes(i); else layer.close(i); }
    }));
  }

  // exports
  W.open = open;
  W.confirm = confirm;
  W.API = API;
  W.RESERVED = RESERVED;
  W.S = S;
  W.TABS = TABS;
  W.dayStr = dayStr;
  W.ec = ec;
  W.ensureEcharts = ensureEcharts;
  W.esc = esc;
  W.fit = fit;
  W.mb = mb;
  W.num = num;
  W.pickDate = pickDate;
  W.icoCalendar = icoCalendar;
  W.post = post;
  W.renderTabs = renderTabs;
  W.resizeCharts = resizeCharts;
  W.route = route;
  W.todayStr = todayStr;
  W.widen = widen;
})(window.WAFPRO = window.WAFPRO || {});
