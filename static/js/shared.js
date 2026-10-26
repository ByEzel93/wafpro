(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;

  function applyGSub() {
    $('#g-cards .wp-gc').each(function () {
      $(this).css('display', (S.gSub === 'all' || $(this).data('g') === S.gSub) ? '' : 'none');
    });
  }

  function row(label, ctrl, tip) {
    return '<div style="display:flex;align-items:center;gap:14px;padding:11px 0">' +
      '<div style="width:150px;color:var(--wp-text2);text-align:right;flex:none">' + label + '</div>' +
      '<div style="flex:none">' + ctrl + '</div>' +
      (tip ? '<div style="color:var(--wp-text3);font-size:12px">' + tip + '</div>' : '') + '</div>';
  }
  function sw(id, on) {
    return '<label class="wp-sw"><input type="checkbox" id="' + id + '"' + (on ? ' checked' : '') + '><span class="sl"></span></label>';
  }

  /* ---------- inline icons ---------- */
  function icoFilter() { return '<svg class="wp-ico" viewBox="0 0 24 24"><path d="M3 5h18l-7 8v6l-4 2v-8z"/></svg>'; }
  function icoPulse() { return '<svg class="wp-ico" viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>'; }
  function icoShield() { return '<svg class="wp-ico" viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg>'; }
  function icoWarn() { return '<svg class="wp-ico" viewBox="0 0 24 24"><path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17h.01"/></svg>'; }
  function icoChart() { return '<svg class="wp-ico" viewBox="0 0 24 24"><path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/></svg>'; }
  function icoDoc() { return '<svg class="wp-ico" viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/></svg>'; }
  function icoPie() { return '<svg class="wp-ico" viewBox="0 0 24 24"><path d="M12 3v9h9"/><circle cx="12" cy="12" r="9"/></svg>'; }
  function icoClock() { return '<svg class="wp-ico" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>'; }
  function icoGlobe() { return '<svg class="wp-ico" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>'; }
  function svgBugBg() {
    return '<svg class="bg" viewBox="0 0 24 24"><path d="M9 8V6a3 3 0 016 0v2"/><rect x="7" y="8" width="10" height="11" rx="5"/><path d="M3 13h4M17 13h4M4 19l3.5-2M20 19l-3.5-2"/></svg>';
  }
  function svgShieldBg() {
    return '<svg class="bg" viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M12 8v5M12 16h.01"/></svg>';
  }


  // exports
  W.applyGSub = applyGSub;
  W.icoChart = icoChart;
  W.icoClock = icoClock;
  W.icoDoc = icoDoc;
  W.icoFilter = icoFilter;
  W.icoGlobe = icoGlobe;
  W.icoPie = icoPie;
  W.icoPulse = icoPulse;
  W.icoShield = icoShield;
  W.icoWarn = icoWarn;
  W.row = row;
  W.svgBugBg = svgBugBg;
  W.svgShieldBg = svgShieldBg;
  W.sw = sw;
})(window.WAFPRO = window.WAFPRO || {});
