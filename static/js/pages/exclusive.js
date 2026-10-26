(function (W) {
  // generated wiring: names declared in other modules
  function esc() { return W.esc.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }

  /* ================= EXCLUSIVE RULES (aaPanel 8 layout) =================
     Our N-day virtual patches: one exploit fingerprint per row, gated by the
     global "N-day" module switch, applied to every site. */
  function split(ps) {
    var m = /^(.*?)\s*\(([^)]*CVE[^)]*)\)\s*$/.exec(ps || '');
    var name = m ? m[1] : (ps || '');
    var cve = m ? m[2] : '';
    return {
      name: name,
      desc: (cve ? 'Virtual patch for ' + cve + '. ' : 'Virtual patch. ') +
        'Blocks the exploit by its request fingerprint, so normal traffic is not touched.'
    };
  }

  function pageExclusive() {
    $('#wp-body').html('<div class="wp-loading">Loading...</div>');
    post('exclusive_rules', {}, function (r) {
      if (!r.status) { $('#wp-body').html('<div class="wp-note">' + esc(r.msg || 'error') + '</div>'); return; }
      var h = '<div class="wp-card">';
      if (!r.enabled) {
        h += '<div class="wp-ex-off"><span class="wp-ex-i">!</span><span><b>Exclusive rules are disabled</b>' +
          '. Enable them to enhance protection for WordPress, ThinkPHP, Laravel and other applications.</span>' +
          '<span class="wp-lnk" id="ex-on" style="margin-left:8px">Enable now</span></div>';
      }
      h += '<div class="wp-site-box"><table class="wp-site-tbl"><thead><tr><th style="width:110px">Rule ID</th>' +
        '<th style="width:30%">Name</th><th>Description</th><th style="width:80px">Hits</th><th style="width:90px">Status</th></tr></thead><tbody>';
      h += (r.data || []).length ? r.data.map(function (x) {
        var n = split(x.ps);
        return '<tr><td>' + x.id + '</td><td class="ell" title="' + esc(x.rule) + '">' + esc(n.name) + '</td>' +
          '<td style="white-space:normal">' + esc(n.desc) + '</td>' +
          '<td><span class="wp-tag' + (x.hits ? ' ok' : '') + '">' + x.hits + '</span></td>' +
          '<td><label class="wp-sw wp-sw-sm"><input type="checkbox" class="ex-on" data-i="' + x.index + '"' +
          (x.open ? ' checked' : '') + (r.enabled ? '' : ' disabled') + '><span class="sl"></span></label></td></tr>';
      }).join('') : '<tr><td colspan="5" class="wp-empty">No Data</td></tr>';
      h += '</tbody></table></div><ul class="wp-notes" style="margin-top:20px">' +
        '<li>After enabling exclusive rules, they will apply to all websites. If false positives occur, you can disable individual rules.</li>' +
        '<li>Exclusive rules target widely exploited, public vulnerabilities of common programs; most of them are remote code execution.</li>' +
        '<li>Rule updates: updating the plugin also updates the rules. Each rule is matched against the decoded request line and form body.</li>' +
        '</ul></div>';
      $('#wp-body').html(h);

      $('#ex-on').on('click', function () {
        post('save_config', { config: JSON.stringify({ m_nday: true }) }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
          if (rr.status) route();
        });
      });
      $('.ex-on').on('change', function () {
        var on = this.checked;
        post('rule_toggle', { rule_name: 'nday', index: $(this).data('i'), open: on ? 1 : 0 }, function (rr) {
          layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        });
      });
    });
  }

  // exports
  W.pageExclusive = pageExclusive;
})(window.WAFPRO = window.WAFPRO || {});
