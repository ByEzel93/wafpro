(function (W) {
  // generated wiring: names declared in other modules
  var S = W.S;
  function esc() { return W.esc.apply(this, arguments); }
  function post() { return W.post.apply(this, arguments); }

  /* ---------- plugin self-update ----------
     The panel's store only offers updates for plugins aaPanel hosts, so the
     plugin checks its own GitHub releases (wafpro_main.update_check, cached
     server side) and installs them (update_install). A bar under the tabs
     says when a new version is out; the Global tab has the switch for
     automatic updates. */

  // release notes are GitHub markdown: enough of it for a readable dialog
  function notesHtml(md) {
    var out = [], list = false;
    String(md || '').replace(/\r/g, '').split('\n').forEach(function (line) {
      var t = esc(line.trim())
        .replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
      var li = /^[-*] /.test(line.trim());
      if (li && !list) { out.push('<ul>'); list = true; }
      if (!li && list) { out.push('</ul>'); list = false; }
      if (li) out.push('<li>' + t.slice(2) + '</li>');
      else if (/^#+ /.test(line.trim())) out.push('<p><b>' + t.replace(/^#+ /, '') + '</b></p>');
      else if (t) out.push('<p>' + t + '</p>');
    });
    if (list) out.push('</ul>');
    return out.join('');
  }

  function updateDialog(u) {
    var l = u.latest || {};
    W.confirm(
      '<div class="wp-upd-dlg"><div class="wp-upd-h">WAF Pro ' + esc(l.version) +
        (l.date ? ' <span>' + esc(l.date) + '</span>' : '') + '</div>' +
      '<div class="wp-upd-notes">' + (notesHtml(l.notes) || '<p>No release notes.</p>') + '</div>' +
      '<div class="wp-upd-foot">Installed: ' + esc(u.current) + '. Settings, rules and logs are kept. ' +
        'If nginx is wired, it is reloaded only after <code>nginx -t</code> passes.</div></div>',
      { title: 'Update WAF Pro', btn: ['Update now', 'Cancel'], area: ['620px', 'auto'] },
      function (i) { layer.close(i); install(); });
  }

  function install() {
    var ld = layer.msg('Updating WAF Pro, this can take a minute...', { icon: 16, time: 0, shade: 0.3 });
    $.post(W.API + 'update_install', {}, function (rr) {
      layer.close(ld);
      if (!rr.status) return layer.msg(rr.msg, { icon: 2, time: 6000 });
      layer.msg(rr.msg + ' — reloading', { icon: 1 });
      // the open page still runs the old scripts
      setTimeout(function () { location.reload(); }, 1500);
    }, 'json').fail(function (x) {
      layer.close(ld);
      layer.msg('Request failed: ' + x.status, { icon: 2 });
    });
  }

  // the bar under the tabs; shown once per page load
  function updateBar() {
    if (S.updDismissed) return;
    post('update_check', {}, function (u) {
      if (!u.status || !u.available) return;
      $('#wp-upd').html('<span>WAF Pro <b>' + esc(u.latest.version) + '</b> is available (installed: ' +
        esc(u.current) + ').</span><span class="wp-lnk" id="wp-upd-go">Update</span>' +
        '<span class="wp-upd-x" id="wp-upd-x" title="Hide">&times;</span>').show();
      $('#wp-upd-go').on('click', function () { updateDialog(u); });
      $('#wp-upd-x').on('click', function () { S.updDismissed = true; $('#wp-upd').hide(); W.fit(); });
      W.fit();
    });
  }

  // the "Plugin update" card on the Global tab
  function updateCard(force) {
    var $c = $('#g-upd');
    if (!$c.length) return;
    post('update_check', force ? { force: 1 } : {}, function (u) {
      var line;
      if (u.available) line = 'Version <b>' + esc(u.latest.version) + '</b> is available.';
      else if (u.error) line = esc(u.error);
      else line = 'Up to date.';
      if (u.checked) line += ' Last checked ' + esc(u.checked) + '.';
      if (u.last && u.last.msg) line += '<br>Last update ' + esc(u.last.time) + ': ' + esc(u.last.msg);
      $c.find('.wp-sc-n').html(line).css('color', u.error && !u.available ? 'var(--wp-red)' : '');
      $c.find('#g-upd-auto').prop('checked', !!u.auto);
      $c.find('#g-upd-ver').text(u.current);
      $c.find('#g-upd-go').toggle(!!u.available).off('click').on('click', function () { updateDialog(u); });
      if (force) layer.msg(u.error || (u.available ? 'Version ' + u.latest.version + ' is available' : 'Already up to date'),
        { icon: u.error ? 2 : 1 });
    });
  }

  function updateCardHtml() {
    return '<div class="wp-sc" id="g-upd">' +
      '<div class="wp-sc-top"><div class="wp-sc-t">Automatic updates</div>' + W.sw('g-upd-auto', false) + '</div>' +
      '<div class="wp-sc-bot"><div class="wp-sc-d">Installed version <span id="g-upd-ver">-</span>. Checks GitHub once a day ' +
        'and installs new releases by itself. When off, new versions are shown at the top of the plugin.' +
        '<div class="wp-sc-n" style="color:inherit">Checking...</div></div>' +
      '<div class="wp-sc-btns"><span class="wp-btn primary" id="g-upd-go" style="display:none">Update</span>' +
        '<span class="wp-btn ghost" id="g-upd-check">Check now</span></div></div></div>';
  }

  function bindUpdateCard() {
    $('#g-upd-check').on('click', function () { updateCard(true); });
    $('#g-upd-auto').on('change', function () {
      var on = this.checked, $cb = $(this);
      post('update_auto', { open: on ? 1 : 0 }, function (rr) {
        layer.msg(rr.msg, { icon: rr.status ? 1 : 2 });
        if (!rr.status) $cb.prop('checked', !on);
      });
    });
    updateCard(false);
  }

  // exports
  W.updateBar = updateBar;
  W.updateCardHtml = updateCardHtml;
  W.bindUpdateCard = bindUpdateCard;
})(window.WAFPRO = window.WAFPRO || {});
