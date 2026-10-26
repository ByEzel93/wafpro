(function (W) {
  // generated wiring: names declared in other modules
  function renderTabs() { return W.renderTabs.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }
  function widen() { return W.widen.apply(this, arguments); }

  /* ---------- boot ---------- */
  window.addEventListener('resize', widen);
  setTimeout(widen, 60); setTimeout(widen, 300); setTimeout(widen, 900);
  renderTabs();
  route();

  // exports
})(window.WAFPRO = window.WAFPRO || {});
