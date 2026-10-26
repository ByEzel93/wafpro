(function (W) {
  // generated wiring: names declared in other modules
  function renderTabs() { return W.renderTabs.apply(this, arguments); }
  function route() { return W.route.apply(this, arguments); }

  /* ---------- boot ---------- */
  renderTabs();
  route();
  // the loader keeps the page hidden until this point (and the stylesheet)
  if (W.booted) W.booted();

  // exports
})(window.WAFPRO = window.WAFPRO || {});
