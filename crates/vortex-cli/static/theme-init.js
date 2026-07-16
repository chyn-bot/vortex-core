/* Theme pre-paint loader. Loaded as a blocking <script src> in <head>
   (NOT deferred) so the saved theme is applied before first paint, with
   no flash. Externalized from an inline <script> so pages can ship a
   strict Content-Security-Policy (script-src 'self', no 'unsafe-inline'). */
(function () {
  var t;
  try { t = localStorage.getItem('theme'); } catch (e) {}
  if (t) document.documentElement.setAttribute('data-theme', t);
})();
