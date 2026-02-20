(function () {
  "use strict";

  function toUrl(href) {
    try {
      return new URL(href, window.location.href);
    } catch (err) {
      return null;
    }
  }

  function prefetchLink(link) {
    if (!link || !link.href) return;
    var url = toUrl(link.href);
    if (!url || url.origin !== window.location.origin) return;

    var targetHref = url.pathname + url.search + url.hash;
    var selector = 'link[rel="prefetch"][href="' + targetHref.replace(/"/g, '\\"') + '"]';
    if (document.head.querySelector(selector)) return;

    var prefetch = document.createElement("link");
    prefetch.rel = "prefetch";
    prefetch.as = "document";
    prefetch.href = targetHref;
    document.head.appendChild(prefetch);
  }

  document.addEventListener("mouseover", function (event) {
    var link = event.target.closest("a[data-smooth-nav]");
    if (link) prefetchLink(link);
  });

  document.addEventListener("touchstart", function (event) {
    var link = event.target.closest("a[data-smooth-nav]");
    if (link) prefetchLink(link);
  }, { passive: true });
})();
