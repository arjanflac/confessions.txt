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

  function isEligibleClick(link, event) {
    if (!link || !link.href) return false;
    if (event.defaultPrevented) return false;
    if (event.button !== 0) return false;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return false;
    if (link.target && link.target !== "_self") return false;
    if (link.hasAttribute("download")) return false;

    var url = toUrl(link.href);
    if (!url || url.origin !== window.location.origin) return false;
    if (url.pathname === window.location.pathname && url.search === window.location.search && !url.hash) return false;
    return true;
  }

  document.addEventListener("mouseover", function (event) {
    var link = event.target.closest("a[data-smooth-nav]");
    if (link) prefetchLink(link);
  });

  document.addEventListener("touchstart", function (event) {
    var link = event.target.closest("a[data-smooth-nav]");
    if (link) prefetchLink(link);
  }, { passive: true });

  var prefersReducedMotion = false;
  try {
    prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch (err) {
    prefersReducedMotion = false;
  }

  var supportsNativeViewTransitions = typeof document.startViewTransition === "function";
  if (prefersReducedMotion || supportsNativeViewTransitions) {
    return;
  }

  document.addEventListener("click", function (event) {
    var link = event.target.closest("a[data-smooth-nav]");
    if (!isEligibleClick(link, event)) return;

    event.preventDefault();
    document.documentElement.classList.add("is-routing");
    window.setTimeout(function () {
      window.location.assign(link.href);
    }, 180);
  });
})();
