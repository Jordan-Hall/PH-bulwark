// PH Bulwark Browser — full-content extraction + in-page censor bridge.
//
// Walks the rendered DOM (visible AND off-viewport) and reports every text run
// and image element to the native side over the `BulwarkBridge` interface, so
// the native classifiers can pre-check content BEFORE the child reads it. On a
// hit, the native side calls back into __bulwarkCensor(id) to drop an opaque
// cover over that element's box (the cover is positioned in DOCUMENT
// coordinates, so it scrolls with the page — no native re-tracking needed).
//
// This file is plumbing only: it carries text/image references to the native
// classifiers and draws covers. It does no classification itself.
(function () {
  if (window.__bulwarkInstalled) return;
  window.__bulwarkInstalled = true;

  var ID_ATTR = 'data-bulwark-id';
  var seq = 0;
  // Element id -> the element it was assigned to, so a censor callback can find
  // the box again even if the node moved.
  var byId = Object.create(null);
  // Avoid re-emitting the same element on every mutation tick.
  var emitted = new WeakSet();

  function ensureId(el) {
    var id = el.getAttribute(ID_ATTR);
    if (!id) {
      id = 'b' + (++seq);
      el.setAttribute(ID_ATTR, id);
      byId[id] = el;
    }
    return id;
  }

  function docRect(el) {
    var r = el.getBoundingClientRect();
    // Translate viewport rect -> document coordinates (survives scroll).
    return {
      left: Math.round(r.left + window.scrollX),
      top: Math.round(r.top + window.scrollY),
      width: Math.round(r.width),
      height: Math.round(r.height),
    };
  }

  function visibleEnough(el) {
    // Skip zero-area / display:none / collapsed nodes — they carry no readable
    // content and would only add noise to the classify queue.
    var r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4) return false;
    var s = window.getComputedStyle(el);
    if (!s || s.visibility === 'hidden' || s.display === 'none') return false;
    return true;
  }

  // --- TEXT: walk text nodes, attribute each run to its parent element. ------
  function collectText() {
    var batch = [];
    var walker = document.createTreeWalker(
      document.body || document.documentElement,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: function (node) {
          var t = node.nodeValue;
          if (!t || t.trim().length < 2) return NodeFilter.FILTER_REJECT;
          var p = node.parentElement;
          if (!p) return NodeFilter.FILTER_REJECT;
          var tag = p.tagName;
          if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT') {
            return NodeFilter.FILTER_REJECT;
          }
          return NodeFilter.FILTER_ACCEPT;
        },
      },
    );
    var n;
    while ((n = walker.nextNode())) {
      var el = n.parentElement;
      if (!el || emitted.has(el) || !visibleEnough(el)) continue;
      emitted.add(el);
      var text = (el.innerText || el.textContent || '').trim();
      if (text.length < 2) continue;
      var id = ensureId(el);
      var rect = docRect(el);
      batch.push({ id: id, text: text, rect: rect });
    }
    return batch;
  }

  // --- IMAGES: every <img> element URL + its document box. -------------------
  function collectImages() {
    var batch = [];
    var imgs = document.querySelectorAll('img');
    for (var i = 0; i < imgs.length; i++) {
      var el = imgs[i];
      if (emitted.has(el) || !visibleEnough(el)) continue;
      var src = el.currentSrc || el.src;
      if (!src) continue;
      emitted.add(el);
      var id = ensureId(el);
      batch.push({ id: id, src: src, rect: docRect(el) });
    }
    return batch;
  }

  function scan() {
    try {
      var text = collectText();
      var images = collectImages();
      if (text.length || images.length) {
        BulwarkBridge.onExtract(JSON.stringify({ text: text, images: images }));
      }
    } catch (e) {
      // Plumbing must never throw into page script.
    }
  }

  // --- CENSOR: opaque cover over an element's document box. ------------------
  // Called from native (webView.evaluateJavascript) on a classifier hit.
  window.__bulwarkCensor = function (id) {
    try {
      var el = byId[id] || document.querySelector('[' + ID_ATTR + '="' + id + '"]');
      if (!el) return;
      var rect = docRect(el);
      var cover = document.createElement('div');
      cover.setAttribute('data-bulwark-cover', id);
      cover.style.position = 'absolute';
      cover.style.left = rect.left + 'px';
      cover.style.top = rect.top + 'px';
      cover.style.width = rect.width + 'px';
      cover.style.height = rect.height + 'px';
      cover.style.background = '#0F3D5C';
      cover.style.zIndex = '2147483647';
      cover.style.pointerEvents = 'auto';
      cover.style.borderRadius = '4px';
      (document.body || document.documentElement).appendChild(cover);
    } catch (e) {
      // ignore — a missing element just means nothing to cover.
    }
  };

  // Debounced re-scan on DOM mutation (SPA content, lazy images, infinite
  // scroll) — mirrors the throttle the on-device screen scan uses.
  var pending = null;
  function schedule() {
    if (pending) return;
    pending = setTimeout(function () {
      pending = null;
      scan();
    }, 400);
  }

  try {
    var mo = new MutationObserver(schedule);
    mo.observe(document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: false,
    });
  } catch (e) {
    // Older WebViews without MutationObserver still get the initial + scroll scans.
  }

  // Off-viewport content is already in the DOM, so the initial walk sees it all;
  // scroll only matters for re-measuring covers, which ride document coords.
  window.addEventListener('scroll', schedule, { passive: true });

  // Initial full-page extraction (visible + off-screen).
  scan();
})();
