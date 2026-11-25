// Theme toggle: System -> Light -> Dark, and the Analyzer page's sliders.
// The only script on the page; no inline code (CSP script-src 'self').
(function () {
  var order = ["system", "light", "dark"];
  var label = { system: "System", light: "Light", dark: "Dark" };
  function get() { try { return localStorage.getItem("bk-theme") || "system"; } catch (e) { return "system"; } }
  function apply(t) {
    if (t === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", t);
    var b = document.querySelector("[data-theme-toggle]");
    if (b) {
      var next = order[(order.indexOf(t) + 1) % order.length];
      b.textContent = "Theme: " + label[t];
      b.setAttribute("aria-label", "Theme: " + label[t] + ". Change to " + label[next]);
      b.title = "Change to " + label[next];
    }
  }
  apply(get());
  document.addEventListener("DOMContentLoaded", function () {
    apply(get());
    var b = document.querySelector("[data-theme-toggle]");
    if (!b) return;
    b.addEventListener("click", function () {
      var next = order[(order.indexOf(get()) + 1) % order.length];
      try { localStorage.setItem("bk-theme", next); } catch (e) {}
      apply(next);
    });
  });
})();

// Analyzer page: show each slider's value, and recount the 14-day preview
// from the scores the page carries (numbers only, no mail content).
document.addEventListener("DOMContentLoaded", function () {
  var q = document.getElementById("thresholds_quarantine");
  var r = document.getElementById("thresholds_review");
  if (!q || !r) return;
  var pv = document.getElementById("preview");
  var scores = pv && pv.dataset.scores ? pv.dataset.scores.split(",").map(Number) : [];
  function update() {
    [q, r].forEach(function (el) {
      var out = document.getElementById(el.dataset.out);
      if (out) out.textContent = el.value + "%";
      el.setAttribute("aria-valuetext", el.value + " percent");
    });
    if (!pv) return;
    var qv = q.value / 100, rv = r.value / 100, t = 0, v = 0;
    scores.forEach(function (x) { if (x >= qv) t++; else if (x >= rv) v++; });
    pv.querySelector('[data-would="trash"]').textContent = t;
    pv.querySelector('[data-would="review"]').textContent = v;
  }
  q.addEventListener("input", update);
  r.addEventListener("input", update);
  update();
});
