/* Zero-flicker theme engine (SRS 7.2).
   The first paint reads localStorage synchronously via the inline <head>
   script; this file only handles the switcher UI and persistence. */
(function () {
  var THEMES = [
    { id: "retro-paper", label: "Paper" },
    { id: "high-contrast", label: "Contrast" },
    { id: "colorblind-safe", label: "Colorblind" },
    { id: "monochrome-eink", label: "E-Ink" },
    { id: "amber-crt", label: "Amber" }
  ];

  function current() {
    return document.documentElement.getAttribute("data-theme") || "retro-paper";
  }

  function apply(theme) {
    if (!THEMES.some(function (t) { return t.id === theme; })) return;
    document.documentElement.setAttribute("data-theme", theme);
    try { localStorage.setItem("rwa-theme", theme); } catch (e) {}
    document.querySelectorAll("[data-theme-btn]").forEach(function (btn) {
      btn.setAttribute("aria-pressed", String(btn.dataset.themeBtn === theme));
    });
  }

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-theme-btn]");
    if (!btn) return;
    ev.preventDefault();
    apply(btn.dataset.themeBtn);
    // Mirror the preference to the server when signed in (best effort).
    if (document.querySelector('meta[name="csrf-token"]')) {
      fetch("/api/theme", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content
        },
        body: JSON.stringify({ theme: btn.dataset.themeBtn })
      }).catch(function () {});
    }
  });

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-theme-btn]").forEach(function (btn) {
      btn.setAttribute("aria-pressed", String(btn.dataset.themeBtn === current()));
    });
  });
})();
