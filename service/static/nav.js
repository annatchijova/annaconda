/* Shared chrome: theme toggle + current-page marker. Included by every page. */
(function () {
  // Restore the saved theme before paint where possible.
  try {
    var t = localStorage.getItem("anna-theme");
    if (t) document.documentElement.setAttribute("data-theme", t);
  } catch (e) {}

  function currentTheme() {
    return document.documentElement.getAttribute("data-theme")
      || (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  }
  function setTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    try { localStorage.setItem("anna-theme", t); } catch (e) {}
    var btn = document.querySelector(".theme");
    if (btn) btn.textContent = t === "dark" ? "◑" : "◐";
  }

  document.addEventListener("DOMContentLoaded", function () {
    // Mark the nav link for the page we're on.
    var here = location.pathname.replace(/\/$/, "") || "/";
    document.querySelectorAll(".nav-links a").forEach(function (a) {
      var href = a.getAttribute("href").replace(/\/$/, "") || "/";
      if (href === here) a.setAttribute("aria-current", "page");
    });
    // Wire the theme toggle.
    var btn = document.querySelector(".theme");
    if (btn) {
      btn.textContent = currentTheme() === "dark" ? "◑" : "◐";
      btn.addEventListener("click", function () {
        setTheme(currentTheme() === "dark" ? "light" : "dark");
      });
    }
  });
})();
