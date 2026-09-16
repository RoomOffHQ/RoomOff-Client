/**
 * theme-manager.js by RoomOff
 * ---------------------------------------------------------------------
 * Owns the theme system for RoomOff:
 *   - Registry of available themes (each: id, name, css, optional js).
 *   - Loads ONLY the active theme's CSS (never all themes at once).
 *   - Persists the chosen theme in a cookie (1 year) so returning
 *     visitors get the right theme with zero flash (see the tiny
 *     synchronous bootstrap inline script in index.php <head>, which
 *     this file takes over from after DOMContentLoaded).
 *   - Populates the theme <select>, hiding desktop-only themes on
 *     touch devices using a robust (non width-based) heuristic.
 *   - Hands off to a theme's own controller script (e.g. the Windows OS
 *     window manager) via a tiny init()/teardown() contract, so adding
 *     a future theme never requires touching this file's core logic.
 * ---------------------------------------------------------------------
 */

(function () {
  "use strict";

  var COOKIE_NAME = "roomoff_theme";
  var COOKIE_DAYS = 365;
  var STYLE_LINK_ID = "theme-style";
  var CSS_VERSION = "20260915-1";

  var THEME_REGISTRY = [
    {
      id: "roomoff-dark",
      name: "Dark Mode",
      css: "themes/roomoff-dark/theme.css",
      desktopOnly: false
    },    
    {
      id: "roomoff-light",
      name: "Light",
      css: "themes/roomoff-light/theme.css",
      desktopOnly: false
    },    
    {
      id: "candy-girl",
      name: "Candy Girl",
      css: "themes/candy-girl/theme.css",
      desktopOnly: false
    },    
    {
      id: "titanium",
      name: "Titanium",
      css: "themes/titanium/theme.css",
      desktopOnly: false
    },    
    {
      id: "ocean-deep",
      name: "Ocean Deep",
      css: "themes/ocean-deep/theme.css",
      desktopOnly: false
    },    
    {
      id: "volcanic-hash",
      name: "Volcanic Hash",
      css: "themes/volcanic-hash/theme.css",
      desktopOnly: false
    },    
    {
      id: "nebula-dream",
      name: "Nebula Dream",
      css: "themes/nebula-dream/theme.css",
      desktopOnly: false
    }

  ];

  var DEFAULT_THEME_ID = "roomoff-dark";

  var activeTheme = null;
  var loadedControllers = {}; // path -> true once its <script> has resolved

  function setCookie(name, value, days) {
    var maxAge = days * 24 * 60 * 60;
    document.cookie =
      name + "=" + encodeURIComponent(value) +
      "; max-age=" + maxAge +
      "; path=/; samesite=lax";
  }

  function getCookie(name) {
    var escaped = name.replace(/([.$?*|{}()[\]\\/+^])/g, "\\$1");
    var match = document.cookie.match(new RegExp("(?:^|; )" + escaped + "=([^;]*)"));
    return match ? decodeURIComponent(match[1]) : null;
  }

  function isDesktopEnvironment() {
    try {
      if (window.matchMedia) {
        var fine = window.matchMedia("(pointer: fine)").matches;
        var coarse = window.matchMedia("(pointer: coarse)").matches;
        var noHover = window.matchMedia("(hover: none)").matches;
        if (fine && !coarse) return true;
        if (coarse && noHover) return false;
      }
    } catch (err) {
      /* matchMedia unsupported or malformed query — fall through */
    }
    // Fallback for older browsers without pointer/hover media features:
    // no touch points reported at all is our best remaining signal.
    return !(navigator.maxTouchPoints && navigator.maxTouchPoints > 0);
  }

  function availableThemes() {
    var desktop = isDesktopEnvironment();
    return THEME_REGISTRY.filter(function (theme) {
      return desktop || !theme.desktopOnly;
    });
  }

  function findTheme(id) {
    for (var i = 0; i < THEME_REGISTRY.length; i++) {
      if (THEME_REGISTRY[i].id === id) return THEME_REGISTRY[i];
    }
    return null;
  }

  function loadThemeCss(theme) {
    return new Promise(function (resolve) {
      var link = document.getElementById(STYLE_LINK_ID);
      var href = theme.css + "?v=" + CSS_VERSION;

      if (!link) {
        link = document.createElement("link");
        link.id = STYLE_LINK_ID;
        link.rel = "stylesheet";
        document.head.appendChild(link);
      }

      if (link.getAttribute("data-theme-id") === theme.id) {
        resolve();
        return;
      }

      var settled = false;
      var finish = function () {
        if (settled) return;
        settled = true;
        resolve();
      };

      link.addEventListener("load", finish, { once: true });
      link.addEventListener("error", finish, { once: true });
      link.setAttribute("data-theme-id", theme.id);
      link.href = href;

      // Safety net: some older browsers don't reliably fire load/error
      // for stylesheet swaps. Never let a theme switch hang forever.
      setTimeout(finish, 2000);
    });
  }

  function loadController(theme) {
    if (!theme.controller) return Promise.resolve(null);
    if (loadedControllers[theme.controller]) {
      return Promise.resolve(window[theme.controllerGlobal] || null);
    }
    return new Promise(function (resolve, reject) {
      var script = document.createElement("script");
      script.src = theme.controller + "?v=" + CSS_VERSION;
      script.onload = function () {
        loadedControllers[theme.controller] = true;
        resolve(window[theme.controllerGlobal] || null);
      };
      script.onerror = function () {
        reject(new Error("Failed to load theme controller: " + theme.controller));
      };
      document.body.appendChild(script);
    });
  }

  function applyTheme(id, options) {
    options = options || {};
    var persist = options.persist !== false;

    var theme = findTheme(id);
    if (!theme) theme = findTheme(DEFAULT_THEME_ID);
    if (theme.desktopOnly && !isDesktopEnvironment()) {
      theme = findTheme(DEFAULT_THEME_ID);
    }

    var previous = activeTheme;

    return loadThemeCss(theme).then(function () {
      document.documentElement.setAttribute("data-theme", theme.id);
      document.body.classList.remove("theme-" + (previous ? previous.id : ""));
      document.body.classList.add("theme-" + theme.id);

      // Tear down the previous theme's controller (e.g. the Windows OS
      // window manager restoring the DOM to its plain layout) before
      // handing off to the new one.
      if (previous && previous.controllerGlobal) {
        var prevController = window[previous.controllerGlobal];
        if (prevController && typeof prevController.teardown === "function") {
          try {
            prevController.teardown();
          } catch (err) {
            /* non-fatal: keep switching even if teardown had an issue */
          }
        }
      }

      activeTheme = theme;

      if (persist) setCookie(COOKIE_NAME, theme.id, COOKIE_DAYS);

      var select = document.getElementById("themeSelect");
      if (select && select.value !== theme.id) select.value = theme.id;

      return loadController(theme).then(function (controller) {
        if (controller && typeof controller.init === "function") {
          controller.init();
        }
        return theme.id;
      });
    });
  }

  function populateSelect() {
    var select = document.getElementById("themeSelect");
    if (!select) return;
    select.innerHTML = "";
    availableThemes().forEach(function (theme) {
      var option = document.createElement("option");
      option.value = theme.id;
      option.textContent = theme.name;
      select.appendChild(option);
    });
    select.addEventListener("change", function () {
      applyTheme(select.value);
    });
  }

  function boot() {
    populateSelect();

    var startId = document.documentElement.getAttribute("data-theme") ||
      getCookie(COOKIE_NAME) || DEFAULT_THEME_ID;

    var theme = findTheme(startId);
    if (!theme || (theme.desktopOnly && !isDesktopEnvironment())) {
      theme = findTheme(DEFAULT_THEME_ID);
    }

    var select = document.getElementById("themeSelect");
    if (select) select.value = theme.id;
    applyTheme(theme.id, { persist: false });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  window.RoomOffThemeManager = {
    applyTheme: applyTheme,
    isDesktopEnvironment: isDesktopEnvironment,
    availableThemes: availableThemes
  };
})();
