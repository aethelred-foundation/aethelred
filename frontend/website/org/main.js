(function () {
  var doc = document;
  var body = doc.body;
  var root = doc.documentElement;
  var header = doc.querySelector("[data-header]");
  var progress = doc.querySelector("[data-scroll-progress]");
  var menuToggle = doc.querySelector("[data-menu-toggle]");
  var mobileMenu = doc.querySelector("[data-mobile-menu]");
  var mobileBackdrop = doc.querySelector("[data-mobile-backdrop]");
  var mobileMenuPanel = mobileMenu ? mobileMenu.querySelector(".mobile-menu-panel") : null;
  var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var parallaxEls = [];
  var cinematicSections = [];
  var ticking = false;
  var mobileMenuState = { lastFocus: null };

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function isVisibleElement(node) {
    return Boolean(node && (node.offsetWidth || node.offsetHeight || node.getClientRects().length));
  }

  function getFocusable(container) {
    if (!container) {
      return [];
    }

    return Array.prototype.slice
      .call(
        container.querySelectorAll(
          'a[href], button:not([disabled]), textarea:not([disabled]), input:not([type="hidden"]):not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )
      )
      .filter(function (node) {
        return isVisibleElement(node) && node.getAttribute("aria-hidden") !== "true";
      });
  }

  function focusNode(node) {
    if (!node || typeof node.focus !== "function") {
      return;
    }
    window.requestAnimationFrame(function () {
      node.focus();
    });
  }

  function focusFirst(container, fallback) {
    var focusables = getFocusable(container);
    if (focusables.length) {
      focusNode(focusables[0]);
      return;
    }
    if (fallback) {
      focusNode(fallback);
    }
  }

  function focusLast(container, fallback) {
    var focusables = getFocusable(container);
    if (focusables.length) {
      focusNode(focusables[focusables.length - 1]);
      return;
    }
    if (fallback) {
      focusNode(fallback);
    }
  }

  function trapFocus(container, event) {
    if (!container || event.key !== "Tab") {
      return;
    }

    var focusables = getFocusable(container);
    if (!focusables.length) {
      event.preventDefault();
      return;
    }

    var first = focusables[0];
    var last = focusables[focusables.length - 1];

    if (event.shiftKey && doc.activeElement === first) {
      event.preventDefault();
      last.focus();
      return;
    }

    if (!event.shiftKey && doc.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function normalizePath(href) {
    if (!href) {
      return "/";
    }

    var url;
    try {
      url = new URL(href, window.location.origin);
    } catch (_error) {
      return "/";
    }

    var path = url.pathname || "/";
    path = path.replace(/\/index\.html$/i, "/");
    path = path.replace(/\.html$/i, "");

    if (path.length > 1 && path.endsWith("/")) {
      path = path.slice(0, -1);
    }

    return path || "/";
  }

  function setYear() {
    var yearNode = doc.querySelector("[data-year]");
    if (yearNode) {
      yearNode.textContent = String(new Date().getFullYear());
    }
  }

  function updateHeader() {
    if (!header) {
      return;
    }

    var y = window.scrollY || 0;
    header.classList.toggle("is-scrolled", y > 22);
    header.classList.remove("is-hidden");
  }

  function updateProgress() {
    if (!progress) {
      return;
    }

    var scrollTop = window.scrollY || 0;
    var max = doc.documentElement.scrollHeight - window.innerHeight;
    var ratio = max > 0 ? (scrollTop / max) * 100 : 0;
    progress.style.width = ratio.toFixed(2) + "%";
  }

  function closeMobileMenu(restoreFocus) {
    if (!menuToggle || !mobileMenu) {
      return;
    }

    var wasOpen = menuToggle.getAttribute("aria-expanded") === "true" || mobileMenu.classList.contains("is-open");

    menuToggle.setAttribute("aria-expanded", "false");
    mobileMenu.classList.remove("is-open");
    body.classList.remove("menu-open");
    mobileMenu.setAttribute("aria-hidden", "true");
    if (mobileMenuPanel) {
      mobileMenuPanel.setAttribute("aria-hidden", "true");
    }
    if (wasOpen && restoreFocus !== false) {
      focusNode(mobileMenuState.lastFocus || menuToggle);
    }
    mobileMenuState.lastFocus = null;
  }

  function openMobileMenu() {
    if (!menuToggle || !mobileMenu) {
      return;
    }

    mobileMenuState.lastFocus = doc.activeElement;
    menuToggle.setAttribute("aria-expanded", "true");
    mobileMenu.classList.add("is-open");
    body.classList.add("menu-open");
    mobileMenu.setAttribute("aria-hidden", "false");
    if (mobileMenuPanel) {
      mobileMenuPanel.setAttribute("aria-hidden", "false");
      focusFirst(mobileMenuPanel, mobileMenuPanel);
    }
  }

  function bindMobileMenu() {
    if (!menuToggle || !mobileMenu) {
      return;
    }

    mobileMenu.setAttribute("aria-hidden", "true");
    if (mobileMenuPanel) {
      if (!mobileMenuPanel.id) {
        mobileMenuPanel.id = "mobile-menu-panel";
      }
      mobileMenuPanel.setAttribute("tabindex", "-1");
      mobileMenuPanel.setAttribute("aria-hidden", "true");
      menuToggle.setAttribute("aria-controls", mobileMenuPanel.id);
    }

    menuToggle.addEventListener("click", function () {
      var expanded = menuToggle.getAttribute("aria-expanded") === "true";
      if (expanded) {
        closeMobileMenu();
      } else {
        openMobileMenu();
      }
    });

    if (mobileBackdrop) {
      mobileBackdrop.addEventListener("click", closeMobileMenu);
    }

    mobileMenu.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        closeMobileMenu(false);
      });
    });

    doc.addEventListener("keydown", function (event) {
      if (menuToggle.getAttribute("aria-expanded") !== "true") {
        return;
      }

      if (event.key === "Escape") {
        event.preventDefault();
        closeMobileMenu();
        return;
      }

      if (mobileMenuPanel) {
        trapFocus(mobileMenuPanel, event);
      }
    });
  }

  function bindDropdowns() {
    var dropdowns = Array.prototype.slice.call(doc.querySelectorAll("[data-dropdown]"));
    if (!dropdowns.length) {
      return;
    }

    var closeTimer = null;

    function clearCloseTimer() {
      if (closeTimer) {
        window.clearTimeout(closeTimer);
        closeTimer = null;
      }
    }

    function getDropdownItems(panel) {
      return getFocusable(panel).filter(function (node) {
        return node.matches("a, button, [role='menuitem']");
      });
    }

    function closeDropdown(dropdown, restoreFocus) {
      if (!dropdown) {
        return;
      }

      var trigger = dropdown.querySelector("[data-dropdown-trigger]");
      var panel = dropdown.querySelector("[data-dropdown-panel]");
      if (!trigger || !panel) {
        return;
      }

      trigger.setAttribute("aria-expanded", "false");
      panel.classList.remove("open");
      panel.setAttribute("aria-hidden", "true");
      if (restoreFocus) {
        focusNode(trigger);
      }
    }

    function openDropdown(dropdown, focusMode) {
      if (!dropdown) {
        return;
      }

      var trigger = dropdown.querySelector("[data-dropdown-trigger]");
      var panel = dropdown.querySelector("[data-dropdown-panel]");
      if (!trigger || !panel) {
        return;
      }

      closeAllDropdowns(dropdown, false);
      trigger.setAttribute("aria-expanded", "true");
      panel.classList.add("open");
      panel.setAttribute("aria-hidden", "false");

      if (focusMode === "first") {
        focusFirst(panel);
      } else if (focusMode === "last") {
        focusLast(panel);
      }
    }

    function closeAllDropdowns(except, restoreFocus) {
      clearCloseTimer();
      dropdowns.forEach(function (dropdown) {
        if (dropdown === except) {
          return;
        }
        closeDropdown(dropdown, restoreFocus);
      });
    }

    dropdowns.forEach(function (dropdown, index) {
      var trigger = dropdown.querySelector("[data-dropdown-trigger]");
      var panel = dropdown.querySelector("[data-dropdown-panel]");
      if (!trigger || !panel) {
        return;
      }

      if (!panel.id) {
        panel.id = "dropdown-panel-" + index;
      }
      trigger.setAttribute("aria-controls", panel.id);
      panel.setAttribute("role", "menu");
      panel.setAttribute("aria-hidden", "true");
      panel.querySelectorAll("a").forEach(function (item) {
        item.setAttribute("role", "menuitem");
      });

      trigger.addEventListener("click", function (event) {
        event.preventDefault();
        clearCloseTimer();
        var expanded = trigger.getAttribute("aria-expanded") === "true";
        if (expanded) {
          closeDropdown(dropdown, true);
          return;
        }
        openDropdown(dropdown);
      });

      trigger.addEventListener("keydown", function (event) {
        if (event.key === "ArrowDown" || event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openDropdown(dropdown, "first");
        }

        if (event.key === "ArrowUp") {
          event.preventDefault();
          openDropdown(dropdown, "last");
        }
      });

      dropdown.addEventListener("mouseenter", function () {
        if (window.innerWidth <= 980) {
          return;
        }
        clearCloseTimer();
        openDropdown(dropdown);
      });

      dropdown.addEventListener("mouseleave", function () {
        if (window.innerWidth <= 980) {
          return;
        }
        clearCloseTimer();
        closeTimer = window.setTimeout(function () {
          closeDropdown(dropdown, false);
        }, 120);
      });

      panel.addEventListener("mouseenter", clearCloseTimer);

      dropdown.addEventListener("focusout", function (event) {
        if (dropdown.contains(event.relatedTarget)) {
          return;
        }
        closeDropdown(dropdown, false);
      });

      panel.addEventListener("keydown", function (event) {
        var items = getDropdownItems(panel);
        var currentIndex = items.indexOf(doc.activeElement);

        if (event.key === "ArrowDown") {
          event.preventDefault();
          if (!items.length) {
            return;
          }
          items[(currentIndex + 1 + items.length) % items.length].focus();
          return;
        }

        if (event.key === "ArrowUp") {
          event.preventDefault();
          if (!items.length) {
            return;
          }
          items[(currentIndex - 1 + items.length) % items.length].focus();
          return;
        }

        if (event.key === "Home") {
          event.preventDefault();
          focusFirst(panel, trigger);
          return;
        }

        if (event.key === "End") {
          event.preventDefault();
          focusLast(panel, trigger);
          return;
        }

        if (event.key === "Escape") {
          event.preventDefault();
          closeDropdown(dropdown, true);
        }
      });

      panel.querySelectorAll("a").forEach(function (item) {
        item.addEventListener("click", function () {
          closeDropdown(dropdown, false);
        });
      });
    });

    doc.addEventListener("click", function (event) {
      var clickedDropdown = event.target.closest("[data-dropdown]");
      if (!clickedDropdown) {
        closeAllDropdowns();
      }
    });

    doc.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        var activeDropdown = doc.activeElement ? doc.activeElement.closest("[data-dropdown]") : null;
        if (activeDropdown) {
          closeDropdown(activeDropdown, true);
        } else {
          closeAllDropdowns();
        }
        closeMobileMenu();
      }
    });
  }

  function iconSVG(type) {
    var icons = {
      network:
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3l7.4 4.3v9.4L12 21l-7.4-4.3V7.3L12 3z" stroke="currentColor" stroke-width="1.7"/><path d="M12 8.3l4.2 2.4v4.7L12 17.8l-4.2-2.4v-4.7L12 8.3z" stroke="currentColor" stroke-width="1.5"/></svg>',
      shield:
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3l7 3v6c0 4.5-2.7 7.7-7 9-4.3-1.3-7-4.5-7-9V6l7-3z" stroke="currentColor" stroke-width="1.7"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
      chart:
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 19h16" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M7 16V9m5 7V6m5 10v-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
      stack:
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 4l8 4-8 4-8-4 8-4z" stroke="currentColor" stroke-width="1.7"/><path d="M4 12l8 4 8-4M4 16l8 4 8-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
      github:
        '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38v-1.35c-2.23.49-2.7-1.08-2.7-1.08-.37-.93-.9-1.17-.9-1.17-.74-.5.06-.49.06-.49.82.06 1.25.84 1.25.84.73 1.24 1.92.89 2.39.68.07-.53.29-.9.52-1.11-1.78-.2-3.65-.88-3.65-3.91 0-.86.31-1.56.82-2.11-.08-.2-.36-1 .08-2.09 0 0 .67-.22 2.2.81A7.6 7.6 0 0 1 8 4.84c.68 0 1.36.09 2 .27 1.52-1.03 2.2-.81 2.2-.81.44 1.09.16 1.89.08 2.09.51.55.82 1.25.82 2.11 0 3.04-1.87 3.71-3.65 3.91.29.25.54.73.54 1.48v2.2c0 .22.15.45.55.38A8 8 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>',
      discord:
        '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M13.545 2.907A13.227 13.227 0 0 0 10.308 2c-.142.258-.307.61-.42.885a12.19 12.19 0 0 0-3.776 0A8.683 8.683 0 0 0 5.69 2a13.18 13.18 0 0 0-3.24.91C.4 5.953-.156 8.92.122 11.854a13.32 13.32 0 0 0 3.971 2.04c.322-.44.609-.908.861-1.398a8.64 8.64 0 0 1-1.357-.652c.114-.083.225-.17.333-.26 2.62 1.25 5.457 1.25 8.044 0 .109.09.22.177.333.26a8.5 8.5 0 0 1-1.36.654c.252.49.54.957.862 1.396a13.28 13.28 0 0 0 3.97-2.04c.326-3.404-.556-6.343-2.234-8.947ZM5.35 10.088c-.786 0-1.434-.723-1.434-1.612 0-.89.63-1.614 1.434-1.614.807 0 1.448.736 1.434 1.614 0 .89-.627 1.612-1.434 1.612Zm5.302 0c-.786 0-1.434-.723-1.434-1.612 0-.89.63-1.614 1.434-1.614.807 0 1.448.736 1.434 1.614 0 .89-.627 1.612-1.434 1.612Z"/></svg>',
      telegram:
        '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M22.02 3.98a1.75 1.75 0 0 0-1.86-.24L2.6 10.82a1.75 1.75 0 0 0 .09 3.27l4.7 1.58 1.7 5.19a1.75 1.75 0 0 0 3 .63l2.62-2.66 4.37 3.22a1.75 1.75 0 0 0 2.78-1.02l2.13-15.03a1.75 1.75 0 0 0-.97-2.02ZM9.2 14.3l8.86-5.53-6.9 7.12-.45 2.73L9.2 14.3Z"/></svg>',
      x:
        '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M18.9 2h3.2l-7 8 8.2 12H17l-5-7.2L5.9 22H2.7l7.5-8.5L2.4 2h6.4l4.6 6.7L18.9 2Zm-1.1 18h1.8L7.8 3.9H5.9L17.8 20Z"/></svg>',
      social:
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.7"/><path d="M8.5 12h7M12 8.5v7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
      docs:
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7 3.8h7.5L18 7.3v12.9H7z" stroke="currentColor" stroke-width="1.7"/><path d="M14.5 3.8v3.5H18M9.5 12h6M9.5 15h6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
      mail:
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M3.5 6.5h17v11h-17z" stroke="currentColor" stroke-width="1.7" rx="2"/><path d="m4.5 8 7.5 6L19.5 8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
      bolt:
        '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M13.5 3L6.8 13.3h4.8L10.5 21l6.7-10.3h-4.8L13.5 3z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>'
    };
    return icons[type] || icons.stack;
  }

  function prependIcon(node, iconType) {
    if (!node || node.querySelector(".ui-icon")) {
      return;
    }
    var icon = doc.createElement("span");
    icon.className = "ui-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.innerHTML = iconSVG(iconType);
    node.insertBefore(icon, node.firstChild);
  }

  function initIcons() {
    var dropdownIcons = ["network", "chart", "shield", "docs", "social", "stack"];
    doc.querySelectorAll(".dropdown-item strong").forEach(function (strong, index) {
      prependIcon(strong, dropdownIcons[index % dropdownIcons.length]);
    });

    var footerMap = [
      { match: /^github/i, icon: "github" },
      { match: /discord/i, icon: "discord" },
      { match: /telegram/i, icon: "telegram" },
      { match: /^x$/i, icon: "x" },
      { match: /twitter/i, icon: "x" },
      { match: /docs|developer/i, icon: "docs" },
      { match: /mail|@|inquiries/i, icon: "mail" }
    ];

    doc.querySelectorAll(".footer-list a").forEach(function (link) {
      var text = link.textContent || "";
      var selected = footerMap.find(function (entry) {
        return entry.match.test(text);
      });
      prependIcon(link, selected ? selected.icon : "social");
    });

    var statIcons = ["chart", "stack", "network", "shield", "bolt"];
    doc.querySelectorAll(".stat-card").forEach(function (card, index) {
      prependIcon(card, statIcons[index % statIcons.length]);
    });
  }

  function initReveal() {
    var nodes = Array.prototype.slice.call(doc.querySelectorAll("[data-reveal]"));
    if (!nodes.length) {
      return;
    }

    if (!("IntersectionObserver" in window)) {
      nodes.forEach(function (node) {
        node.classList.add("is-visible");
      });
      return;
    }

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) {
            return;
          }
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        });
      },
      {
        threshold: 0.12,
        rootMargin: "0px 0px -10% 0px"
      }
    );

    nodes.forEach(function (node) {
      observer.observe(node);
    });
  }

  function initCounter() {
    var counters = Array.prototype.slice.call(doc.querySelectorAll("[data-count]"));
    if (!counters.length) {
      return;
    }

    function runCounter(node) {
      var target = Number(node.getAttribute("data-count"));
      if (!Number.isFinite(target)) {
        return;
      }

      if (reducedMotion) {
        node.textContent = node.getAttribute("data-count-label") || String(target);
        return;
      }

      var duration = Number(node.getAttribute("data-count-duration")) || 1300;
      var suffix = node.getAttribute("data-count-suffix") || "";
      var prefix = node.getAttribute("data-count-prefix") || "";
      var decimals = Number(node.getAttribute("data-count-decimals")) || 0;
      var start = performance.now();

      function tick(now) {
        var elapsed = now - start;
        var ratio = Math.min(elapsed / duration, 1);
        var eased = 1 - Math.pow(1 - ratio, 3);
        var current = target * eased;
        node.textContent = prefix + current.toFixed(decimals).replace(/\.0+$/, "") + suffix;

        if (ratio < 1) {
          window.requestAnimationFrame(tick);
        } else if (node.getAttribute("data-count-label")) {
          node.textContent = node.getAttribute("data-count-label");
        }
      }

      window.requestAnimationFrame(tick);
    }

    if (!("IntersectionObserver" in window)) {
      counters.forEach(runCounter);
      return;
    }

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) {
            return;
          }
          runCounter(entry.target);
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.6 }
    );

    counters.forEach(function (node) {
      observer.observe(node);
    });
  }

  function initParallax() {
    if (reducedMotion) {
      return;
    }
    parallaxEls = Array.prototype.slice.call(doc.querySelectorAll("[data-parallax]"));
    updateParallax();
  }

  function updateParallax() {
    if (!parallaxEls.length) {
      return;
    }

    var top = window.scrollY || 0;
    parallaxEls.forEach(function (el) {
      var speed = Number(el.getAttribute("data-parallax")) || 0.08;
      var y = Math.round(top * speed);
      el.style.transform = "translate3d(0," + y + "px,0)";
    });
  }

  function initCinematicScroll() {
    cinematicSections = Array.prototype.slice.call(doc.querySelectorAll(".hero, .section"));
    updateCinematicScroll();
  }

  function updateCinematicScroll() {
    if (!cinematicSections.length || reducedMotion) {
      return;
    }

    var scrollTop = window.scrollY || 0;
    var viewport = window.innerHeight || 1;
    var heroProgress = clamp(scrollTop / (viewport * 0.9), 0, 1);
    root.style.setProperty("--hero-progress", heroProgress.toFixed(4));

    cinematicSections.forEach(function (section) {
      var rect = section.getBoundingClientRect();
      var progress = clamp((viewport - rect.top) / (viewport + rect.height), 0, 1);
      section.style.setProperty("--section-progress", progress.toFixed(3));
      section.classList.toggle("is-in-view", progress > 0.08 && progress < 0.95);
    });
  }

  function initCardTilt() {
    if (reducedMotion || window.matchMedia("(hover: none)").matches) {
      return;
    }

    var cards = Array.prototype.slice.call(
      doc.querySelectorAll(".panel, .feature-card, .metric-card, .info-card, .contact-card, .quote-card, .stat-card")
    );

    cards.forEach(function (card) {
      card.addEventListener("mousemove", function (event) {
        var rect = card.getBoundingClientRect();
        var relX = (event.clientX - rect.left) / rect.width;
        var relY = (event.clientY - rect.top) / rect.height;

        var tiltY = clamp((relX - 0.5) * 8, -5.5, 5.5);
        var tiltX = clamp((0.5 - relY) * 8, -5.5, 5.5);

        card.style.setProperty("--tilt-x", tiltX.toFixed(2) + "deg");
        card.style.setProperty("--tilt-y", tiltY.toFixed(2) + "deg");
        card.classList.add("is-tilting");
      });

      card.addEventListener("mouseleave", function () {
        card.style.removeProperty("--tilt-x");
        card.style.removeProperty("--tilt-y");
        card.classList.remove("is-tilting");
      });
    });
  }

  function highlightCurrentLinks() {
    var currentPath = normalizePath(window.location.pathname || "/");
    var navLinks = Array.prototype.slice.call(doc.querySelectorAll("[data-nav-link]"));
    navLinks.forEach(function (link) {
      var href = link.getAttribute("href");
      if (!href || href.charAt(0) === "#") {
        return;
      }
      if (normalizePath(href) === currentPath) {
        link.classList.add("is-active");
      }
    });
  }

  function bindAnchorOffset() {
    var links = Array.prototype.slice.call(doc.querySelectorAll('a[href^="#"]'));
    links.forEach(function (link) {
      link.addEventListener("click", function (event) {
        var id = link.getAttribute("href");
        if (!id || id === "#") {
          return;
        }

        var target = doc.querySelector(id);
        if (!target) {
          return;
        }

        event.preventDefault();
        var headerOffset = (header ? header.offsetHeight : 0) + 20;
        var top = target.getBoundingClientRect().top + window.scrollY - headerOffset;
        window.scrollTo({ top: top, behavior: "smooth" });
        history.pushState(null, "", id);
      });
    });
  }

  function initLeadForm() {
    var form = doc.querySelector("[data-lead-form]");
    if (!form) {
      return;
    }

    var submitBtn = form.querySelector('button[type="submit"]');
    var statusNode = form.querySelector("[data-form-status]");
    var startedAt = form.querySelector('input[name="startedAt"]');
    var honeypot = form.querySelector('input[name="website"]');
    var allowedTypes = [
      "Venture Capital",
      "Private Equity",
      "Family Office",
      "Corporate Development",
      "Sovereign / Strategic Capital"
    ];
    var allowedRegions = ["", "North America", "Europe", "MENA", "APAC", "Global / Multi-region"];

    function setStatus(kind, message) {
      if (!statusNode) {
        return;
      }
      statusNode.classList.remove("is-error", "is-success", "is-info");
      statusNode.classList.add(kind === "error" ? "is-error" : kind === "success" ? "is-success" : "is-info");
      statusNode.textContent = message;
    }

    function setBusy(isBusy) {
      form.setAttribute("aria-busy", isBusy ? "true" : "false");
      if (submitBtn) {
        submitBtn.disabled = isBusy;
      }
    }

    if (startedAt && !startedAt.value) {
      startedAt.value = new Date().toISOString();
    }

    form.addEventListener("submit", function (event) {
      event.preventDefault();

      function fieldValue(fieldName) {
        var field = form.elements.namedItem(fieldName);
        if (!field) {
          return "";
        }
        return field.value || "";
      }

      var payload = {
        name: fieldValue("name").trim(),
        email: fieldValue("email").trim(),
        institution: fieldValue("institution").trim(),
        type: fieldValue("type").trim(),
        region: fieldValue("region").trim(),
        timeline: fieldValue("timeline").trim(),
        message: fieldValue("message").trim(),
        consent: Boolean(form.elements.namedItem("consent") && form.elements.namedItem("consent").checked),
        website: honeypot ? (honeypot.value || "").trim() : "",
        startedAt: startedAt ? startedAt.value : "",
        sourcePath: window.location.pathname,
        sourceUrl: window.location.href
      };

      var errors = [];
      if (!payload.name || payload.name.length < 2) {
        errors.push("Enter your full name.");
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email)) {
        errors.push("Enter a valid work email.");
      }
      if (!payload.institution || payload.institution.length < 2) {
        errors.push("Enter your institution.");
      }
      if (!payload.type || allowedTypes.indexOf(payload.type) === -1) {
        errors.push("Select an investor type.");
      }
      if (allowedRegions.indexOf(payload.region) === -1) {
        errors.push("Select a valid jurisdiction focus.");
      }
      if (payload.timeline.length > 120) {
        errors.push("Timeline must be 120 characters or fewer.");
      }
      if (payload.message.length > 2400) {
        errors.push("Message must be 2400 characters or fewer.");
      }
      if (!payload.consent) {
        errors.push("Accept the consent notice to continue.");
      }

      if (errors.length) {
        setStatus("error", errors[0]);
        return;
      }

      setBusy(true);
      setStatus("info", "Submitting request...");

      fetch(form.getAttribute("action") || "lead-handler.php", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      })
        .then(function (response) {
          return response
            .json()
            .catch(function () {
              return { ok: false, message: "Unexpected server response." };
            })
            .then(function (data) {
              return { response: response, data: data };
            });
        })
        .then(function (result) {
          if (!result.response.ok || !result.data.ok) {
            throw new Error(result.data.message || "Unable to submit request right now.");
          }

          setStatus("success", "Request submitted. Investor relations will follow up within one business day.");
          form.reset();
          if (startedAt) {
            startedAt.value = new Date().toISOString();
          }
        })
        .catch(function (error) {
          setStatus("error", (error && error.message) || "Submission failed. Please email investors@aethelred.org.");
        })
        .finally(function () {
          setBusy(false);
        });
    });
  }

  function initCookiePreferences() {
    var COOKIE_PREF_KEY = "aethelred_cookie_prefs_v1";

    function normalizePrefs(raw) {
      var prefs = raw && typeof raw === "object" ? raw : {};
      return {
        essential: true,
        analytics: Boolean(prefs.analytics),
        marketing: Boolean(prefs.marketing),
        updatedAt: typeof prefs.updatedAt === "string" ? prefs.updatedAt : ""
      };
    }

    function readPrefs() {
      try {
        var raw = window.localStorage.getItem(COOKIE_PREF_KEY);
        if (!raw) {
          return null;
        }
        return normalizePrefs(JSON.parse(raw));
      } catch (_error) {
        return null;
      }
    }

    function savePrefs(prefs) {
      var normalized = normalizePrefs(prefs);
      normalized.updatedAt = new Date().toISOString();
      try {
        window.localStorage.setItem(COOKIE_PREF_KEY, JSON.stringify(normalized));
      } catch (_error) {
        // no-op when localStorage is unavailable
      }
      return normalized;
    }

    function applyPrefs(prefs) {
      var normalized = normalizePrefs(prefs);
      root.setAttribute("data-cookie-essential", "granted");
      root.setAttribute("data-cookie-analytics", normalized.analytics ? "granted" : "denied");
      root.setAttribute("data-cookie-marketing", normalized.marketing ? "granted" : "denied");
      if (typeof window.CustomEvent === "function") {
        window.dispatchEvent(new window.CustomEvent("aethelred:cookie-preferences", { detail: normalized }));
      }
      return normalized;
    }

    function buildCookieUi() {
      var banner = doc.createElement("section");
      banner.className = "cookie-banner";
      banner.setAttribute("aria-label", "Cookie notice");
      banner.innerHTML =
        '<div class="cookie-banner-shell">' +
        '<p class="cookie-banner-title">Cookie preferences</p>' +
        '<p class="cookie-banner-text">We use essential cookies for site operations. Optional analytics and outreach categories stay inactive unless you enable them and Aethelred activates those services.</p>' +
        '<div class="cookie-actions">' +
        '<button class="btn btn-primary" type="button" data-cookie-accept>Accept all</button>' +
        '<button class="btn btn-secondary" type="button" data-cookie-reject>Reject non essential</button>' +
        '<button class="btn btn-ghost" type="button" data-cookie-manage>Manage settings</button>' +
        '</div>' +
        '</div>';

      var backdrop = doc.createElement("div");
      backdrop.className = "cookie-modal-backdrop";
      backdrop.setAttribute("data-cookie-backdrop", "true");
      backdrop.setAttribute("aria-hidden", "true");

      var modal = doc.createElement("section");
      modal.className = "cookie-modal";
      modal.setAttribute("role", "dialog");
      modal.setAttribute("aria-modal", "true");
      modal.setAttribute("aria-label", "Cookie settings");
      modal.setAttribute("aria-hidden", "true");
      modal.setAttribute("tabindex", "-1");
      modal.innerHTML =
        '<div class="cookie-modal-shell">' +
        '<div class="cookie-modal-head">' +
        '<h3>Cookie settings</h3>' +
        '<button class="cookie-close" type="button" aria-label="Close cookie settings" data-cookie-close>&times;</button>' +
        '</div>' +
        '<p class="cookie-modal-text">Control how Aethelred stores optional cookie preferences on this device. Optional categories remain inactive unless corresponding services are introduced and you opt in.</p>' +
        '<div class="cookie-pref-grid">' +
        '<label class="cookie-pref-item">' +
        '<input class="cookie-toggle" type="checkbox" checked disabled>' +
        '<span><strong>Essential cookies</strong><p>Required for navigation, security, and core site functionality.</p></span>' +
        '</label>' +
        '<label class="cookie-pref-item">' +
        '<input class="cookie-toggle" type="checkbox" data-cookie-analytics>' +
        '<span><strong>Analytics cookies</strong><p>Reserved for future aggregate measurement tooling and disabled by default.</p></span>' +
        '</label>' +
        '<label class="cookie-pref-item">' +
        '<input class="cookie-toggle" type="checkbox" data-cookie-marketing>' +
        '<span><strong>Marketing cookies</strong><p>Reserved for future outreach and attribution tooling and disabled by default.</p></span>' +
        '</label>' +
        '</div>' +
        '<div class="cookie-actions">' +
        '<button class="btn btn-primary" type="button" data-cookie-save>Save preferences</button>' +
        '<button class="btn btn-secondary" type="button" data-cookie-accept>Accept all</button>' +
        '<button class="btn btn-ghost" type="button" data-cookie-reject>Reject non essential</button>' +
        '</div>' +
        '</div>';

      body.appendChild(banner);
      body.appendChild(backdrop);
      body.appendChild(modal);

      return {
        banner: banner,
        backdrop: backdrop,
        modal: modal,
        close: modal.querySelector("[data-cookie-close]"),
        analytics: modal.querySelector("[data-cookie-analytics]"),
        marketing: modal.querySelector("[data-cookie-marketing]")
      };
    }

    var storedPrefs = readPrefs();
    var activePrefs = applyPrefs(storedPrefs || { analytics: false, marketing: false });
    var ui = buildCookieUi();
    var lastModalFocus = null;

    function syncInputs() {
      if (ui.analytics) {
        ui.analytics.checked = Boolean(activePrefs.analytics);
      }
      if (ui.marketing) {
        ui.marketing.checked = Boolean(activePrefs.marketing);
      }
    }

    function openModal() {
      lastModalFocus = doc.activeElement;
      syncInputs();
      ui.backdrop.classList.add("open");
      ui.modal.classList.add("open");
      ui.backdrop.setAttribute("aria-hidden", "false");
      ui.modal.setAttribute("aria-hidden", "false");
      body.classList.add("cookie-modal-open");
      focusFirst(ui.modal, ui.close || ui.modal);
    }

    function closeModal() {
      ui.backdrop.classList.remove("open");
      ui.modal.classList.remove("open");
      ui.backdrop.setAttribute("aria-hidden", "true");
      ui.modal.setAttribute("aria-hidden", "true");
      body.classList.remove("cookie-modal-open");
      focusNode(lastModalFocus);
      lastModalFocus = null;
    }

    function hideBanner() {
      ui.banner.classList.remove("is-visible");
    }

    function commit(prefs) {
      activePrefs = applyPrefs(savePrefs(prefs));
      hideBanner();
      closeModal();
    }

    if (!storedPrefs) {
      ui.banner.classList.add("is-visible");
    }

    function attachActions(node) {
      if (!node) {
        return;
      }

      var acceptBtn = node.querySelector("[data-cookie-accept]");
      var rejectBtn = node.querySelector("[data-cookie-reject]");
      var manageBtn = node.querySelector("[data-cookie-manage]");
      var saveBtn = node.querySelector("[data-cookie-save]");
      var closeBtn = node.querySelector("[data-cookie-close]");

      if (acceptBtn) {
        acceptBtn.addEventListener("click", function () {
          commit({ analytics: true, marketing: true });
        });
      }

      if (rejectBtn) {
        rejectBtn.addEventListener("click", function () {
          commit({ analytics: false, marketing: false });
        });
      }

      if (manageBtn) {
        manageBtn.addEventListener("click", openModal);
      }

      if (saveBtn) {
        saveBtn.addEventListener("click", function () {
          commit({
            analytics: ui.analytics ? ui.analytics.checked : false,
            marketing: ui.marketing ? ui.marketing.checked : false
          });
        });
      }

      if (closeBtn) {
        closeBtn.addEventListener("click", closeModal);
      }
    }

    attachActions(ui.banner);
    attachActions(ui.modal);

    ui.backdrop.addEventListener("click", closeModal);

    doc.querySelectorAll("[data-cookie-settings]").forEach(function (trigger) {
      trigger.addEventListener("click", function (event) {
        event.preventDefault();
        openModal();
      });
    });

    doc.addEventListener("keydown", function (event) {
      if (ui.modal.classList.contains("open")) {
        trapFocus(ui.modal, event);
      }
      if (event.key === "Escape") {
        closeModal();
      }
    });

    window.aethelredCookieSettings = {
      open: openModal,
      getPreferences: function () {
        return normalizePrefs(readPrefs() || activePrefs);
      }
    };
  }

  function onScroll() {
    if (ticking) {
      return;
    }

    ticking = true;
    window.requestAnimationFrame(function () {
      updateHeader();
      updateProgress();
      updateParallax();
      updateCinematicScroll();
      ticking = false;
    });
  }

  function onResize() {
    if (window.innerWidth > 980) {
      closeMobileMenu();
    }
    updateCinematicScroll();
  }

  setYear();
  bindMobileMenu();
  bindDropdowns();
  initReveal();
  initCounter();
  initParallax();
  initCinematicScroll();
  initCardTilt();
  highlightCurrentLinks();
  bindAnchorOffset();
  initLeadForm();
  initIcons();
  initCookiePreferences();

  updateHeader();
  updateProgress();
  updateCinematicScroll();

  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onResize);
})();
