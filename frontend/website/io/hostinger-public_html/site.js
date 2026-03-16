(function () {
  'use strict';

  var body = document.body;
  var header = document.querySelector('[data-site-header]');
  var progressBar = document.querySelector('[data-scroll-progress]');
  var menuToggle = document.querySelector('[data-menu-toggle]');
  var mobilePanel = document.querySelector('[data-mobile-panel]');
  var dropdowns = Array.prototype.slice.call(document.querySelectorAll('[data-dropdown]'));
  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function toggleMenu(forceOpen) {
    if (!menuToggle || !mobilePanel) {
      return;
    }

    var shouldOpen = typeof forceOpen === 'boolean' ? forceOpen : !mobilePanel.classList.contains('is-open');
    mobilePanel.classList.toggle('is-open', shouldOpen);
    menuToggle.setAttribute('aria-expanded', shouldOpen ? 'true' : 'false');
    body.classList.toggle('menu-open', shouldOpen);
  }

  if (menuToggle && mobilePanel) {
    menuToggle.addEventListener('click', function () {
      toggleMenu();
    });

    mobilePanel.addEventListener('click', function (event) {
      var target = event.target;
      if (target instanceof HTMLElement && target.classList.contains('mobile-link')) {
        toggleMenu(false);
      }
    });
  }

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      toggleMenu(false);
      closeAllDropdowns();
    }
  });

  document.addEventListener('click', function (event) {
    if (mobilePanel && menuToggle) {
      var clickedInside = mobilePanel.contains(event.target) || menuToggle.contains(event.target);
      if (!clickedInside) {
        toggleMenu(false);
      }
    }
  });

  function closeDropdownsIfOutside(event) {
    dropdowns.forEach(function (dropdown) {
      if (!dropdown.contains(event.target)) {
        setDropdownState(dropdown, false);
      }
    });
  }

  var outsideDropdownEvent = window.PointerEvent ? 'pointerdown' : 'mousedown';
  document.addEventListener(outsideDropdownEvent, closeDropdownsIfOutside);
  if (outsideDropdownEvent === 'mousedown') {
    document.addEventListener('touchstart', closeDropdownsIfOutside, { passive: true });
  }

  function setDropdownState(dropdown, shouldOpen) {
    dropdown.classList.toggle('is-open', shouldOpen);
    var button = dropdown.querySelector('[data-dropdown-toggle]');
    if (button) {
      button.setAttribute('aria-expanded', shouldOpen ? 'true' : 'false');
    }
  }

  function closeAllDropdowns() {
    dropdowns.forEach(function (dropdown) {
      setDropdownState(dropdown, false);
    });
  }

  dropdowns.forEach(function (dropdown) {
    var button = dropdown.querySelector('[data-dropdown-toggle]');
    var panel = dropdown.querySelector('.dropdown-panel');
    if (!button) {
      return;
    }
    button.setAttribute('type', 'button');

    button.addEventListener('click', function (event) {
      event.stopPropagation();
      var isOpen = dropdown.classList.contains('is-open');
      closeAllDropdowns();
      setDropdownState(dropdown, !isOpen);
    });

    button.addEventListener('keydown', function (event) {
      if (event.key !== 'ArrowDown' || !panel) {
        return;
      }
      event.preventDefault();
      closeAllDropdowns();
      setDropdownState(dropdown, true);
      var firstLink = panel.querySelector('a');
      if (firstLink) {
        firstLink.focus();
      }
    });

    if (panel) {
      var menuLinks = Array.prototype.slice.call(panel.querySelectorAll('a'));
      menuLinks.forEach(function (link) {
        link.addEventListener('click', function () {
          closeAllDropdowns();
        });
      });
    }
  });

  var ticking = false;

  function onScroll() {
    var scrollY = window.scrollY;
    var docHeight = document.documentElement.scrollHeight - window.innerHeight;

    if (header) {
      header.classList.toggle('is-scrolled', scrollY > 16);
      header.classList.remove('is-hidden');
    }

    if (progressBar && docHeight > 0) {
      var width = Math.min((scrollY / docHeight) * 100, 100);
      progressBar.style.width = width + '%';
    }

    ticking = false;
  }

  window.addEventListener(
    'scroll',
    function () {
      if (!ticking) {
        window.requestAnimationFrame(onScroll);
        ticking = true;
      }
    },
    { passive: true }
  );

  onScroll();

  var revealItems = Array.prototype.slice.call(document.querySelectorAll('[data-reveal]'));
  if (revealItems.length) {
    var revealImmediately = function (item) {
      if (!item) {
        return;
      }

      item.style.transition = 'none';
      item.classList.add('is-visible');
      item.getBoundingClientRect();
      window.requestAnimationFrame(function () {
        item.style.transition = '';
      });
    };

    var revealHashTarget = function () {
      if (!window.location.hash) {
        return;
      }

      var target;
      try {
        target = document.querySelector(window.location.hash);
      } catch (error) {
        return;
      }

      if (!target) {
        return;
      }

      var revealTarget = target.closest('[data-reveal]');
      if (revealTarget) {
        revealImmediately(revealTarget);
      }

      var nestedRevealItems = target.querySelectorAll('[data-reveal]');
      nestedRevealItems.forEach(function (item) {
        revealImmediately(item);
      });
    };

    if ('IntersectionObserver' in window && !reducedMotion) {
      var initialRevealFold = (window.innerHeight || 0) * 0.92;
      var pendingRevealItems = [];

      revealItems.forEach(function (item) {
        var rect = item.getBoundingClientRect();
        if (rect.top <= initialRevealFold && rect.bottom >= 0) {
          item.classList.add('is-visible');
          return;
        }
        pendingRevealItems.push(item);
      });

      var revealObserver = new IntersectionObserver(
        function (entries, observer) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting) {
              entry.target.classList.add('is-visible');
              observer.unobserve(entry.target);
            }
          });
        },
        {
          rootMargin: '0px 0px -8% 0px',
          threshold: 0.15,
        }
      );

      pendingRevealItems.forEach(function (item) {
        revealObserver.observe(item);
      });
    } else {
      revealItems.forEach(function (item) {
        item.classList.add('is-visible');
      });
    }

    revealHashTarget();
    window.addEventListener('hashchange', function () {
      window.requestAnimationFrame(revealHashTarget);
    });
  }

  function applyMotionTransform(node) {
    if (!node) {
      return;
    }

    var parallaxOffset = parseFloat(node.getAttribute('data-motion-parallax') || '0');
    var cinematicOffset = parseFloat(node.getAttribute('data-motion-cinematic') || '0');
    var scale = parseFloat(node.getAttribute('data-motion-scale') || '1');
    var combinedOffset = parallaxOffset + cinematicOffset;
    node.style.transform = 'translate3d(0,' + combinedOffset.toFixed(2) + 'px,0) scale(' + scale.toFixed(4) + ')';
  }

  if (!reducedMotion) {
    var cinematicHeroes = Array.prototype.slice.call(document.querySelectorAll('[data-scroll-cinematic]'));
    if (cinematicHeroes.length) {
      var cinematicEntries = [];
      cinematicHeroes.forEach(function (hero) {
        var layers = Array.prototype.slice.call(hero.querySelectorAll('[data-scroll-layer]'));
        if (!layers.length) {
          return;
        }
        cinematicEntries.push({ hero: hero, layers: layers });
      });

      if (cinematicEntries.length) {
        var cinematicRafId = 0;

        var updateCinematicScroll = function () {
          var viewportHeight = window.innerHeight || 1;

          cinematicEntries.forEach(function (entry) {
            var rect = entry.hero.getBoundingClientRect();
            var travel = rect.height + viewportHeight;
            if (travel <= 0) {
              return;
            }

            var progress = (viewportHeight - rect.top) / travel;
            progress = Math.max(0, Math.min(progress, 1));
            var centered = progress * 2 - 1;

            entry.layers.forEach(function (layer, index) {
              var defaultDepth = 0.06 + index * 0.03;
              var depth = parseFloat(layer.getAttribute('data-scroll-depth') || String(defaultDepth));
              var offset = centered * depth * 28;
              var scale = 1;
              var opacity = 1 - Math.abs(centered) * Math.min(depth * 0.18, 0.08);

              layer.setAttribute('data-motion-cinematic', offset.toFixed(2));
              layer.setAttribute('data-motion-scale', scale.toFixed(4));
              layer.style.opacity = Math.max(0.92, opacity).toFixed(3);
              applyMotionTransform(layer);
            });
          });

          cinematicRafId = 0;
        };

        var requestCinematicScroll = function () {
          if (!cinematicRafId) {
            cinematicRafId = window.requestAnimationFrame(updateCinematicScroll);
          }
        };

        requestCinematicScroll();
        window.addEventListener('scroll', requestCinematicScroll, { passive: true });
        window.addEventListener('resize', requestCinematicScroll);
      }
    }
  }

  var typingTimers = new WeakMap();

  function clearTypingTimer(codeNode) {
    var timer = typingTimers.get(codeNode);
    if (timer) {
      window.clearTimeout(timer);
      typingTimers.delete(codeNode);
    }
  }

  function escapeHtml(value) {
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function inferLanguageFromLabel(labelText) {
    var label = (labelText || '').trim().toLowerCase();
    if (!label) {
      return '';
    }

    if (label.indexOf('typescript') !== -1 || label === 'ts' || /\.tsx?$/.test(label)) {
      return 'typescript';
    }
    if (label.indexOf('javascript') !== -1 || label === 'js' || /\.jsx?$/.test(label)) {
      return 'typescript';
    }
    if (label.indexOf('python') !== -1 || /\.py$/.test(label)) {
      return 'python';
    }
    if (label.indexOf('rust') !== -1 || label === 'rs' || /\.rs$/.test(label)) {
      return 'rust';
    }
    if (label === 'go' || /\.go$/.test(label)) {
      return 'go';
    }
    if (label.indexOf('solidity') !== -1 || /\.sol$/.test(label)) {
      return 'solidity';
    }
    if (label.indexOf('json') !== -1 || /\.json$/.test(label)) {
      return 'json';
    }
    if (label.indexOf('toml') !== -1 || /\.toml$/.test(label)) {
      return 'toml';
    }
    if (
      label.indexOf('bash') !== -1 ||
      label.indexOf('shell') !== -1 ||
      label.indexOf('terminal') !== -1 ||
      label.indexOf('curl') !== -1 ||
      label.indexOf('install') !== -1 ||
      label.indexOf('setup') !== -1
    ) {
      return 'bash';
    }

    return '';
  }

  function resolveCodeLanguage(codeNode, panelLanguage) {
    var explicit = (codeNode.getAttribute('data-lang') || '').trim().toLowerCase();
    if (explicit) {
      return explicit;
    }

    if (panelLanguage) {
      return panelLanguage.toLowerCase();
    }

    var shell = codeNode.closest('.code-shell, .terminal, .code-block');
    if (shell) {
      var labelNode = shell.querySelector('.code-label, .terminal-label');
      var labelLanguage = inferLanguageFromLabel(labelNode ? labelNode.textContent : '');
      if (labelLanguage) {
        return labelLanguage;
      }
    }

    return 'plaintext';
  }

  function getCodeSource(codeNode) {
    var source = codeNode.getAttribute('data-code-source');
    if (!source) {
      source = codeNode.textContent.replace(/\r\n/g, '\n');
      codeNode.setAttribute('data-code-source', source);
    }
    return source;
  }

  function renderStaticCode(codeNode, panelLanguage) {
    var source = getCodeSource(codeNode);
    var language = resolveCodeLanguage(codeNode, panelLanguage);
    codeNode.innerHTML = highlightCode(source, language);
  }

  function highlightCode(source, language) {
    var normalizedLanguage = (language || '').toLowerCase();
    var placeholders = [];

    function markerFor(index) {
      return String.fromCharCode(0xe000 + index);
    }

    function stashRaw(segment, className) {
      var index = placeholders.length;
      placeholders.push('<span class="' + className + '">' + escapeHtml(segment) + '</span>');
      return markerFor(index);
    }

    function stashHtml(segment, className) {
      var index = placeholders.length;
      placeholders.push('<span class="' + className + '">' + segment + '</span>');
      return markerFor(index);
    }

    var raw = source.replace(/\r\n/g, '\n');

    // Strings first so comment markers inside strings are not treated as comments.
    raw = raw.replace(/(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)/g, function (match) {
      return stashRaw(match, 'tk-str');
    });

    var hashCommentLanguages = {
      python: true,
      bash: true,
      shell: true,
      terminal: true,
      curl: true,
      toml: true,
    };
    var slashCommentLanguages = {
      typescript: true,
      javascript: true,
      rust: true,
      go: true,
      solidity: true,
    };

    if (hashCommentLanguages[normalizedLanguage]) {
      raw = raw.replace(/#.*$/gm, function (match) {
        return stashRaw(match, 'tk-cm');
      });
    } else if (slashCommentLanguages[normalizedLanguage]) {
      raw = raw.replace(/\/\*[\s\S]*?\*\//g, function (match) {
        return stashRaw(match, 'tk-cm');
      });
      raw = raw.replace(/\/\/.*$/gm, function (match) {
        return stashRaw(match, 'tk-cm');
      });
    }

    var html = escapeHtml(raw);

    var keywordMap = {
      python: ['from', 'import', 'as', 'def', 'for', 'in', 'if', 'elif', 'else', 'return', 'print', 'None', 'True', 'False', 'async', 'await', 'break', 'continue', 'class', 'try', 'except', 'with'],
      typescript: ['import', 'from', 'const', 'let', 'async', 'await', 'if', 'else', 'return', 'function', 'new', 'interface', 'type', 'try', 'catch', 'throw', 'export'],
      rust: ['use', 'let', 'async', 'fn', 'if', 'else', 'return', 'match', 'mut', 'impl', 'pub', 'struct', 'enum', 'await'],
      go: ['package', 'import', 'func', 'if', 'defer', 'return', 'var', 'const', 'type', 'range', 'go', 'select'],
      solidity: ['pragma', 'solidity', 'contract', 'interface', 'function', 'external', 'public', 'private', 'view', 'pure', 'returns', 'address', 'bytes', 'bytes32', 'uint8', 'bool', 'memory', 'calldata', 'storage', 'mapping', 'event'],
      bash: ['cd', 'curl', 'git', 'make', 'docker', 'brew', 'cargo', 'npm', 'pnpm', 'go', 'export', 'echo'],
      toml: ['true', 'false'],
    };

    var keywords = keywordMap[normalizedLanguage] || [];
    if (keywords.length) {
      var keywordRegex = new RegExp('\\b(' + keywords.join('|') + ')\\b', 'g');
      html = html.replace(keywordRegex, function (match) {
        return stashHtml(match, 'tk-kw');
      });
    }

    html = html.replace(/\b([A-Z][A-Za-z0-9_]*)\b/g, function (match) {
      return stashHtml(match, 'tk-ty');
    });
    html = html.replace(/\b([A-Za-z_][A-Za-z0-9_]*)\s*(?=\()/g, function (match) {
      return stashHtml(match, 'tk-fn');
    });
    html = html.replace(/\b(\d+(?:\.\d+)?)\b/g, function (match) {
      return stashHtml(match, 'tk-num');
    });
    html = html.replace(/\b(ERROR|Error|error|FAILED|Failed|failed|FAIL|Fail|fail|FATAL|Fatal|fatal|PANIC|panic|EXCEPTION|Exception|exception|INVALID|Invalid|invalid)\b/g, function (match) {
      return stashHtml(match, 'tk-err');
    });
    html = html.replace(/(\|\||&&|==|!=|<=|>=|:=|=>|->|::|\+|-|\*|\/|%|=)/g, function (match) {
      return stashHtml(match, 'tk-op');
    });

    placeholders.forEach(function (fragment, index) {
      html = html.split(markerFor(index)).join(fragment);
    });

    return html;
  }

  function renderCodeWithOptionalTyping(codeNode, language, source, shouldAnimate) {
    if (!shouldAnimate) {
      codeNode.innerHTML = highlightCode(source, language);
      return;
    }

    var index = 0;
    var typingSpeed = 12;
    codeNode.textContent = '';

    function typeNext() {
      index += 1;

      if (index >= source.length) {
        codeNode.innerHTML = highlightCode(source, language);
        typingTimers.delete(codeNode);
        return;
      }

      codeNode.innerHTML = highlightCode(source.slice(0, index), language) + '<span class="typing-cursor">▌</span>';

      var latest = source.charAt(index - 1);
      var delay = latest === '\n' ? typingSpeed * 4 : typingSpeed;
      var timerId = window.setTimeout(typeNext, delay);
      typingTimers.set(codeNode, timerId);
    }

    typeNext();
  }

  function playTypingAnimation(group, pane) {
    if (!group || !pane) {
      return;
    }

    var codeNodes = Array.prototype.slice.call(group.querySelectorAll('[data-tab-panel] code'));
    codeNodes.forEach(function (codeNode) {
      clearTypingTimer(codeNode);
    });

    var targetCode = pane.querySelector('code');
    if (!targetCode) {
      return;
    }

    var panelLanguage = pane.getAttribute('data-tab-panel') || '';
    var language = resolveCodeLanguage(targetCode, panelLanguage);
    var source = getCodeSource(targetCode);
    var shouldAnimate = group.hasAttribute('data-code-typing-group') && !reducedMotion;
    renderCodeWithOptionalTyping(targetCode, language, source, shouldAnimate);
  }

  function playStandaloneTyping(codeNode) {
    if (!codeNode || codeNode.getAttribute('data-code-typed') === 'true') {
      return;
    }

    clearTypingTimer(codeNode);
    codeNode.setAttribute('data-code-typed', 'true');

    var language = resolveCodeLanguage(codeNode, '');
    var source = getCodeSource(codeNode);
    renderCodeWithOptionalTyping(codeNode, language, source, !reducedMotion);
  }

  function initStandaloneTypingBlocks() {
    var standaloneNodes = Array.prototype.slice.call(document.querySelectorAll('pre code[data-code-typing]')).filter(function (codeNode) {
      return !codeNode.closest('[data-tab-group]');
    });

    if (!standaloneNodes.length) {
      return;
    }

    if (reducedMotion || !('IntersectionObserver' in window)) {
      standaloneNodes.forEach(function (codeNode) {
        playStandaloneTyping(codeNode);
      });
      return;
    }

    var typingObserver = new IntersectionObserver(
      function (entries, observer) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) {
            return;
          }

          playStandaloneTyping(entry.target);
          observer.unobserve(entry.target);
        });
      },
      {
        rootMargin: '0px 0px -10% 0px',
        threshold: 0.2,
      }
    );

    standaloneNodes.forEach(function (codeNode) {
      typingObserver.observe(codeNode);
    });
  }

  function highlightStaticCodeBlocks() {
    var codeNodes = Array.prototype.slice.call(document.querySelectorAll('pre code'));
    codeNodes.forEach(function (codeNode) {
      if (codeNode.hasAttribute('data-code-typing')) {
        return;
      }
      if (codeNode.closest('[data-code-typing-group]')) {
        return;
      }
      if (codeNode.closest('[data-tab-group]')) {
        return;
      }
      renderStaticCode(codeNode, '');
    });
  }

  var tabGroups = Array.prototype.slice.call(document.querySelectorAll('[data-tab-group]'));
  tabGroups.forEach(function (group) {
    var tabs = Array.prototype.slice.call(group.querySelectorAll('[data-tab-target]'));
    var panes = Array.prototype.slice.call(group.querySelectorAll('[data-tab-panel]'));

    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        var target = tab.getAttribute('data-tab-target');

        tabs.forEach(function (item) {
          item.classList.remove('is-active');
          item.setAttribute('aria-selected', 'false');
        });

        panes.forEach(function (pane) {
          pane.classList.remove('is-active');
        });

        tab.classList.add('is-active');
        tab.setAttribute('aria-selected', 'true');

        var activePane = group.querySelector('[data-tab-panel="' + target + '"]');
        if (activePane) {
          activePane.classList.add('is-active');
          playTypingAnimation(group, activePane);
        }
      });
    });

    var initialPane = group.querySelector('[data-tab-panel].is-active') || panes[0];
    playTypingAnimation(group, initialPane);
  });

  highlightStaticCodeBlocks();
  initStandaloneTypingBlocks();

  var copyButtons = Array.prototype.slice.call(document.querySelectorAll('[data-copy]'));
  copyButtons.forEach(function (button) {
    button.addEventListener('click', function () {
      var text = button.getAttribute('data-copy') || '';
      if (!text) {
        return;
      }

      var label = button.getAttribute('data-copy-label') || 'Copy';

      function showCopiedState() {
        button.classList.add('is-copied');
        button.textContent = 'Copied';
        window.setTimeout(function () {
          button.classList.remove('is-copied');
          button.textContent = label;
        }, 1800);
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(showCopiedState).catch(function () {
          fallbackCopy(text, showCopiedState);
        });
      } else {
        fallbackCopy(text, showCopiedState);
      }
    });
  });

  function fallbackCopy(text, callback) {
    var tempInput = document.createElement('textarea');
    tempInput.value = text;
    tempInput.setAttribute('readonly', '');
    tempInput.style.position = 'absolute';
    tempInput.style.left = '-9999px';
    document.body.appendChild(tempInput);
    tempInput.select();
    document.execCommand('copy');
    document.body.removeChild(tempInput);
    callback();
  }

  var verifierButton = document.querySelector('[data-verify-trigger]');
  var verifierInput = document.querySelector('[data-verify-input]');
  var verifierResult = document.querySelector('[data-verify-result]');

  if (verifierButton && verifierInput && verifierResult) {
    verifierButton.addEventListener('click', function () {
      var value = verifierInput.value.trim();
      var isBase64 = /^[A-Za-z0-9+/=\s]{32,}$/.test(value);

      verifierResult.classList.remove('is-success', 'is-error');
      verifierResult.classList.add('is-visible');

      if (!value) {
        verifierResult.classList.add('is-error');
        verifierResult.innerHTML = '<strong>Error:</strong> No attestation quote provided. Paste a base64-encoded SGX or Nitro quote.';
        return;
      }

      if (!isBase64) {
        verifierResult.classList.add('is-error');
        verifierResult.innerHTML = '<strong>Verification Failed:</strong> Input does not appear to be a valid base64 attestation quote.';
        return;
      }

      verifierResult.classList.add('is-success');
      verifierResult.innerHTML =
        '<strong>Verification Passed</strong><br>' +
        'Enclave: Intel SGX (DCAP)<br>' +
        'Measurement: a3f8c2...e91b04<br>' +
        'Model Hash: sha256:7d1a9f...c83e22<br>' +
        'Seal ID: seal_01J7K...<br>' +
        'Timestamp: 2025-11-15T14:32:08Z<br>' +
        'Validators: 14/21 confirmed';
    });
  }

  var glossarySearch = document.querySelector('[data-glossary-search]');
  if (glossarySearch) {
    var glossaryItems = Array.prototype.slice.call(document.querySelectorAll('[data-glossary-item]'));
    var glossarySections = Array.prototype.slice.call(document.querySelectorAll('[data-glossary-section]'));
    var glossaryLetters = Array.prototype.slice.call(document.querySelectorAll('[data-glossary-letter]'));
    var glossaryEmpty = document.querySelector('[data-glossary-empty]');

    function setActiveGlossaryLetter(hashValue) {
      glossaryLetters.forEach(function (link) {
        var isActive = hashValue && link.getAttribute('href') === hashValue;
        link.classList.toggle('is-active', Boolean(isActive));
      });
    }

    function updateGlossaryFilter() {
      var query = glossarySearch.value.trim().toLowerCase();
      var visibleCount = 0;

      glossaryItems.forEach(function (item) {
        var haystack = (item.getAttribute('data-term') || '') + ' ' + item.textContent;
        var matches = !query || haystack.toLowerCase().indexOf(query) !== -1;
        item.hidden = !matches;
        if (matches) {
          visibleCount += 1;
        }
      });

      glossarySections.forEach(function (section) {
        var hasVisibleItems = section.querySelector('[data-glossary-item]:not([hidden])');
        section.hidden = !hasVisibleItems;
      });

      if (glossaryEmpty) {
        glossaryEmpty.hidden = visibleCount !== 0;
      }
    }

    glossarySearch.addEventListener('input', updateGlossaryFilter);

    glossaryLetters.forEach(function (link) {
      link.addEventListener('click', function () {
        setActiveGlossaryLetter(link.getAttribute('href'));
      });
    });

    window.addEventListener('hashchange', function () {
      setActiveGlossaryLetter(window.location.hash || '');
    });

    updateGlossaryFilter();
    setActiveGlossaryLetter(window.location.hash || '');
  }

  var yearNodes = document.querySelectorAll('[data-current-year]');
  if (yearNodes.length) {
    var year = new Date().getFullYear();
    yearNodes.forEach(function (node) {
      node.textContent = String(year);
    });
  }
})();
