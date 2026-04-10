// content.js — Password Ledger Auto-Fill Content Script
// =====================================================================
// Injected into every page. Detects login forms, queries the background
// script for matching vault entries, and fills credentials automatically
// when a single match is found (or shows a picker for multiple matches).
// =====================================================================

(function () {
  "use strict";

  // Prevent double-injection
  if (window.__pwledgerContentLoaded) return;
  window.__pwledgerContentLoaded = true;

  // -----------------------------------------------------------------------
  // Constants
  // -----------------------------------------------------------------------
  const BADGE_ID      = "pwledger-autofill-badge";
  const PICKER_ID     = "pwledger-autofill-picker";
  const OVERLAY_ID    = "pwledger-autofill-overlay";
  const FILLED_ATTR   = "data-pwledger-filled";

  // -----------------------------------------------------------------------
  // Form detection utilities
  // -----------------------------------------------------------------------

  // Find all visible password fields on the page.
  function findPasswordFields() {
    const inputs = document.querySelectorAll('input[type="password"]');
    return Array.from(inputs).filter(isVisible);
  }

  // Find the most likely username/email field associated with a password field.
  // Walk backward through preceding inputs in the same form (or document).
  function findUsernameField(passwordField) {
    const form = passwordField.closest("form");
    const scope = form || document;

    // Collect all text-like inputs in the scope
    const candidates = Array.from(
      scope.querySelectorAll(
        'input[type="text"], input[type="email"], input:not([type])'
      )
    ).filter(isVisible);

    if (candidates.length === 0) return null;

    // Prefer inputs that come before the password field in DOM order.
    // Among those, pick the closest one.
    const pwIndex = getDocumentIndex(passwordField);

    let best = null;
    let bestDistance = Infinity;

    for (const c of candidates) {
      const idx = getDocumentIndex(c);
      const distance = pwIndex - idx;
      if (distance > 0 && distance < bestDistance) {
        best = c;
        bestDistance = distance;
      }
    }

    // If nothing before, fall back to first candidate in scope
    return best || candidates[0];
  }

  // Returns a rough document-order index for an element.
  function getDocumentIndex(el) {
    let idx = 0;
    const walker = document.createTreeWalker(
      document.documentElement,
      NodeFilter.SHOW_ELEMENT
    );
    while (walker.nextNode()) {
      if (walker.currentNode === el) return idx;
      idx++;
    }
    return idx;
  }

  // Check if an element is visible (not hidden, not display:none, has size).
  function isVisible(el) {
    if (!el) return false;
    const style = window.getComputedStyle(el);
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      style.opacity !== "0" &&
      el.offsetWidth > 0 &&
      el.offsetHeight > 0
    );
  }

  // -----------------------------------------------------------------------
  // Fill logic
  // -----------------------------------------------------------------------

  // Set a value on an input, dispatching events so JS frameworks pick it up.
  function setInputValue(input, value) {
    if (!input) return;

    // Use the native setter to bypass React/Vue controlled component checks
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    )?.set;

    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(input, value);
    } else {
      input.value = value;
    }

    // Dispatch events in the order a real user interaction would
    input.dispatchEvent(new Event("input",  { bubbles: true, composed: true }));
    input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
    input.dispatchEvent(new KeyboardEvent("keydown",  { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keyup",    { bubbles: true }));
  }

  // Fill the detected fields with credentials.
  function fillCredentials(username, password) {
    const pwFields = findPasswordFields();
    if (pwFields.length === 0) return;

    for (const pwField of pwFields) {
      if (pwField.getAttribute(FILLED_ATTR)) continue;

      const userField = findUsernameField(pwField);
      if (userField) {
        setInputValue(userField, username);
      }
      setInputValue(pwField, password);
      pwField.setAttribute(FILLED_ATTR, "true");
    }

    // Brief visual flash on filled fields
    showFillFeedback();

    removeUI();
  }

  // Show a brief green flash on filled fields
  function showFillFeedback() {
    const filledFields = document.querySelectorAll(`[${FILLED_ATTR}]`);
    filledFields.forEach(f => {
      f.style.transition = "box-shadow 0.3s ease";
      f.style.boxShadow = "0 0 0 2px #00c853, 0 0 8px rgba(0,200,83,0.4)";
      setTimeout(() => {
        f.style.boxShadow = "";
        f.style.transition = "";
      }, 1200);
    });

    // Also flash the username field
    const pwFields = findPasswordFields();
    pwFields.forEach(pw => {
      const u = findUsernameField(pw);
      if (u) {
        u.style.transition = "box-shadow 0.3s ease";
        u.style.boxShadow = "0 0 0 2px #00c853, 0 0 8px rgba(0,200,83,0.4)";
        setTimeout(() => {
          u.style.boxShadow = "";
          u.style.transition = "";
        }, 1200);
      }
    });
  }

  // -----------------------------------------------------------------------
  // UI: Auto-fill badge (shown near the password field)
  // -----------------------------------------------------------------------

  function createBadge(entries, passwordField) {
    removeBadge();

    const badge = document.createElement("div");
    badge.id = BADGE_ID;
    badge.title = "Password Ledger — Click to fill";
    badge.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2C9.24 2 7 4.24 7 7V10H5C3.9 10 3 10.9 3 12V20C3 21.1 3.9 22 5 22H19C20.1 22 21 21.1 21 20V12C21 10.9 20.1 10 19 10H17V7C17 4.24 14.76 2 12 2ZM12 4C13.66 4 15 5.34 15 7V10H9V7C9 5.34 10.34 4 12 4ZM12 14C13.1 14 14 14.9 14 16C14 17.1 13.1 18 12 18C10.9 18 10 17.1 10 16C10 14.9 10.9 14 12 14Z" fill="currentColor"/>
      </svg>
    `;

    badge.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (entries.length === 1) {
        requestAndFill(entries[0].uuid);
      } else {
        showPicker(entries, passwordField);
      }
    });

    // Position the badge
    document.body.appendChild(badge);
    positionBadge(badge, passwordField);
  }

  function positionBadge(badge, field) {
    const rect = field.getBoundingClientRect();
    badge.style.position = "fixed";
    badge.style.top  = `${rect.top + (rect.height - 28) / 2}px`;
    badge.style.left = `${rect.right - 34}px`;
    badge.style.zIndex = "2147483647";
  }

  function removeBadge() {
    const existing = document.getElementById(BADGE_ID);
    if (existing) existing.remove();
  }

  // -----------------------------------------------------------------------
  // UI: Multi-entry picker overlay
  // -----------------------------------------------------------------------

  function showPicker(entries, passwordField) {
    removePicker();

    // Overlay
    const overlay = document.createElement("div");
    overlay.id = OVERLAY_ID;
    overlay.addEventListener("click", () => removePicker());

    // Picker panel
    const picker = document.createElement("div");
    picker.id = PICKER_ID;

    const title = document.createElement("div");
    title.className = "pwledger-picker-title";
    title.textContent = "Choose an account";
    picker.appendChild(title);

    entries.forEach((entry) => {
      const item = document.createElement("div");
      item.className = "pwledger-picker-item";

      const pk = document.createElement("div");
      pk.className = "pwledger-picker-pk";
      pk.textContent = entry.primary_key;

      const user = document.createElement("div");
      user.className = "pwledger-picker-user";
      user.textContent = entry.username || "No username";

      item.appendChild(pk);
      item.appendChild(user);

      item.addEventListener("click", (e) => {
        e.stopPropagation();
        removePicker();
        requestAndFill(entry.uuid);
      });

      picker.appendChild(item);
    });

    // Position near the password field
    const rect = passwordField.getBoundingClientRect();
    picker.style.position = "fixed";
    picker.style.top  = `${rect.bottom + 6}px`;
    picker.style.left = `${rect.left}px`;
    picker.style.zIndex = "2147483647";

    overlay.style.position = "fixed";
    overlay.style.top = "0";
    overlay.style.left = "0";
    overlay.style.width = "100vw";
    overlay.style.height = "100vh";
    overlay.style.zIndex = "2147483646";
    overlay.style.background = "transparent";

    document.body.appendChild(overlay);
    document.body.appendChild(picker);
  }

  function removePicker() {
    const o = document.getElementById(OVERLAY_ID);
    const p = document.getElementById(PICKER_ID);
    if (o) o.remove();
    if (p) p.remove();
  }

  function removeUI() {
    removeBadge();
    removePicker();
  }

  // -----------------------------------------------------------------------
  // Communication with background
  // -----------------------------------------------------------------------

  function requestAndFill(uuid) {
    browser.runtime
      .sendMessage({ command: "fill_credentials", uuid })
      .then((response) => {
        if (response && response.status === "ok") {
          fillCredentials(response.username, response.password);
        } else {
          console.warn("Password Ledger: fill failed:", response?.message);
        }
      })
      .catch((err) => {
        console.error("Password Ledger: communication error:", err);
      });
  }

  // -----------------------------------------------------------------------
  // Listen for "do_fill" messages from background (triggered by popup)
  // -----------------------------------------------------------------------
  browser.runtime.onMessage.addListener((message) => {
    if (message.command === "do_fill") {
      fillCredentials(message.username, message.password);
    }
  });

  // -----------------------------------------------------------------------
  // Main: detect forms and query for matches
  // -----------------------------------------------------------------------

  function init() {
    const pwFields = findPasswordFields();
    if (pwFields.length === 0) return;

    // Query the background for matching credentials
    browser.runtime
      .sendMessage({ command: "page_loaded", url: location.href })
      .then((response) => {
        if (
          !response ||
          response.status !== "ok" ||
          !response.results ||
          response.results.length === 0
        ) {
          return; // No matches — do nothing
        }

        const entries = response.results;

        if (entries.length === 1) {
          // Single match — auto-fill immediately
          requestAndFill(entries[0].uuid);
        } else {
          // Multiple matches — show badge near first password field
          createBadge(entries, pwFields[0]);
        }
      })
      .catch(() => {
        // Vault likely locked or native host not running — silent failure
      });
  }

  // Run on load
  init();

  // Also observe for dynamically injected login forms (SPAs)
  const observer = new MutationObserver(() => {
    const pwFields = findPasswordFields();
    // Only re-init if there are new password fields that haven't been filled
    const unfilled = pwFields.filter(f => !f.getAttribute(FILLED_ATTR));
    if (unfilled.length > 0) {
      init();
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
})();
