// browser-polyfill.js — Cross-browser compatibility shim
// =====================================================================
// Firefox uses the promise-based `browser.*` API.
// Chrome uses the callback-based `chrome.*` API.
//
// This shim creates a `browser` global on Chrome that wraps the key
// chrome.* APIs in promises, so the rest of the extension code can use
// `browser.*` uniformly without branching on the runtime.
//
// Only the APIs actually used by pwledger are shimmed.
// =====================================================================

(function () {
  "use strict";

  // If `browser` already exists (Firefox), nothing to do.
  if (typeof globalThis.browser !== "undefined" &&
      typeof globalThis.browser.runtime !== "undefined") {
    return;
  }

  // Chrome's `chrome` global must exist.
  if (typeof globalThis.chrome === "undefined") {
    return;
  }

  const chrome = globalThis.chrome;

  // Helper: wrap a Chrome callback-style function to return a Promise.
  function promisify(fn, thisArg) {
    return function (...args) {
      return new Promise((resolve, reject) => {
        fn.call(thisArg, ...args, (...results) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(results.length <= 1 ? results[0] : results);
          }
        });
      });
    };
  }

  const browser = {};

  // ---------------------------------------------------------------------------
  // browser.runtime
  // ---------------------------------------------------------------------------
  browser.runtime = {
    // Connect to a native messaging host (returns a Port — no wrapping needed).
    connectNative: chrome.runtime.connectNative
      ? chrome.runtime.connectNative.bind(chrome.runtime)
      : undefined,

    // Send a message to the extension's background script (or to an extension).
    sendMessage: promisify(chrome.runtime.sendMessage, chrome.runtime),

    // Send a single message to a native messaging host and get a response.
    sendNativeMessage: chrome.runtime.sendNativeMessage
      ? promisify(chrome.runtime.sendNativeMessage, chrome.runtime)
      : undefined,

    // Event listeners (pass through directly — they use the same .addListener API).
    onMessage: chrome.runtime.onMessage,
    onConnect: chrome.runtime.onConnect,

    // Commonly accessed properties
    get lastError() { return chrome.runtime.lastError; },
    get id() { return chrome.runtime.id; },
    getURL: chrome.runtime.getURL
      ? chrome.runtime.getURL.bind(chrome.runtime)
      : undefined,
  };

  // ---------------------------------------------------------------------------
  // browser.tabs
  // ---------------------------------------------------------------------------
  if (chrome.tabs) {
    browser.tabs = {
      query: promisify(chrome.tabs.query, chrome.tabs),
      sendMessage: promisify(chrome.tabs.sendMessage, chrome.tabs),
    };
  }

  // ---------------------------------------------------------------------------
  // browser.storage (if ever needed)
  // ---------------------------------------------------------------------------
  if (chrome.storage && chrome.storage.local) {
    browser.storage = {
      local: {
        get: promisify(chrome.storage.local.get, chrome.storage.local),
        set: promisify(chrome.storage.local.set, chrome.storage.local),
      },
    };
  }

  // Expose as a global.
  globalThis.browser = browser;
})();
