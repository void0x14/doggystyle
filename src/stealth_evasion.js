// Stealth Evasion Script — Native chrome.runtime proxy
// SOURCE: Arkose Labs BDA detection research (2026-04-16)
// SOURCE: DataDome CDP side-effect research — Runtime.enable detection
// SOURCE: Castle.io — Proxy ownKeys trap detection (still unpatched)
//
// NATIVE APPROACH: Do NOT spoof/mock values that should come from real browser.
// Only ADD missing properties. Real GPU rendering provides real WebGL values.
// This script ensures chrome.runtime exists with minimal native-like stubs
// ONLY when Chrome doesn't provide them natively.
//
// Injected via CDP Page.addScriptToEvaluateOnNewDocument (runs BEFORE any page JS)

(function() {
  'use strict';

  // DEBUG: Confirm script execution
  window.__stealth_loaded = true;
  window.__stealth_errors = [];

  function stealthError(msg) {
    window.__stealth_errors.push(msg);
  }

  // =========================================================================
  // chrome.runtime Native Proxy
  // =========================================================================
  // NATIVE APPROACH: If Chrome provides chrome.runtime natively (which it does
  // in GUI mode), we only fill in missing properties. We do NOT replace existing
  // native properties. This makes the emulation undetectable by property
  // descriptor checks (getOwnPropertyDescriptor returns native-like attributes).

  try {
    if (!window.chrome) {
      window.chrome = {};
    }

    if (!window.chrome.runtime) {
      // Create a MINIMAL runtime object that passes:
      // 1. typeof chrome.runtime.connect === 'function'
      // 2. typeof chrome.runtime.sendMessage === 'function'
      // 3. chrome.runtime.connect.toString() returns native-like string
      // 4. Object.getOwnPropertyDescriptor checks show configurable/writable
      var runtime = {};

      // --- connect() stub ---
      // Only add if NOT already present natively
      if (typeof runtime.connect !== 'function') {
        var connectFn = function(connectInfo) {
          var port = {
            name: (connectInfo && connectInfo.name) ? connectInfo.name : '',
            sender: undefined,
            onDisconnect: {
              addListener: function() {},
              removeListener: function() {},
              hasListener: function() { return false; },
              hasListeners: function() { return false; }
            },
            onMessage: {
              addListener: function() {},
              removeListener: function() {},
              hasListener: function() { return false; },
              hasListeners: function() { return false; }
            },
            postMessage: function() {},
            disconnect: function() {}
          };
          return port;
        };
        connectFn.toString = function() { return 'function connect() { [native code] }'; };
        Object.defineProperty(runtime, 'connect', {
          value: connectFn,
          configurable: true,
          enumerable: true,
          writable: true
        });
      }

      // --- sendMessage() stub ---
      if (typeof runtime.sendMessage !== 'function') {
        var sendMessageFn = function() {
          var args = arguments;
          var callback = args[args.length - 1];
          if (typeof callback === 'function') {
            callback();
          }
        };
        sendMessageFn.toString = function() { return 'function sendMessage() { [native code] }'; };
        Object.defineProperty(runtime, 'sendMessage', {
          value: sendMessageFn,
          configurable: true,
          enumerable: true,
          writable: true
        });
      }

      // --- onConnect stub ---
      if (!runtime.onConnect) {
        Object.defineProperty(runtime, 'onConnect', {
          value: {
            addListener: function() {},
            removeListener: function() {},
            hasListener: function() { return false; },
            hasListeners: function() { return false; }
          },
          configurable: true,
          enumerable: true,
          writable: true
        });
      }

      // --- onMessage stub ---
      if (!runtime.onMessage) {
        Object.defineProperty(runtime, 'onMessage', {
          value: {
            addListener: function() {},
            removeListener: function() {},
            hasListener: function() { return false; },
            hasListeners: function() { return false; }
          },
          configurable: true,
          enumerable: true,
          writable: true
        });
      }

      // --- id property ---
      if (runtime.id === undefined) {
        Object.defineProperty(runtime, 'id', {
          value: undefined,
          configurable: true,
          enumerable: true,
          writable: true
        });
      }

      window.chrome.runtime = runtime;
      window.__chrome_runtime_emulated = true;
    }
  } catch(e) {
    stealthError('chrome.runtime native proxy failed: ' + e.message);
  }

  // =========================================================================
  // CDP Detection Guard — Proxy ownKeys trap detector
  // =========================================================================
  // SOURCE: Castle.io research — console.debug triggers Proxy ownKeys trap
  // when Runtime.enable is active (V8 object preview serialization)
  // SOURCE: V8 May 2025 patch — Error.stack getter trick patched, but
  //   Proxy ownKeys trick is SPEC-LEVEL and cannot be patched
  //
  // We do NOT use Runtime.enable (removed from browser_bridge.zig), so this
  // guard is a safety net. If Runtime.enable is somehow re-enabled, we detect
  // it and log a warning.
  (function detectCdpSerialization() {
    try {
      var detected = false;
      var handler = {
        ownKeys: function() {
          detected = true;
          return [];
        }
      };
      var proxy = new Proxy({}, handler);
      // console.debug is the trigger — CDP serializes arguments when Runtime.enable is active
      console.debug(proxy);
      if (detected) {
        stealthError('CDP serialization detected via Proxy ownKeys trap — Runtime.enable may be active');
      }
    } catch(e) {
      // Silently ignore — console.debug may not be available
    }
})();
})();

//# sourceURL=content_script