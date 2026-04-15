// Stealth Evasion Script — chrome.runtime emulation
// SOURCE: scrapfly.io/blog/posts/puppeteer-stealth-complete-guide — chrome.runtime emulation
// SOURCE: puppeteer-extra-plugin-stealth — proven evasion patterns
//
// This script does NOT patch WebGL values. Chrome reports real GPU values.
// Injected via CDP Page.addScriptToEvaluateOnNewDocument (runs BEFORE any page JS)
// This ensures patches are in place before Arkose's enforcement.js executes.

(function() {
  'use strict';

  // DEBUG: Confirm script execution
  window.__stealth_loaded = true;
  window.__stealth_errors = [];

  function stealthError(msg) {
    window.__stealth_errors.push(msg);
  }

  // =========================================================================
  // chrome.runtime Emulation
  // =========================================================================

  try {
    if (!window.chrome) {
      window.chrome = {};
    }

    if (!window.chrome.runtime) {
      var _mockOnDisconnect = {
        addListener: function() {},
        removeListener: function() {},
        hasListener: function() { return false; },
        hasListeners: function() { return false; }
      };

      var _mockOnMessage = {
        addListener: function() {},
        removeListener: function() {},
        hasListener: function() { return false; },
        hasListeners: function() { return false; }
      };

      var _mockPort = {
        name: '',
        sender: undefined,
        onDisconnect: _mockOnDisconnect,
        onMessage: _mockOnMessage,
        postMessage: function() {},
        disconnect: function() {}
      };

      var _runtime = {
        id: undefined,
        lastError: undefined,
        connect: function(connectInfo) {
          var port = {};
          for (var key in _mockPort) {
            if (_mockPort.hasOwnProperty(key)) {
              port[key] = _mockPort[key];
            }
          }
          if (typeof connectInfo === 'object' && connectInfo.name) {
            port.name = connectInfo.name;
          }
          return port;
        },
        sendMessage: function() {
          var args = arguments;
          var callback = args[args.length - 1];
          if (typeof callback === 'function') {
            callback();
          }
        },
        onConnect: {
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
        }
      };

      window.chrome.runtime = _runtime;
      window.__chrome_runtime_emulated = true;

      // Patch toString AFTER assignment
      window.chrome.runtime.connect.toString = function() { return 'function connect() { [native code] }'; };
      window.chrome.runtime.sendMessage.toString = function() { return 'function sendMessage() { [native code] }'; };
    }
  } catch(e) {
    stealthError('chrome.runtime emulation failed: ' + e.message);
  }

})();
