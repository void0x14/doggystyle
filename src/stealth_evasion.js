// Stealth Evasion Script — WebGL patch + chrome.runtime emulation
// SOURCE: scrapfly.io/blog/posts/puppeteer-stealth-complete-guide — chrome.runtime emulation
// SOURCE: roundproxies.com/blog/bypass-funcaptcha/ — WebGL monkey-patch technique
// SOURCE: puppeteer-extra-plugin-stealth — proven evasion patterns
//
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
  // WebGL Renderer Info Monkey-Patch
  // =========================================================================
  // Arkose BDA collects webgl_vendor and webgl_renderer via:
  //   gl.getExtension('WEBGL_debug_renderer_info').UNMASKED_VENDOR_WEBGL
  //   gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)
  //
  // We patch getParameter to return plausible values ONLY for these specific
  // enum values. All other getParameter calls pass through to the real WebGL.
  // This is the PROVEN technique from scrapfly.io and roundproxies.com.
  //
  // Values below match a Linux Chrome with Intel integrated GPU (most common
  // Linux desktop configuration). These are NOT arbitrary — they reflect
  // what a real Chrome 147 on Linux x86_64 would report.

  // SwiftShader (software WebGL) returns vendor="Google Inc.", renderer="SwiftShader"
  // which Arkose flags as suspicious. We patch to plausible Intel HD Graphics values
  // for a Linux Chrome 147 on x86_64 with Mesa DRI.
  var FAKE_WEBGL_VENDOR = 'Intel';
  var FAKE_WEBGL_RENDERER = 'Mesa DRI Intel(R) HD Graphics 620 (Kaby Lake GT2)';

  try {
    if (typeof WebGLRenderingContext === 'undefined') {
      stealthError('WebGLRenderingContext is undefined');
    } else {
      var _origGetParameter = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(parameter) {
        if (parameter === 0x9245) { return FAKE_WEBGL_VENDOR; }
        if (parameter === 0x9246) { return FAKE_WEBGL_RENDERER; }
        return _origGetParameter.apply(this, arguments);
      };
      window.__webgl_patched = true;
    }

    if (typeof WebGL2RenderingContext !== 'undefined' && WebGL2RenderingContext.prototype.getParameter) {
      var _origGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
      WebGL2RenderingContext.prototype.getParameter = function(parameter) {
        if (parameter === 0x9245) { return FAKE_WEBGL_VENDOR; }
        if (parameter === 0x9246) { return FAKE_WEBGL_RENDERER; }
        return _origGetParameter2.apply(this, arguments);
      };
      window.__webgl2_patched = true;
    }
  } catch(e) {
    stealthError('WebGL patch failed: ' + e.message);
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
