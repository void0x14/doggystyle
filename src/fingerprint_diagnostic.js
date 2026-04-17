// Fingerprint Diagnostic Logger — collects 25+ Arkose Labs BDA signals
// SOURCE: PRD Diagnostic Signal Specification (prd.md)
// SOURCE: puppeteer-extra-plugin-stealth evasion techniques
// SOURCE: DataDome CDP side-effect research
// SOURCE: Khronos WebGL spec — WEBGL_debug_renderer_info extension

(function() {
  'use strict';

  var result = {};

  // Helper: safely collect a signal with try/catch
  function collect(name, fn) {
    try {
      result[name] = fn();
    } catch(e) {
      result[name] = null;
    }
  }

  // === CDP/Automation Detection Signals ===

  collect('stealth_script_loaded', function() {
    return !!window.__stealth_loaded;
  });

  collect('stealth_errors', function() {
    return JSON.stringify(window.__stealth_errors || []);
  });

  collect('webgl_patched', function() {
    return !!window.__webgl_patched;
  });

  collect('chrome_runtime_emulated', function() {
    return !!window.__chrome_runtime_emulated;
  });

  collect('navigator_webdriver', function() {
    return navigator.webdriver;
  });

  collect('window_chrome_exists', function() {
    return !!(window.chrome && window.chrome !== undefined);
  });

  collect('chrome_runtime_connect', function() {
    return !!(window.chrome && window.chrome.runtime && typeof window.chrome.runtime.connect === 'function');
  });

  collect('chrome_runtime_sendMessage', function() {
    return !!(window.chrome && window.chrome.runtime && typeof window.chrome.runtime.sendMessage === 'function');
  });

  // DataDome CDP side-effect test (stack getter technique)
  // NOTE: V8 May 2025 broke this, but test anyway per research
  collect('cdp_runtime_enable_side_effect', function() {
    var detected = false;
    try {
      var e = new Error();
      Object.defineProperty(e, 'stack', {
        get: function() { detected = true; }
      });
      console.log(e);
    } catch(err) {
      // If Error construction itself fails, not CDP-related
    }
    return detected;
  });

  collect('console_debug_side_effects', function() {
    // Test if console.debug has CDP side-effects
    var hasSideEffects = false;
    var originalDebug = console.debug;
    try {
      var descriptor = Object.getOwnPropertyDescriptor(console, 'debug');
      // If descriptor exists and has getter/setter, it's been hooked by CDP
      hasSideEffects = !!(descriptor && (descriptor.get || descriptor.set));
    } catch(e) {}
    return hasSideEffects;
  });

  collect('sourceurl_leak', function() {
    // Check for __puppeteer_evaluation_script__ in stack traces
    try {
      throw new Error('test');
    } catch(e) {
      return e.stack && e.stack.indexOf('__puppeteer_evaluation_script__') !== -1;
    }
  });

  // === Browser Fingerprint Signals ===

  collect('navigator_plugins_length', function() {
    return navigator.plugins ? navigator.plugins.length : 0;
  });

  collect('navigator_plugins_names', function() {
    if (!navigator.plugins) return '';
    var names = [];
    for (var i = 0; i < navigator.plugins.length; i++) {
      names.push(navigator.plugins[i].name);
    }
    return JSON.stringify(names); // Return as JSON string for Zig parsing
  });

  collect('navigator_languages', function() {
    return JSON.stringify(navigator.languages || []); // Return as JSON string
  });

  collect('navigator_platform', function() {
    return navigator.platform || '';
  });

  collect('navigator_userAgent', function() {
    return navigator.userAgent || '';
  });

  collect('screen_width', function() {
    return screen ? screen.width : 0;
  });

  collect('screen_height', function() {
    return screen ? screen.height : 0;
  });

  collect('screen_avail_width', function() {
    return screen ? screen.availWidth : 0;
  });

  collect('screen_avail_height', function() {
    return screen ? screen.availHeight : 0;
  });

  collect('navigator_hardware_concurrency', function() {
    return navigator.hardwareConcurrency || 0;
  });

  collect('navigator_device_memory', function() {
    return navigator.deviceMemory || 0;
  });

  collect('screen_inner_width', function() {
    return window.innerWidth || 0;
  });

  collect('screen_inner_height', function() {
    return window.innerHeight || 0;
  });

  collect('screen_avail_width', function() {
    return screen ? screen.availWidth : 0;
  });

  collect('screen_avail_height', function() {
    return screen ? screen.availHeight : 0;
  });

  collect('navigator_hardwareConcurrency', function() {
    return navigator.hardwareConcurrency || 0;
  });

  collect('navigator_deviceMemory', function() {
    return navigator.deviceMemory || 0;
  });

  collect('timezone_offset', function() {
    return new Date().getTimezoneOffset();
  });

  collect('language', function() {
    return navigator.language || '';
  });

  // === WebGL/Canvas Signals ===

  collect('webgl_vendor', function() {
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl');
      if (!gl) return '';
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (!ext) return '';
      return gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '';
    } catch(e) {
      return '';
    }
  });

  collect('webgl_renderer', function() {
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl');
      if (!gl) return '';
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (!ext) return '';
      return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
    } catch(e) {
      return '';
    }
  });

  collect('canvas_hash', function() {
    try {
      var canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 50;
      var ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('Canvas fingerprint', 2, 2);
      // Return last 16 chars of data URL as hash
      var dataUrl = canvas.toDataURL();
      return dataUrl.slice(-16);
    } catch(e) {
      return '';
    }
  });

  collect('webgl_canvas_hash', function() {
    try {
      var canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 50;
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return '';
      gl.clearColor(0.0, 0.0, 0.0, 1.0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      gl.disable(gl.DEPTH_TEST);
      var dataUrl = canvas.toDataURL();
      return dataUrl.slice(-16);
    } catch(e) {
      return '';
    }
  });

  // === FAZ 6.7.1 New Signals ===

  collect('history_length', function() {
    return window.history ? window.history.length : 0;
  });

  collect('touch_support', function() {
    return navigator.maxTouchPoints || 0;
  });

  collect('audio_context', function() {
    try {
      var OfflineAudioContext = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!OfflineAudioContext) return 'not_supported';
      var ctx = new OfflineAudioContext(1, 44100, 44100);
      return ctx.sampleRate + '_' + ctx.state;
    } catch(e) {
      return 'error';
    }
  });

  collect('fonts_list', function() {
    try {
      var testFonts = ['Arial', 'Courier New', 'Times New Roman', 'Comic Sans MS', 'Impact', 'Verdana'];
      var canvas = document.createElement('canvas');
      var ctx = canvas.getContext('2d');
      var text = 'abcdefghijklmnopqrstuvwxyz0123456789';
      ctx.font = '72px monospace';
      var baselineWidth = ctx.measureText(text).width;
      var detected = [];
      for (var i = 0; i < testFonts.length; i++) {
          ctx.font = '72px "' + testFonts[i] + '", monospace';
          if (ctx.measureText(text).width !== baselineWidth) {
              detected.push(testFonts[i]);
          }
      }
      return JSON.stringify(detected);
    } catch(e) {
      return '[]';
    }
  });

  collect('webgl_extensions', function() {
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return '';
      var exts = gl.getSupportedExtensions();
      return JSON.stringify(exts || []);
    } catch(e) {
      return '[]';
    }
  });

  collect('performance_timing', function() {
    if (!window.performance || !window.performance.timing) return '{}';
    var t = window.performance.timing;
    return JSON.stringify({
      navigationStart: t.navigationStart,
      loadEventEnd: t.loadEventEnd,
      domComplete: t.domComplete
    });
  });

  collect('battery_status', function() {
    return 'getBattery' in navigator ? 'supported' : 'unsupported';
  });

  collect('connection_info', function() {
    var c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!c) return '{}';
    return JSON.stringify({
      downlink: c.downlink,
      effectiveType: c.effectiveType,
      rtt: c.rtt,
      saveData: c.saveData
    });
  });

  collect('storage_estimate', function() {
    return (navigator.storage && navigator.storage.estimate) ? 'supported' : 'unsupported';
  });

  collect('media_devices', function() {
    return (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) ? 'supported' : 'unsupported';
  });

  collect('speech_synthesis', function() {
    if (!window.speechSynthesis) return '[]';
    var voices = window.speechSynthesis.getVoices();
    return JSON.stringify(voices.map(function(v) { return v.name; }));
  });

  collect('math_constants', function() {
    return JSON.stringify({
      PI: Math.PI,
      E: Math.E,
      SQRT2: Math.SQRT2,
      LN2: Math.LN2
    });
  });

  collect('error_stack_trace', function() {
    try {
      throw new Error('test');
    } catch(e) {
      if (!e.stack) return '';
      return e.stack.split('\n')[0] + ' format';
    }
  });

  collect('document_features', function() {
    return JSON.stringify({
      hidden: document.hidden,
      visibilityState: document.visibilityState
    });
  });

  collect('webdriver_flag', function() {
    return typeof navigator.webdriver !== 'undefined' ? navigator.webdriver : false;
  });

  // === Permissions Signals ===

  collect('notification_permission', function() {
    try {
      return Notification ? Notification.permission : 'unknown';
    } catch(e) {
      return 'unknown';
    }
  });

  collect('permissions_notifications', function() {
    if (!navigator.permissions || !navigator.permissions.query) return 'unknown';
    try {
      // Permissions.query returns Promise, but we can't await in sync context
      // Return a placeholder — actual value requires async execution
      return 'query_supported';
    } catch(e) {
      return 'unknown';
    }
  });

  collect('permissions_geolocation', function() {
    if (!navigator.permissions || !navigator.permissions.query) return 'unknown';
    try {
      return 'query_supported';
    } catch(e) {
      return 'unknown';
    }
  });

  // === DOM/IFrame Signals ===

  collect('iframe_contentWindow_exists', function() {
    var iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    document.body.appendChild(iframe);
    var hasContentWindow = !!(iframe.contentWindow);
    document.body.removeChild(iframe);
    return hasContentWindow;
  });

  // Return JSON string (CDP Runtime.evaluate will capture this)
  return JSON.stringify(result);
})();
//# sourceURL=analytics
