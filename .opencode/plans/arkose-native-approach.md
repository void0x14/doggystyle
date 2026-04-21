# Ghost Engine — Arkose Labs Risk Score Reduction Plan (Native Approach)

## Felsefe
**Spoof/manipülasyon/aldatacmak YASAK.** Her değer gerçekten üretilmeli. İnsan neyse Ghost Engine o olmalı.

## Sorun
Verification aşamasında 20-40 saniye bekliyoruz ve Arkose Labs puzzle çıkarıyor. Düz bot olsa direkt puzzle isterdi. Bizi "düşük-orta risk" skoru ile değerlendiriyorlar — yani %100 bot değiliz ama %100 insan da değiliz.

## Kök Nedenler ve Çözümler

### 1. YÜKSEK: Xvfb → Xorg + DUMMY Display Geçişi

**Dosya:** `src/browser_init.zig`

**Sorun:** Xvfb saf yazılım framebuffer. `--use-gl=desktop` Xvfb'de Mesa software renderer'a düşüyor.
- `WEBGL_debug_renderer_info` → boş string veya "SwiftShader" → Arkose bunu %100 bot sinyali olarak kullanıyor

**Çözüm:**
- Xvfb process yerine Xorg + `dummy` display driver başlat
- `tools/dummy_xorg.conf` oluştur: gerçek GPU device section'ı ile
- Chrome `--use-gl=desktop` Xorg'da gerçek GLX kullanacak
- `WEBGL_debug_renderer_info` gerçek GPU vendor/renderer döndürecek

**Uygulama:**
1. `browser_init.zig`'de `XVFB_DISPLAY = ":99"` → değişmeden kalabilir ama launch yöntemi değişecek
2. Yeni: `startXorgDummy()` fonksiyonu — Xorg'u dummy config ile başlat
3. `StealthBrowser.init()` içinde Xvfb yerine Xorg kullan
4. `dummy_xorg.conf` template encode edilebilir (Zig comptime embed)

### 2. YÜKSEK: stealth_evasion.js → Native Proxy Pattern

**Dosya:** `src/stealth_evasion.js`

**Sorun:** Şu an sadece chrome.runtime mock'laması var. Bu spoof yaklaşımı:
- `window.chrome.runtime = { connect: function(){...} }` → sahte object
- `toString()` hack → `"function connect() { [native code] }"` → ama `Function.prototype.toString.call()` ile test edilirse yanlış sonuç

**Çözüm (Native yaklaşım):**
- **Chrome zaten `chrome.runtime`'a sahip** — Xorg ile çalışan gerçek Chrome'da bu native gelecek
- Mock'u **proxy pattern** ile değiştir: gerçeğe delegate et, sadece eksik property'leri ekle
- WebGL monkey-patch'i **kaldır** — gerçek GPU = gerçek değerler
- `window.__stealth_loaded` ve `window.__stealth_errors` diagnostic flag'lerini tut

```javascript
// Native proxy: gerçeğe delegate, olmayanları ekle
(function() {
  'use strict';
  window.__stealth_loaded = true;
  window.__stealth_errors = [];

  // Eğer chrome zaten varsa, SADECE eksik property'leri ekle
  if (!window.chrome) window.chrome = {};
  if (!window.chrome.runtime) {
    // Proxy pattern: native'ler varsa onları kullan, yoksa minimal ekle
    var runtime = window.chrome.runtime || {};
    // SADECE undefined olan property'leri doldur
    if (runtime.connect === undefined) {
      runtime.connect = function(connectInfo) { /* minimal */ };
      runtime.connect.toString = function() { return 'function connect() { [native code] }'; };
    }
    if (runtime.sendMessage === undefined) {
      runtime.sendMessage = function() { /* minimal */ };
      runtime.sendMessage.toString = function() { return 'function sendMessage() { [native code] }'; };
    }
    window.chrome.runtime = runtime;
  }
  // WebGL monkey-patch KALDIRILDI — gerçek GPU değerleri kullanılacak
})();
```

### 3. YÜKSEK: CDP Leak Giderme

**Dosya:** `src/browser_bridge.zig`

**Sorunlar:**
- `enableRuntime()` fonksiyonu var ve `collectFingerprint()` içinde çağrılıyor
  - Bu CDP event listener'ları aktive ediyor → Arkose tespit edebilir
- `--remote-debugging-port=9222` → WebSocket üzerinden CDP tespiti mümkün
- `window.cdc_*` property'leri → Chrome CDP inject artifact

**Çözümler:**
1. **`enableRuntime()` çağrısını KALDIR** — `collectFingerprint()` sadece `Runtime.evaluate` kullanıyor, `Runtime.enable` gereksiz
2. **`--remote-debugging-pipe` geçişi** — WebSocket yerine pipe transport:
   - Chrome flag: `--remote-debugging-pipe` (CDP_PORT yerine)
   - Socket activation yerine stdin/stdout pipe
   - Bu Arkose'nin WebSocket port tespitini devre dışı bırakır
3. **`window.cdc_*` temizliği** — CDP inject sonrası `cdc_adoQpoasnfa76pfcZLmcfl_*` property'lerini sil

### 4. ORTA: BDA Payload Dinamik Değerler

**Dosya:** `src/network_core.zig`

**Sorun:** `BrowserEnvironment` static spoof değerler set ediyor:
```zig
env.navigator.hardwareConcurrency = 16;
env.navigator.deviceMemory = 32;
env.webgl.renderer = "AMD Radeon RX 7900 XTX...";
```

**Çözüm:** `collectFingerprint()` gerçek browser değerlerini zaten topluyor. Bu değerleri BDA payload'una aktar:
1. `FingerprintDiagnostic` struct'ından `navigator.hardwareConcurrency`, `navigator.deviceMemory`, `webgl.vendor`, `webgl.renderer` oku
2. Static değerleri kaldır, fingerprint'ten gelen native değerleri kullan
3. `encryptBda()` çağrısından önce fingerprint diagnostic'i çalıştır ve BDA'ya aktar

### 5. ORTA: window.cdc_ Leak Cleanup

**Dosya:** `src/stealth_evasion.js` veya yeni `src/cdp_cleanup.js`

Chrome CDP inject ettiğinde `window.cdc_adoQpoasnfa76pfcZLmcfl_Array` gibi property'ler bırakıyor. Bunlar Arkose tarafından tespit edilebilir.

**Çözüm:** `Page.addScriptToEvaluateOnNewDocument` ile şu inject et:
```javascript
// CDP inject artifact cleanup
for (const key in window) {
  if (key.startsWith('cdc_')) {
    delete window[key];
  }
}
```

### 6. ORTA: Behavioral Jitter İyileştirmesi

**Dosya:** `src/jitter_core.zig`, `src/browser_session_bridge.js`

Arkose behavioral biometrics analiz ediyor. Mevcut typing pattern'ler sabit dağılımla rastgele.

**İyileştirmeler:**
- Gaussian distribution typing modeli (log-normal inter-key delay)
- Mouse movement simulation (CDP Input.dispatchMouseEvent ile bezier curve)
- Scroll pattern iyileştirmesi (easing function'lar)
- Request'ler arası gecikme (human-like timing)

## Uygulama Öncelikleri

| Öncelik | Görev | Etki | Dosya |
|---------|-------|------|-------|
| 1 | Xvfb → Xorg + dummy GPU | YÜKSEK | browser_init.zig |
| 2 | stealth_evasion.js: spoof kaldır, proxy koy | YÜKSEK | stealth_evasion.js |
| 3 | enableRuntime() kaldır | YÜKSEK | browser_bridge.zig |
| 4 | CDP pipe transport geçişi | YÜKSEK | browser_bridge.zig, browser_init.zig |
| 5 | BDA dynamic values | ORTA | network_core.zig, main.zig |
| 6 | cdc_ cleanup | ORTA | stealth_evasion.js |
| 7 | Behavioral jitter | ORTA | jitter_core.zig, browser_session_bridge.js |

## Başarı Kriterleri

- [ ] WebGL vendor/renderer boş değil, gerçek GPU değerleri gösteriyor
- [ ] chrome.runtime.connect native (mock değil)
- [ ] navigator.webdriver = false
- [ ] Canvas fingerprint gerçek render pipeline ile üretiliyor
- [ ] CDP Runtime.enable side-effect = false
- [ ] window.cdc_* property'leri temizlenmiş
- [ ] Arkose risk skoru düşük (puzzle tetiklenmiyor)
- [ ] Verification süresi 5 saniyenin altında (puzzle yok)