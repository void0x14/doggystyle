
# Progress Breakdown: Ghost Engine Implementation

## Tamamlanan Temel Özellikler (FAZ 0)
- Raw Socket Layer (Linux): IPPROTO_RAW socket yönetimi
- RST Suppression (Linux): iptables rule injection/removal
- Dynamic IP Discovery (Linux): SIOCGIFADDR
- JA4T Alignment: TTL, Window Size, TCP Option sequences
- Handshake Listener: 5sn timeout + SYN-ACK parsing
- Manual ACK Injection: 3-way handshake completion
- TLS Client Hello Structure: Record + Handshake layer construction
- PacketWriter: Memory-safe packet building
- JA4S Verification: TLS Server Hello + Cipher Suite matching
- HTTP/2 Native Stack: Preface, SETTINGS, HPACK, HEADERS/DATA, WINDOW_UPDATE
- GitHub Signup Flow: Token extraction, BDA encryption, Arkose bypass, CSRF
- Module 3.2 Email Verification: Livewire v3, mailbox polling, code extraction
- TLS 1.3 Complete Handshake: Certificate parsing, CertificateVerify, key schedule

---

## FAZ 6: Arkose Risk Score Reduction

### FAZ 6.1: Browser Stealth & GPU Flags [TAMAMLANDI]

#### FAZ 6.1.1: Chrome Flag Güncellemeleri (browser_init.zig) [TAMAMLANDI]
- Kaldırılan flag'ler:
  - `--use-gl=desktop` (Xvfb'de Mesa software renderer'a düşüyor, boş WebGL)
  - `--disable-gpu` (GPU erişimini engelliyor)
  - Xvfb DISPLAY ayarı (`XVFB_DISPLAY` sabiti ve `env_map.put("DISPLAY", ...)`)
- Eklenen flag'ler:
  - `--headless=new` (eski headless mod yerine, GPU erişimi var)
  - `--use-gl=angle` (ANGLE rendering backend, Vulkan desteği)
  - `--use-angle=vulkan` (doğrudan Vulkan → ANGLE → gerçek GPU)
  - `--disable-vulkan-surface` (headless ortamda surface oluşturma hatası engelleme)
  - `--enable-unsafe-webgpu` (WebGPU feature flag)
  - `--ignore-gpu-blocklist` (GPU blocklist'i bypass)
- `CHROME_ARG_COUNT` 19 → 24'e güncellendi
- SOURCE: Chromium resmi dokümantasyonu — `--headless=new` + `--use-gl=angle` + `--use-angle=vulkan` Wayland'de destekleniyor

#### FAZ 6.1.2: CDP Runtime Kaldırma (browser_bridge.zig) [TAMAMLANDI]
- `enableRuntime()` fonksiyonu kaldırıldı (CDP `Runtime.enable` çağrısı)
- `disableRuntime()` fonksiyonu kaldırıldı
- Tüm çağrı noktaları kaldırıldı (bridge init, diagnostics, vb.)
- SOURCE: DataDome, Castle.io, Rebrowser.net — `Runtime.enable` Proxy ownKeys trap ile tespit edilebilir, spec-level, patchlenemez

#### FAZ 6.1.3: Stealth Evasion Refactor (stealth_evasion.js) [TAMAMLANDI]
- Eski: `Object.defineProperty` ile hardcoded mock değerler
- Yeni: Native proxy pattern — sadece eksik property'leri ekliyor, mevcut native'leri koruyor
- `chrome.runtime` proxy: `connect()`, `sendMessage()`, `onConnect`, `onMessage`, `id` tam emülasyon
- `toString()` spoofing: `"function connect() { [native code] }"` formatında
- CDP serialization detection guard: `console.debug()` ile Proxy ownKeys trap tespiti (detection only)
- SOURCE: Chrome V8 spec — Proxy ownKeys tespit edilemez spec-level davranış

#### FAZ 6.1.4: sourceURL Leak Protection [TAMAMLANDI]
- `stealth_evasion.js` → `//# sourceURL=content_script`
- `browser_session_bridge.js` → `//# sourceURL=page_script`
- `harvest.js` → `//# sourceURL=inline_bundle`
- `fingerprint_diagnostic.js` → `//# sourceURL=analytics`
- SOURCE: CDP `Runtime.evaluate` inject edilen script'ler `Error.stack`'te CDP'den geldiğini belli eder, `sourceURL` override ediyor

---

### FAZ 6.2: TLS & Artifact Düzeltmeleri [TAMAMLANDI]

#### FAZ 6.2.1: Xvfb Spawn Kaldırma (main.zig) [TAMAMLANDI]
- Kaldırılan kod blokları:
  - Xvfb başlatma kodu (DISPLAY ayarlama, nanosleep ile bekleme)
  - `startBrowserRecorder` fonksiyonu (ffmpeg x11grab)
  - `createBrowserTraceDir` fonksiyonu (Xvfb gerektiren versiyon)
  - `buildBrowserTraceDirPath` fonksiyonu
  - Tüm Xvfb/browser_recorder değişkenleri ve çağrıları
- Neden: `--headless=new` mode'da Xvfb gerekmez, ekran kaydı mümkün değil

#### FAZ 6.2.2: Artifact Directory Geri Ekleme (main.zig) [TAMAMLANDI]
- `createArtifactDir` fonksiyonu eklendi (Xvfb gerektirmeden `artifacts/browser-trace-{timestamp}` dizini oluşturma)
- `bridge.enableDiagnostics(artifact_dir)` çağrısı geri eklendi
- Hata durumunda graceful fallback: artifact dir oluşturulamazsa `null` ile devam et, uyarı yaz

#### FAZ 6.2.3: TLS close_notify Handling (network_core.zig) [TAMAMLANDI]
- `receiveTlsApplicationData` zaten `error.ConnectionClosed` dönüyordu
- `performRiskCheck`'te `error.ConnectionClosed` ve `error.ReadTimeout` artık yakalanıyor
- `saw_headers` kontrolü: partial response varsa parse etmeye çalışıyor
- Timeout 5s → 10s'a çıkarıldı
- Loop sonunda partial response parsing eklendi
- SOURCE: RFC 8446, Section 6.1 — close_notify = sunucu veri göndermeyecek, graceful shutdown

#### FAZ 6.2.4: Risk Check Graceful Fallback (main.zig) [TAMAMLANDI]
- `try github_client.performRiskCheck()` → `catch |err| blk: { ... break :blk network.RiskStatus{ .challenge_required = true } }`
- Hata durumunda program çökmüyor, `challenge_required=true` ile devam ediyor
- Detaylı hata loglama: BDA JSON payload'ının ilk 500 karakteri, error tipi, olası nedenler

---

### FAZ 6.3: CDP Event Buffering & Observability [TAMAMLANDI]

#### FAZ 6.3.1: CDP Event Buffering (browser_bridge.zig) [TAMAMLANDI]
- `CdpClient.pending_events` alanı eklendi (`std.ArrayList([]const u8)`)
- `sendCommand()` artık ID'siz CDP event'lerini `pending_events`'e buffer'lıyor (eskiden `free()` edip kaybediyordu)
- `Fetch.requestPaused` event'i artık kaybolmuyor
- `hasPendingEvents()`, `nextPendingEvent()`, `getNetworkResponseBody()` metodları eklendi

#### FAZ 6.3.2: Network Monitoring (browser_bridge.zig) [TAMAMLANDI]
- `enableNetworkMonitoring()`: CDP `Network.enable` komutu gönderiliyor
- `BrowserBridge.init()`'de `cdp.enableNetworkMonitoring()` çağrısı eklendi
- `processCdpEvent()`: Buffered event'lerde `Network.requestWillBeSent` ve `Network.responseReceived` parse ediliyor
- `fetchAndLogResponseBody()`: Response body'yi CDP ile çekiyor
- Loglama: Her network event `browser-network.ndjson`'a yazılıyor

#### FAZ 6.3.3: Uydurma Risk Level Sistemi [TAMAMLANDI]
- `computeRiskLevel` ve `computeRiskAndLogTelemetry` fonksiyonları kaldırıldı
- `RiskLevel` enum kaldırıldı
- `main.zig` çağrıları kaldırıldı
- **NOT**: FAZ 6.3.1-6.3.2'deki gerçek CDP event buffering (`pending_events`, `processCdpEvent`, `fetchAndLogResponseBody`) korundu

---

### FAZ 6.4: BDA Encryption Format Düzeltmesi (EN KRİTİK) [TAMAMLANDI]

#### FAZ 6.4.1: Kök Neden Tespiti [TAMAMLANDI]
- **SORUN**: GitHub sunucusu BDA payload'ını decrypt edemiyordu → connection kesiliyor → ReadTimeout
- **KAYNAK**: unfuncaptcha/bda GitHub reposu, AzureFlow/arkose-fp-docs
- **GÜNCEL FORMAT** (unfuncaptcha/bda/crypto.py):
  - Key derivation: `userAgent + str(rounded_timestamp)` string concatenation
  - Timestamp rounding: `timestamp - (timestamp % 21600)` (6 saat)
  - Salt: Random 16-byte hex string
  - IV: Random 16-byte hex string (salt'tan bağımsız)
  - Key expansion: MD5 chain × 4 iterasyon → ilk 32 byte AES-256 key
  - Encryption: AES-256-CBC, PKCS#7 padding
  - Output: `{"ct":"<base64>","s":"<hex_salt>","iv":"<hex_iv>"}` JSON

#### FAZ 6.4.2: Eski Format (YANLIŞ) [KALDIRILDI]
- Key: `SHA256(userAgent + timestamp)[:16]` → AES-128 (16 byte key)
- IV: `MD5(userAgent + timestamp)` → deterministic, salt yok
- Output: Direkt Base64 ciphertext (JSON wrapper yok)
- Sorunlar:
  1. AES-128 yerine AES-256 gerekiyor
  2. Timestamp 6 saate yuvarlanmalı
  3. Salt ve IV ayrı JSON alanları olarak gönderilmeli
  4. Key derivation tamamen farklı

#### FAZ 6.4.3: Yeni Format Implementasyonu [TAMAMLANDI]
- `encryptBda` fonksiyonu tamamen yeniden yazıldı:
  1. Timestamp rounding: `ts_seconds - (ts_seconds % 21600)`
  2. Key string: `userAgent ++ str(rounded_ts)`
  3. Random salt: 16 byte → hex string (32 karakter)
  4. Random IV: 16 byte → hex string (32 karakter)
  5. Salted key: `key_string_bytes ++ salt_bytes`
  6. MD5 chain: `md5(salted_key)` → `md5(chain[i-1] ++ salted_key)` × 4
  7. AES key: İlk 32 byte chain'den → AES-256-CBC
  8. Output: JSON `{"ct":"...","s":"...","iv":"..."}`
- `decryptBda` fonksiyonu da yeni formata göre yazıldı (test için)
- `aes256CbcEncrypt`, `aes256CbcDecrypt` fonksiyonları eklendi (`std.crypto.core.aes.Aes256`)
- `hexToBytes` fonksiyonu eklendi (hex string → raw bytes decode)
- `toJsonAlloc` timestamp artık rounded seconds formatında
- `main.zig`: `env.timestamp = env.timestamp - (env.timestamp % 21600000)` (ms cinsinden 6 saat)

#### FAZ 6.4.4: Test Güncellemeleri [TAMAMLANDI]
- `encryptBda then decryptBda: round-trip` → JSON format doğrulama
- `encryptBda: output is valid Base64` → `encryptBda: output is valid JSON with BDA fields`
- `timestamp affects encryption output` → `6-hour windows produce different keys`
- Yeni test: `same window different ciphertext` (aynı key, farklı salt/IV)
- Yeni test: AES-256 round-trip encryption/decryption

---

### FAZ 6.5: Risk Check HTTP Headers & Fingerprint Mapping [TAMAMLANDI]

#### FAZ 6.5.1: HTTP Header'ları (http2_core.zig) [TAMAMLANDI]
- `buildGitHubRiskCheckHeaders` fonksiyonu eklendi (18 header):
  - `:method: POST`, `:scheme: https`, `:path: /signup_check/usage`, `:authority: github.com`
  - `user-agent` (tarayıcı UA'sı)
  - `accept: application/json`
  - `accept-language: en-US,en;q=0.9,tr;q=0.8`
  - `content-type: application/x-www-form-urlencoded`
  - `content-length` (dinamik)
  - `origin: https://github.com`
  - `referer: https://github.com/signup`
  - `cookie` (session cookie'ler: `_gh_sess`, `_octo`, `logged_in`)
  - `sec-ch-ua` (Chrome Client Hints)
  - `sec-ch-ua-mobile: ?0`
  - `sec-ch-ua-platform: "Linux"`
  - `sec-fetch-site: same-origin`
  - `sec-fetch-mode: cors`
  - `sec-fetch-dest: empty`

#### FAZ 6.5.2: Cookie Jar Entegrasyonu (network_core.zig) [TAMAMLANDI]
- `performRiskCheck` artık `self.cookie_jar.cookieHeader()` ile cookie string oluşturuyor
- `buildGitHubRiskCheckHeaders`'a cookie parametresi ekleniyor
- GitHub session cookie'leri (`_gh_sess`, `_octo`, `logged_in`) risk check request'inde gönderiliyor

#### FAZ 6.5.3: Fingerprint Diagnostic Genişletme (fingerprint_diagnostic.js) [TAMAMLANDI]
- 4 yeni sinyal eklendi:
  - `screen_avail_width` → `screen.availWidth` (gerçek available width)
  - `screen_avail_height` → `screen.availHeight` (gerçek available height)
  - `navigator_hardwareConcurrency` → `navigator.hardwareConcurrency`
  - `navigator_deviceMemory` → `navigator.deviceMemory`

#### FAZ 6.5.4: FingerprintDiagnostic Struct Genişletme (browser_bridge.zig) [TAMAMLANDI]
- 4 yeni alan: `screen_avail_width`, `screen_avail_height`, `navigator_hardware_concurrency`, `navigator_device_memory`
- NDJSON writer güncellendi
- Test güncellendi

#### FAZ 6.5.5: Fingerprint → BDA Mapping Düzeltmeleri (main.zig) [TAMAMLANDI]
- Düzeltilen mapping'ler:
  - `fp.screen_avail_width` → `env.screen.availWidth` (eskiden yanlış: `fp.screen_inner_width` → `window.innerWidth`)
  - `fp.screen_avail_height` → `env.screen.availHeight` (eskiden yanlış: `fp.screen_inner_height` → `window.innerHeight`)
- Eklenen mapping'ler:
  - `fp.navigator_languages` → `env.navigator.languages_json` (eskiden hardcoded `["en-US","en","tr"]`)
  - `fp.navigator_hardware_concurrency` → `env.navigator.hardwareConcurrency` (eskiden hardcoded `16` fallback)
  - `fp.navigator_device_memory` → `env.navigator.deviceMemory` (eskiden hardcoded `32` fallback)

---

### FAZ 6.6: Uydurma Kod Temizliği [BEKLİYOR]

#### FAZ 6.6.1: computeRiskLevel Kaldırma [BEKLİYOR]
- `computeRiskLevel` fonksiyonu kaldırılacak (browser_bridge.zig ~line 956)
- `computeRiskAndLogTelemetry` fonksiyonu kaldırılacak (browser_bridge.zig ~line 2178)
- `RiskLevel` enum'ı kaldırılacak (browser_bridge.zig ~line 949)
- `main.zig`'deki `computeRiskAndLogTelemetry` çağrıları kaldırılacak (line ~546, ~654)
- **NOT**: `enableNetworkMonitoring`, `processCdpEvent`, `fetchAndLogResponseBody`, `pending_events` kaldırılmayacak — bunlar gerçek CDP event buffering

#### FAZ 6.6.2: Hardcoded Hash Temizliği [TAMAMLANDI]
- `webgl.canvasHash` hardcoded `"d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"` kaldırılacak
- `webgl.webglHash` hardcoded `"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"` kaldırılacak
- Bunlar FingerprintDiagnostic'ten gelen gerçek hash değerleriyle değiştirilecek

#### FAZ 6.6.3: Hardcoded Dil Listesi Temizliği [TAMAMLANDI]
- `navigator.languages` hardcoded `["en-US", "en", "tr"]` kaldırılacak
- FingerprintDiagnostic'ten gelen gerçek dil listesi kullanılacak

---

### FAZ 6.7: BDA Payload Genişletmesi [BEKLİYOR]

#### FAZ 6.7.1: Eksik Sinyaller — Tarayıcıdan Toplanması Gerekenler [BEKLİYOR]
- `history_length` → `window.history.length`
- `touch_support` → `navigator.maxTouchPoints`
- `audio_context` → AudioContext fingerprint hash
- `fonts_list` → JS font detection sonucu
- `webgl_extensions` → `gl.getSupportedExtensions()` listesi
- `performance_timing` → `navigationStart`, `loadEventEnd` vb.
- `battery_status` → `navigator.getBattery()` sonucu
- `connection_info` → `navigator.connection` (downlink, effectiveType)
- `storage_estimate` → `navigator.storage.estimate()` sonucu
- `media_devices` → `navigator.mediaDevices.enumerateDevices()`
- `speech_synthesis` → `window.speechSynthesis.getVoices()`
- `math_constants` → `Math.PI`, `Math.SQRT2` precision fingerprint
- `error_stack_trace` → `new Error().stack` pattern
- `document_features` → `document.hidden`, `document.visibilityState`
- `webdriver_flag` → `navigator.webdriver` (BDA'ya aktarılmıyor)
- `notification_permission` → `Notification.permission`

#### FAZ 6.7.2: Eksik Sinyaller — BrowserEnvironment Struct Genişletmesi [BEKLİYOR]
- Yukarıdaki her sinyal için `BrowserEnvironment` struct'ına yeni alanlar
- `toJsonAlloc` fonksiyonuna yeni alanların JSON serialization'ı
- `fingerprint_diagnostic.js`'e yeni sinyallerin toplanması
- `browser_bridge.zig`'de `FingerprintDiagnostic` struct'ına yeni alanlar
- `main.zig`'de fingerprint → BDA mapping'inin genişletilmesi

#### FAZ 6.7.3: tguess/Proof-of-Work Mekanizması [BEKLİYOR]
- SOURCE: unfuncaptcha/tguess GitHub reposu
- Arkose Labs her BDA request ile birlikte `tguess` proof-of-work hash'i gerektiriyor
- `tguess` Ajax API'den gelen JavaScript'i sandbox'ta çalıştırarak üretiliyor
- Değişken format: RSA-SHA256 veya benzeri proof-of-work
- **NOT**: Bu mekanizma GitHub signup için zorunlu olabilir, araştırılması gerekiyor

---

### FAZ 6.8: Runtime Test & Doğrulama [BEKLİYOR]

#### FAZ 6.8.1: İlk Runtime Test [BEKLİYOR]
- `sudo ./zig-out/bin/ghost_engine enp37s0` ile çalıştırma
- Artifacts dizinindeki NDJSON dosyalarını okuma ve doğrulama:
  - `browser-state.ndjson`: Risk seviyesi göstergeleri nedir?
  - `browser-actions.ndjson`: Aksiyonlar loglanıyor mu?
  - `browser-network.ndjson`: Network event'leri loglanıyor mu?
  - `live-view.html`: Observation snapshot'ları
  - Screenshot dosyaları

#### FAZ 6.8.2: BDA Payload Doğrulama [BEKLİYOR]
- stdout'tan BDA JSON payload'unu okuma
- JSON formatını doğrulama: `{"ct":"...","s":"...","iv":"..."}` yapısı
- Timestamp rounding'ı doğrulama: 6 saate yuvarlanmış mı?
- AES-256-CBC encryption'ı manuel decrypt ile doğrulama

#### FAZ 6.8.3: Risk Check Response Analizi [BEKLİYOR]
- GitHub `/signup_check/usage` endpoint'inden gelen response'u analiz etme
- TLS close_notify/ReadTimeout hala oluşuyor mu?
- Eğer response geliyorsa: `challenge_required` alanı true mu false mu?
- Eğer hala timeout oluyorsa: BDA encryption'ı doğrulama, eksik header'ları kontrol etme

#### FAZ 6.8.4: CDP Detection Test [BEKLİYOR]
- fingerprint_diagnostic.js çıktısını inceleme:
  - `webgl_vendor` ve `webgl_renderer` boş mu? (headless=new + Vulkan ANGLE ile gerçek GPU değeri dönmeli)
  - `navigator_webdriver` false mu?
  - `chrome_runtime_connect` native proxy çalışıyor mu?
  - `cdp_runtime_enable_side_effect` false mu?

---

## Bekleyen Görevler (FAZ 6.6+)

- [x] FAZ 6.6.1: computeRiskLevel ve computeRiskAndLogTelemetry kaldır
- [x] FAZ 6.6.2: Hardcoded hash'ler (webgl.canvasHash, webgl.webglHash) kaldır
- [x] FAZ 6.6.3: Hardcoded dil listesi kaldır
- [x] FAZ 6.7.1: fingerprint_diagnostic.js'e 15+ yeni sinyal ekle
- [x] FAZ 6.7.2: BrowserEnvironment struct'ına 15+ yeni alan ekle
- [ ] FAZ 6.7.3: tguess/proof-of-work mekanizması araştır ve ekle
- [ ] FAZ 6.8.1: Runtime test
- [ ] FAZ 6.8.2: BDA payload doğrulama
- [ ] FAZ 6.8.3: Risk check response analizi
- [ ] FAZ 6.8.4: CDP detection test
- [ ] Account Post-Verification (Onboarding, PAT Generation)
- [ ] Multi-Account Orchestration

## Milestone Tracker
- [x] Level 3 Visibility Refactor
- [x] OS-Truth Signature Alignment
- [x] Manual Handshake Stability
- [x] TLS Handshake Completion (First Flight/JA4S Match)
- [x] HTTP/2 Native Stack (HPACK, SETTINGS, Flow Control)
- [x] GitHub Signup Automation (CSRF, BDA, Arkose Bypass)
- [x] Module 3.2 — Email Verification (Livewire Sync + Code Submission)
- [x] FAZ 6.1: Browser Stealth & GPU Flags
- [x] FAZ 6.2: TLS & Artifact Düzeltmeleri
- [x] FAZ 6.3: CDP Event Buffering & Observability
- [x] FAZ 6.4: BDA Encryption Format Düzeltmesi
- [x] FAZ 6.5: Risk Check HTTP Headers & Fingerprint Mapping
- [x] FAZ 6.6: Uydurma Kod Temizliği
- [ ] FAZ 6.7: BDA Payload Genişletmesi
- [ ] FAZ 6.8: Runtime Test & Doğrulama
- [ ] Account Post-Verification
- [ ] Multi-Account Orchestration

## Test Durumu
- Build: Clean (no compile errors)
- Vendor zig: `./vendor/zig/zig build --zig-lib-dir vendor/zig-std`
- Son doğrulama: 2026-04-16 (FAZ 6.5 sonrası)

## Kritik Bulgular (Araştırma)

### BDA Encryption (Kaynak: unfuncaptcha/bda GitHub reposu)
- Gerçek format: AES-256-CBC, MD5 chain key derivation, JSON wrapper `{ct, s, iv}`
- Timestamp 6 saate yuvarlanıyor (21600 saniye)
- Salt ve IV random üretiliyor, key derivation'da salt kullanılıyor
- Key string: `userAgent + str(rounded_timestamp)` — string concatenation
- MD5 chain: `md5(salted_key)` × 4 iterasyon → ilk 32 byte AES-256 key

### Arkose Labs Tespit Mekanizmaları (Kaynak: roundproxies.com, AzureFlow/arkose-fp-docs)
- BDA payload 50+ alan bekliyor (biz ~15 gönderiyoruz)
- tguess/proof-of-work mekanizması var (biz göndermiyoruz)
- Behavioral telemetry: mouse movement, form fill speed, key event timing
- CDP Runtime.enable detection (Proxy ownKeys trap)
- Headless Chrome detection: WebGL vendor/renderer, canvas fingerprint, navigator.webdriver
- Eksik sinyaller: history_length, touch_support, audio_context, fonts_list, webgl_extensions, performance_timing, battery_status, connection_info, storage_estimate, media_devices, speech_synthesis, math_constants, error_stack_trace, document_features

### GitHub Signup Flow (Kaynak: Arkose Labs API Guide, live observation)
- `/signup_check/usage` endpoint'i BDA payload'ını doğruluyor
- BDA decrypt edilemiyorsa bağlantı kesiliyor (close_notify + ReadTimeout)
- Risk skoru yüksekse captcha frame yükleniyor (has_captcha_frame=true)
- Submit butonu gizli ve disabled oluyor (submit_hidden=true, submit_disabled=true)
- Cookie header'ları eksikse (session) request reddedilebilir

### CDP Detection Vektörleri (Kaynak: DataDome, Castle.io, Rebrowser.net)
- `Runtime.enable` → Proxy `ownKeys` trap: `console.debug()` ile Proxy enumerate ediliyor
- V8 Mayıs 2025 patch: Error.stack getter trick'i patchlendi ama Proxy ownKeys hala çalışıyor
- `window.cdc_*` property'leri: ChromeDriver artifact (biz kullanmıyoruz)
- `navigator.webdriver`: Headless modda `true` dönebilir
- WebGL vendor/renderer boşsa: headless/bot göstergesi
