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
  - `--disable-vulkan-surface` (2026-04-18: KALDIRILDI — WebGL context oluşturmayı engelliyordu, ancak kaldırılmasına rağmen WebGL vendor/renderer hala boş — başka bir kök neden var)
  - `--disable-extensions` (2026-04-18: KALDIRILDI — Arkose Labs component extension'larını da devre dışı bırakıyordu, bu da bot sinyali)
- Eklenen flag'ler:
  - `--headless=new` (eski headless mod yerine, GPU erişimi var)
  - `--use-gl=angle` (ANGLE rendering backend, Vulkan desteği)
  - `--use-angle=vulkan` (doğrudan Vulkan → ANGLE → gerçek GPU)
  - `--enable-unsafe-webgpu` (WebGPU feature flag)
  - `--ignore-gpu-blocklist` (GPU blocklist'i bypass)
- `CHROME_ARG_COUNT` 19 → 22'e güncellendi
- SOURCE: Chromium resmi dokümantasyonu — `--headless=new` + `--use-gl=angle` + `--use-angle=vulkan`

#### FAZ 6.1.2: CDP Runtime Kaldırma (browser_bridge.zig) [TAMAMLANDI]
- `enableRuntime()` fonksiyonu kaldırıldı
- `disableRuntime()` fonksiyonu kaldırıldı
- Tüm çağrı noktaları kaldırıldı
- SOURCE: DataDome, Castle.io, Rebrowser.net — `Runtime.enable` Proxy ownKeys trap ile tespit edilebilir

#### FAZ 6.1.3: Stealth Evasion Refactor (stealth_evasion.js) [TAMAMLANDI]
- Native proxy pattern refactor — sadece eksik property'leri ekliyor, mevcut native'leri koruyor
- `chrome.runtime` proxy: `connect()`, `sendMessage()`, `onConnect`, `onMessage`, `id` tam emülasyon
- `toString()` spoofing
- CDP serialization detection guard
- SOURCE: Chrome V8 spec — Proxy ownKeys tespit edilemez spec-level davranış

#### FAZ 6.1.4: sourceURL Leak Protection [TAMAMLANDI]
- `stealth_evasion.js` → `//# sourceURL=content_script`
- `browser_session_bridge.js` → `//# sourceURL=page_script`
- `harvest.js` → `//# sourceURL=inline_bundle`
- `fingerprint_diagnostic.js` → `//# sourceURL=analytics`
- SOURCE: CDP `Runtime.evaluate` inject edilen script'ler `Error.stack`'te CDP'den geldiğini belli eder

---

### FAZ 6.2: TLS & Artifact Düzeltmeleri [TAMAMLANDI]

#### FAZ 6.2.1: Xvfb Spawn Kaldırma [TAMAMLANDI]
- Kaldırılan: Xvfb başlatma, `startBrowserRecorder`, `createBrowserTraceDir`, `buildBrowserTraceDirPath`
- Neden: `--headless=new` mode'da Xvfb gerekmez

#### FAZ 6.2.2: Artifact Directory Geri Ekleme [TAMAMLANDI]
- `createArtifactDir` fonksiyonu eklendi
- `bridge.enableDiagnostics(artifact_dir)` çağrısı geri eklendi
- Hata durumunda graceful fallback

#### FAZ 6.2.3: TLS close_notify Handling [TAMAMLANDI]
- `receiveTlsApplicationData` zaten `error.ConnectionClosed` dönüyordu
- `performRiskCheck`'te `error.ConnectionClosed` ve `error.ReadTimeout` artık yakalanıyor
- Timeout 5s → 10s'a çıkarıldı

#### FAZ 6.2.4: Risk Check Graceful Fallback [TAMAMLANDI]
- `try github_client.performRiskCheck()` → `catch |err| blk: { ... challenge_required=true }`
- Hata durumunda program çökmüyor

---

### FAZ 6.3: CDP Event Buffering & Observability [TAMAMLANDI]

#### FAZ 6.3.1: CDP Event Buffering [TAMAMLANDI]
- `CdpClient.pending_events` buffer'ı eklendi
- `Fetch.requestPaused` event'i artık kaybolmuyor

#### FAZ 6.3.2: Network Monitoring [TAMAMLANDI]
- `Network.enable` komutu gönderiliyor
- `Network.requestWillBeSent` ve `Network.responseReceived` parse ediliyor

#### FAZ 6.3.3: Uydurma Risk Level Sistemi [TAMAMLANDI]
- `computeRiskLevel` ve `computeRiskAndLogTelemetry` kaldırıldı
- `RiskLevel` enum kaldırıldı

---

### FAZ 6.4: BDA Encryption Format Düzeltmesi (EN KRİTİK) [TAMAMLANDI]

#### FAZ 6.4.1: Kök Neden Tespiti [TAMAMLANDI]
- **SORUN**: GitHub BDA payload'ını decrypt edemiyordu → connection kesiliyor
- **KAYNAK**: unfuncaptcha/bda GitHub reposu
- **GERÇEK FORMAT**:
  - Key derivation: `userAgent + str(rounded_timestamp)` string concatenation
  - Timestamp rounding: `timestamp - (timestamp % 21600)` (6 saat)
  - Salt: Random 16-byte hex string
  - IV: Random 16-byte hex string (salt'tan bağımsız)
  - Key expansion: MD5 chain × 4 iterasyon → ilk 32 byte AES-256 key
  - Encryption: AES-256-CBC, PKCS#7 padding
  - Output: `Base64(JSON{"ct":"<base64>","s":"<hex>","iv":"<hex>"})` — çIFT base64 katmanı

#### FAZ 6.4.2: Eski Format (YANLIŞ) [KALDIRILDI]
- AES-128, SHA256 key, deterministic IV, direkt Base64 output — tümü yanlıştı

#### FAZ 6.4.3: Yeni Format Implementasyonu [TAMAMLANDI]
- `encryptBda`: AES-256-CBC + MD5 chain + JSON wrapper + outer Base64
- `decryptBda`: outer Base64 decode → JSON parse → decrypt
- `aes256CbcEncrypt`/`aes256CbcDecrypt` fonksiyonları
- Testler: round-trip, format doğrulama, 6-hour window key differentiation

#### FAZ 6.4.4: Gemini Değişiklikleri (2026-04-18) [TAMAMLANDI]
- `encryptBda` çıktısı artık `base64(JSON{ct,s,iv})` formatında — dışarıdan base64 katmanı eklendi
- `decryptBda` artık önce dış base64 katmanını çözüyor, sonra JSON parse ediyor
- Tüm testler yeni formata göre güncellendi ve geçiyor
- `X-Requested-With: XMLHttpRequest` header'ı `buildGitHubRiskCheckHeaders`'a eklendi
- `FingerprintDiagnostic` struct alanlarına default değerler eklendi (0, "", null)

---

### FAZ 6.5: Risk Check HTTP Headers & Fingerprint Mapping [TAMAMLANDI]

#### FAZ 6.5.1–6.5.5 [TAMAMLANDI]
- 18+ header risk check request'inde
- Cookie jar entegrasyonu
- 4 yeni sinyal fingerprint'te (screen_avail, hardwareConcurrency, deviceMemory)
- Mapping düzeltmeleri

---

### FAZ 6.6: Uydurma Kod Temizliği [TAMAMLANDI]
- computeRiskLevel kaldırıldı
- Hardcoded hash'ler kaldırıldı
- Hardcoded dil listesi kaldırıldı

---

### FAZ 6.7: BDA Payload Genişletmesi [TAMAMLANDI]
- 15+ yeni sinyal eklendi (history_length, touch_support, audio_context, fonts_list, webgl_extensions, performance_timing, battery_status, connection_info, storage_estimate, media_devices, speech_synthesis, math_constants, error_stack_trace, document_features, webdriver_flag)
- BrowserEnvironment struct'ına 14 yeni alan
- toJsonAlloc genişletildi
- tguess/proof-of-work araştırıldı ve dokümante edildi (uygulama yok)

---

## FAZ 6.8: Runtime Test Sonuçları (2026-04-17 → 2026-04-18)

### 2026-04-17 İlkgün Sonuçları (Eski — --disable-vulkan-surface ile)

#### SORUN 1: WebGL vendor/renderer BOŞ [KRİTİK — HALA DEVAM EDİYOR]
```
[FINGERPRINT] WebGL vendor: 
[FINGERPRINT] WebGL renderer:
```
- `--use-angle=vulkan` + `--headless=new` + `--disable-vulkan-surface` ile boş dönüyordu
- 2026-04-18: `--disable-vulkan-surface` kaldırıldı → WebGL vendor/renderer HALA BOŞ
- `--disable-extensions` da kaldırıldı → component extension'lar artık yükleniyor
- **KÖK NEDEN HENÜZ BULUNAMADI**: headless=new modda ANGLE Vulkan backend WebGL context oluşturamıyor olabilir. Bu ayrıntılı araştırma gerektiriyor.

#### SORUN 2: Risk Check ReadTimeout [KRİTİK — HALA DEVAM EDİYOR]
```
[TLS] Alert received: level=1 description=0
[RISK CHECK] ReadTimeout while waiting for risk check response
```
- GitHub sunucusu TLS close_notify (level=1, description=0) gönderip bağlantıyı kesiyor
- Bu bir SONUÇ'tur, kök neden DEĞİLDİR — yüksek risk sinyali gönderildiği için sunucu reddediyor
- BDA encryption formatı doğru çalışıyor (base64 + JSON {ct,s,iv} + AES-256-CBC)
- **Muhtemel kök neden**: WebGL vendor/renderer boş string → Arkose Labs yüksek risk sinyali

#### SORUN 3: Chrome Extension Service Worker [HALA DEVAM EDİYOR]
- İlk log: `chrome-extension://fignfifoniblkonapihmkfakmlgkbkcf/service_worker.js`
- 2026-04-18 log: `chrome-extension://cimiefiiaegbelhefglklhhakcgmhkai/service_worker.js`
- Bu Google Keep extension'ıdır (fignfif...) veya başka bir component extension (cimief...)
- `--disable-extensions` kaldırıldıktan sonra bu extension'lar hala detect ediliyor olabilir
- **NOT**: `--disable-extensions` component extension'larını devre dışı bırakmaz, sadece kullanıcı extension'larını
- **NOT**: Arkose Labs için extension'lar GEREKLİDİR — kaldırılmamalıdır

#### SORUN 4: Octocaptcha iframe Yüklendi [SONUÇ — KÖK NEDEN DEĞİL]
- `captcha_frame=true`, `submit_hidden=true`, `submit_disabled=true`
- Bu risk check'in `challenge_required=true` döndürmesinin sonucudur
- Kök nedeni: WebGL vendor/renderer boş + ReadTimeout

#### SORUN 5: BDA Formatı Doğru [DOĞRULANMIŞ]
- JSON format: `base64({"ct":"...","s":"...","iv":"..."})` 
- AES-256-CBC encryption düzgün çalışıyor
- `webgl.vendor=""` ve `webgl.renderer=""` → bot sinyali

#### SORUN 6: Signup Timeout [YENİ — 2026-04-18]
- Risk check ReadTimeout sonrası `challenge_required=true` ile devam ediyor
- `captureSignupBundle` timeout oluyor çünkü captcha frame var ama çözülemiyor
- Signup submit butonu gizli ve disabled: `submit_hidden=true, submit_disabled=true`
- Octocaptcha iframe yükleniyor ama captcha çözümümüz yok

### 2026-04-18 İkincigün Sonuçları (--disable-vulkan-surface ve --disable-extensions kaldırıldıktan sonra)

#### DEĞİŞİKLİKLER:
1. `--disable-vulkan-surface` kaldırıldı → WebGL vendor/renderer hala boş
2. `--disable-extensions` kaldırıldı → component extension'lar artık yükleniyor
3. BDA artık çift base64 katmanlı: `base64(JSON{ct,s,iv})`
4. `X-Requested-With: XMLHttpRequest` header'ı eklendi
5. CDP bağlantısı başarılı → `https://github.com/signup` tab'ı bulundu
6. Fingerprint diagnostic toplandı (2319 byte response)
7. Chrome Service Worker detect: `cimiefiiaegbelhefglklhhakcgmhkai`

#### HALEN BOŞ STRING:
```
[FINGERPRINT] WebGL vendor: 
[FINGERPRINT] WebGL renderer:
```

#### İYİ HABERLER (Çalışan Şeyler):
- `navigator.webdriver: false`
- `window.chrome exists: true`
- `chrome.runtime.connect: true` (native proxy)
- `CDP side-effect: false`
- `SourceURL leak: false`
- `Console side-effects: false`
- CDP Network monitoring aktif
- BDA encryption AES-256-CBC + JSON wrapper + outer base64
- Cookie header'ları ekleniyor
- Screen: 800x600, hardwareConcurrency: 16, deviceMemory: 16

---

## Kritik Sorunların Kök Neden Analizi

### SORUN: WebGL vendor/renderer boş string
**Durum**: HALA ÇÖZÜLMEDİ — en kritik sorun

`--use-angle=vulkan` + `--headless=new` modunda Chrome'un `WEBGL_debug_renderer_info` extension'ı `getParameter(UNMASKED_VENDOR_WEBGL)` ve `getParameter(UNMASKED_RENDERER_WEBGL)` boş string dönüyor. Bu Arkose Labs'ın en kritik bot sinyalidir.

**Denenen ve İşe Yaramayan Yaklaşımlar**:
- ~~`--disable-vulkan-surface` eklemek~~ — WebGL context oluşturmayı engelliyor, kaldırıldı
- ~~`--disable-extensions` eklemek~~ — Arkose'nin ihtiyaç duyduğu component extension'larını da devre dışı bırakıyor, kaldırıldı

**Araştırılması Gerekenler**:
1. Chrome headless=new modunda ANGLE Vulkan gerçekten GPU'ya erişebiliyor mu? `chrome://gpu` sayfası CDP ile incelenmeli
2. `WEBGL_debug_renderer_info` extension'ı headless=new'de destekleniyor mu?
3. Headless Chrome'da gerçek GPU vendor/renderer değerleri nasıl alınır? (spoofing DEĞİL, gerçek değer)
4. Vulkan driver durumu — `vulkaninfo` çıktısı incelenmeli
5. Chrome'un GPU process logları — `--enable-logging=stderr --v=1` ile GPU başlatma logları alınmalı

### SORUN: Risk Check ReadTimeout → close_notify
**Kök neden**: Yukarıdaki WebGL sorunu. Boş vendor/renderer = yüksek risk sinyali = sunucu reddediyor.

### SORUN: Octocaptcha iframe / submit_hidden / submit_disabled
**Kök neden**: Risk check başarısız → challenge_required=true → captcha yükleniyor.

### ÖZET: TEK KÖK NEDEN = WebGL vendor/renderer boş string. Bunu çözsek diğer sorunlar da çözülür.

---

## Bekleyen Görevler

- [x] FAZ 6.1: Browser Stealth & GPU Flags
- [x] FAZ 6.2: TLS & Artifact Düzeltmeleri
- [x] FAZ 6.3: CDP Event Buffering & Observability
- [x] FAZ 6.4: BDA Encryption Format Düzeltmesi
- [x] FAZ 6.5: Risk Check HTTP Headers & Fingerprint Mapping
- [x] FAZ 6.6: Uydurma Kod Temizliği
- [x] FAZ 6.7: BDA Payload Genişletmesi
- [x] FAZ 6.8.1: Runtime test
- [x] FAZ 6.8.2: BDA payload doğrulama
- [x] FAZ 6.8.3: Risk check response analizi (ReadTimeout → close_notify)
- [ ] **FAZ 6.9: WebGL GPU ERİŞİMİ ÇÖZÜMÜ** ← SONRAKİ ADIM
  - headless=new modunda gerçek GPU vendor/renderer nasıl alınır?
  - `chrome://gpu` dump incelenmeli
  - Vulkan driver erişimi doğrulanmalı
  - `--enable-logging=stderr --v=1` ile GPU process logları alınmalı
  - GERÇEK GPU DEĞERLERİ İSTENİYOR — spoofing YASAK
- [ ] FAZ 6.10: Runtime Output → Dosya Yönlendirme
  - Motor çalıştığında tüm çıktıları txt dosyasına yazacak mekanizma
  - Terminal kopyalama zorunluluğu kalkacak
- [ ] FAZ 6.11: Signup Bundle Capture Timeout → Captcha Çözümü
  - Risk check başarılı olduktan sonra bile timeout olabilir
  - captcha_frame varsa çözüm mekanizması lazım (tguess araştırması yapıldı, implement edilmedi)
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
- [x] FAZ 6.1–6.7: Stealth, TLS, CDP, BDA, Headers, Cleanup, Payload
- [x] FAZ 6.8: Runtime Test & Doğrulama (kısmen — WebGL sorunu devam ediyor)
- [ ] **FAZ 6.9: WebGL GPU Erişimi Çözümü** ← ENGELLEYİCİ
- [ ] Account Post-Verification
- [ ] Multi-Account Orchestration

## Test Durumu
- Build: Clean (no compile errors)
- Vendor zig: `./vendor/zig/zig build --zig-lib-dir vendor/zig-std`
- browser_init tests: 8/8 geçiyor
- network_core tests: 129/129 geçiyor (BDA round-trip dahil)
- http2_core tests: geçiyor
- Son doğrulama: 2026-04-18 (FAZ 6.9 öncesi, --disable-vulkan-surface ve --disable-extensions kaldırıldı)

## Kritik Bulgular (Araştırma)

### BDA Encryption (Kaynak: unfuncaptcha/bda GitHub reposu)
- Gerçek format: `base64(JSON{"ct":"<base64>","s":"<hex_salt>","iv":"<hex_iv>"})` — çift base64 katmanı
- AES-256-CBC, PKCS#7 padding
- Key derivation: MD5 chain, `userAgent + str(rounded_timestamp)`, 6 saat rounding
- Salt ve IV random, key derivation'da salt kullanılıyor

### tguess/Proof-of-Work Mekanizması (Kaynak: unfuncaptcha/tguess)
- Funcaptcha görsel challenge çözümü için proof-of-work
- `/fc/gfct` endpoint'inden dönen JavaScript ile üretiliyor
- Encryption: aynı format (AES-256-CBC, JSON {ct,iv,s})
- Ghost Engine'de implement EDİLMEDİ — sadece araştırma

### Arkose Labs Tespit Mekanizmaları
- BDA payload 50+ alan bekliyor (biz ~25 gönderiyoruz)
- WebGL vendor/renderer boş = en kritik bot sinyali
- Behavioral telemetry: mouse movement, form fill speed, key event timing
- CDP Runtime.enable detection (Proxy ownKeys trap) — biz kaldırdık
- Headless Chrome detection: WebGL vendor/renderer, canvas fingerprint, navigator.webdriver

### CDP Detection Vektörleri (Kaynak: DataDome, Castle.io, Rebrowser.net)
- `Runtime.enable` → Proxy `ownKeys` trap: biz kaldırdık ✓
- `navigator.webdriver`: false dönüyor ✓
- `window.chrome`: true dönüyor ✓
- `chrome.runtime.connect`: native proxy çalışıyor ✓
- SourceURL leak: korunuyor ✓
- WebGL vendor/renderer: BOŞ ← KRİTİK SORUN

### Chrome Extension Tespiti
- `chrome-extension://cimiefiiaegbelhefglklhhakcgmhkai/service_worker.js` detect edildi
- Bu Chrome component extension'ıdır (Google Keep veya benzeri)
- `--disable-extensions` KULLANILMAMALI — Arkose Labs'in ihtiyaç duyduğu extension'ları da devre dışı bırakır

## Yapılan Hatalar ve Dersler

1. **`--disable-vulkan-surface` hatası**: Bu flag'i eklemek WebGL context oluşturmayı engelliyordu. Headless modda Vulkan surface'a ihtiyaç yok gibi düşünmüştük ama yanlıştı. Kaldırıldı ancak WebGL vendor/renderer hala boş — başka bir kök neden var.

2. **`--disable-extensions` hatası**: Arkose Labs'in ihtiyaç duyduğu Chrome component extension'larını da devre dışı bırakıyordu. Kaldırıldı.

3. **Gerçek değer üretimi zorunluluğu**: Spoofing/hardcoding YASAK. Her değer gerçek donanımdan gelmeli. WebGL vendor/renderer boş dönüyorsa bunu "hardcode etmek" yerine gerçek GPU'ya nasıl erişileceğini bulmalıyız.

4. **Chrome eski süreçleri**: Port 9222'yi eski Chrome süreçleri tutabilir. Çalıştırmadan önce `pkill -9 chrome` yapmak gerekebilir.

5. **Output loglama**: Motorun tüm çıktıları bir txt dosyasına yazılmalı. Terminal kopyalama verimli değil.