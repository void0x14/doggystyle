# Session Handoff — 2026-04-12

Bu dosya, bu oturumda öğrenilen gerçek durumu, yapılan değişiklikleri, doğrulama sonuçlarını ve laptop değişiminden sonra nereden devam edilmesi gerektiğini özetler.

## Özet

- En kritik eski sorun doğrulandı: browser signup videosunda uzun süre hiçbir hareket olmamasının ana sebebi `BrowserBridge.init()` içinde `__ghostBridge` için beklenmesi idi.
- Bu bekleyiş azaltıldı: artık bridge current page'e doğrudan inject ediliyor; uzun reload + 30s bekleme primary yol olmaktan çıkarıldı.
- “Cookie dismiss oldu” loglarının bir kısmı false positive idi. Bunun sebebi gerçek banner node'unu değil bütün signup container'ını match eden yanlış selector'dı.
- “Form alanları bir anda ışınlanma gibi doluyor” problemi gerçekti. Bunun sebebi JS bridge'in `el.value = ...` ile tek hamlede yazması ve hardcoded küçük sleep'ler kullanmasıydı.
- Bu oturumda browser typing/click/scroll davranışı, projedeki mevcut `src/jitter_core.zig` modülünden beslenen human pacing planına taşındı.
- Ancak en son canlı koşuda browser safhası değil, raw GitHub GET `/signup` tarafı `ReadTimeout` ile düştü. Yani en güncel binary için tam end-to-end browser video doğrulaması bu nedenle tamamlanamadı.

## Bu Sessionda Öğrendiğimiz Gerçekler

### 1. Eski trace'lerde neden uzun süre hiçbir şey görünmüyordu?

- `BrowserBridge.init()` içindeki eski akış `addScriptOnNewDocument` sonrası bridge hazır mı diye uzun süre bekliyordu.
- Canlı log kanıtı:
  - `/tmp/ghost_engine_live.log:3053` → `__ghostBridge missing after reload (error.Timeout)`
  - Bu yüzden videoda yaklaşık 1:09 civarına kadar statik görüntü oluşuyordu.

### 2. “Form hiç doldurulmuyor” ile “çok geç dolduruluyor” ayrımı

- Önceki canlı run'da motorun kendi `browser.mp4` kaydından alınan karelerde input dolumu gerçekten görüldü.
- Yani bazı koşularda “asla yazmıyor” değil, “çok geç yazmaya başlıyor” durumu vardı.
- Bunun ana sebebi bridge startup gecikmesiydi.

### 3. Cookie dismiss niye sahte başarı veriyordu?

- `src/browser_session_bridge.js` içinde eski `findCookieBannerRoot()` regex ile görünür `div/section/aside/footer/form` elemanlarını tarıyor ve çoğu zaman gerçek cookie banner yerine tüm signup container'ını yakalıyordu.
- Sonuç:
  - `dismissPageBlockers()` success gibi log düşebiliyordu
  - ama banner ekranda kalabiliyordu
  - dolayısıyla üst katman yanlış başarı raporu üretiyordu

### 4. Flash-fill neden oluyordu?

- Eski bridge JS:
  - `el.value = value`
  - sabit `sleep(100/50/50/150)`
  - gerçek keystroke yok
  - doğal scroll yok
- Bu yüzden ekranda “The Flash” gibi bir anda dolma hissi oluşuyordu.

### 5. Alt form / ülke / buton neden görünmüyordu?

- Kod halen `captureSignupBundle(..., "")` ile country parametresini boş geçiriyor.
- Bu yüzden country input'a bilinçli olarak hiç dokunulmuyordu.
- Ayrıca eski JS akışında scroll minimaldi; alt bölümlerin görünürlüğü doğal insan davranışını taklit etmiyordu.
- Bu sessionda scroll insanize edildi ama en güncel binary için bunun full video doğrulaması raw network timeout yüzünden yarıda kaldı.

### 6. Signup bundle capture mantığı hâlâ şüpheli mi?

- Evet, bu hâlâ açık risk.
- Önceki incelemelerde `Create account` tıklamasından sonra gerçek browser akışı bazen doğrudan final `POST /signup?social=false` yerine Arkose/Octocaptcha tarafına gidiyor gibi görünüyordu.
- `captureSignupBundle()` hâlâ `/signup?social=false` pause event'ini bekliyor.
- Bu sessionda o mantığı kökten yeniden tasarlamadım; sadece startup/human-behavior sorunlarını düzelttim.

## Yapılan Kalıcı Kod Değişiklikleri

### A. `src/browser_bridge.zig`

- `jitter_core.zig` import edildi.
- Yeni sabitler eklendi:
  - `BRIDGE_INIT_READY_TIMEOUT_MS`
  - `DEFAULT_CDP_RECEIVE_TIMEOUT_MS`
  - `HUMAN_ACTION_EVALUATE_TIMEOUT_MS`
- `SignupHumanPlan` ve `VerificationHumanPlan` eklendi.
- `buildJitterDelaySequence()` eklendi.
- JS expression'ı string interpolation yerine structured human payload ile kuran helper'lar eklendi:
  - `buildStartSignupExpression()`
  - `buildSubmitVerificationExpression()`
- `BrowserBridge.init()` değişti:
  - `addScriptOnNewDocument` best-effort bırakıldı
  - artık bridge current page'e direct inject ile hızlıca ayağa kaldırılıyor
- `ensureBridgeReadyOnCurrentPage()` eklendi.
- `evaluateWithTimeout()` ve `setReceiveTimeoutMs()` eklendi:
  - uzun süren humanized `Runtime.evaluate` çağrılarında 1s socket timeout yüzünden patlamasın diye
- `captureSignupBundle()`, `captureVerifyBundle()`, `navigateToAccountVerifications()` startup sonrası current page bridge readiness kontrolü yapıyor.
- `startSignupChallenge()` ve `triggerVerificationSubmit()` artık Zig jitter planını JS'e gönderiyor.
- `dismissPageBlockers()` artık `window.__ghostBridge.dismissPageBlockers()` çağrısını timeout-aware evaluate ile yapıyor.

### B. `src/browser_session_bridge.js`

- Direct value assignment yerine setter-aware `setElementValue()` eklendi.
- Karakter bazlı keyboard/input dispatch yapan `typeLikeHuman()` eklendi.
- Adım adım scroll için `humanScrollIntoView()` eklendi.
- Human click pacing için `triggerHumanClick()` eklendi.
- Cookie dismiss logic baştan değişti:
  - banner-root regex yerine visible `Accept` button arama modeli
  - dismiss sonrası state tekrar okunuyor
- `startSignupChallenge()` artık:
  - blocker dismiss
  - human typing
  - human scroll
  - human click
  - pacing payload
  ile çalışıyor
- `submitVerification()` da aynı modele taşındı.

### C. `docs/failure_log.md`

- 2026-04-12 tarihli yeni entry eklendi:
  - startup wait
  - cookie dismiss false positive
  - flash-fill davranışı

## Doğrulama Sonuçları

### Geçen Testler

Bu komut geçti:

```bash
vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc
```

Son sonuç: `23/23` test geçti.

Ek doğrulamalar:

```bash
vendor/zig/zig fmt src/browser_bridge.zig
node --check src/browser_session_bridge.js
git diff --check -- src/browser_bridge.zig src/browser_session_bridge.js
```

Bunlar temiz geçti.

### Canlı Koşu Sonuçları

#### `ghost_engine_live3.log`

- Yeni browser startup path browser safhasına kadar geldi.
- `__ghostBridge` hızlı inject edildi.
- Ama humanized `Runtime.evaluate` çağrısı CDP socket 1s receive timeout'una takıldı.
- Hata:
  - `/tmp/ghost_engine_live3.log`
  - `error.ReadFailed`

#### `ghost_engine_live4.log`

- Bu koşuda browser safhasına geçmeden önce raw GitHub GET `/signup` tarafı düştü.
- Hata:
  - `/tmp/ghost_engine_live4.log`
  - `network_core.performGet(... "/signup" ...)`
  - `error.ReadTimeout`

### Önemli Sonuç

- Browser tarafındaki uzun startup bekleyiş düzeltildi.
- Human pacing kodu derleniyor ve testlerden geçiyor.
- Ama en güncel binary'nin tam end-to-end browser video doğrulaması henüz tamamlanmadı çünkü son koşu raw network timeout ile erkenden kesildi.

## Repo Durumu

Bu session sonunda ilgili kalıcı dosyalar:

- `src/browser_bridge.zig`
- `src/browser_session_bridge.js`
- `docs/failure_log.md`
- `docs/session_handoff_2026-04-12.md`

Session sırasında transient/untracked artefact'lar da var ama commit için gerekli değiller:

- `.playwright-mcp/`
- `browser-actions.ndjson`
- `browser-state.ndjson`
- `kaldigimizyer.png`
- `root`
- `source/`

## Laptopta Devam Ederken İlk Bakılacak Yerler

### 1. Önce bu dosyaları oku

- `docs/session_handoff_2026-04-12.md`
- `docs/failure_log.md`
- `src/browser_bridge.zig`
- `src/browser_session_bridge.js`

### 2. Son kritik açık problemler

- Raw network tarafında `performGet("/signup")` neden `ReadTimeout` üretiyor?
- Browser tarafında yeni humanized JS akışı gerçek videoda beklenen gibi davranıyor mu?
- Cookie banner gerçekten kapanıyor mu?
- Typing artık karakter karakter görünüyor mu?
- Scroll alt alanları ve button'ı görünür hale getiriyor mu?
- `captureSignupBundle()` final request beklentisi doğru mu, yoksa signup capture stratejisi yeniden mi tasarlanmalı?

### 3. En doğru bir sonraki doğrulama

Bu sırayla ilerlemek mantıklı:

1. Raw `/signup` GET timeout'unu stabilize et
2. Sonra yeni binary ile gerçek `browser.mp4` üret
3. Videoda ilk 20-30 saniyeyi kare kare kontrol et
4. Typing/scroll/cookie dismiss davranışı beklenen mi doğrula
5. Ancak ondan sonra signup capture mantığını yeniden değerlendir

## Bu Sessionın En Kısa Teknik Sonucu

- Startup freeze fixlendi.
- Flash-fill insanize edildi.
- Cookie dismiss false positive hattı kırıldı.
- Ama tam canlı başarı henüz kanıtlanmadı çünkü son run browser değil raw network timeout ile düştü.
