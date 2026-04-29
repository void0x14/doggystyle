# Ghost Engine — Failure Log

---

## [2026-04-30] — Metadata Parse Fragility: ffprobe Line Position ve 0ch/0bit Hatası

**Hata:** Eski `audio_decoder.zig` kodunda ffprobe çıktısı `-of default=noprint_wrappers=1:nokey=1` ile sabit satır pozisyonuna göre parse ediliyordu (`lines.next()` sırasıyla sample_rate, bit_depth, channels, duration). Sonrasında key=value formatına geçilse de `bits_per_sample=0` (MP3), `N/A` (bazı versiyonlar), eksik alanlar ve `sample_rate` assert (yalnızca 44100/22050/16000 kabul ediyordu) nedeniyle fragility devam etti. Farklı sample_rate (örn. 48000 WAV) crash, MP3 `bits_per_sample=0` durumu ise loglarda "0bit" olarak yansıdı.

**Kök sebep:** Lossy formatlar (MP3, AAC, OGG) için ffprobe `bits_per_sample=0` döndürür; bu formatlarda bit depth anlamsızdır. Bazı ffprobe versiyonları `N/A` veya alanı tamamen atlayabilir. `sample_rate` assert ise yalnızca 3 sabit değer kabul ederek diğer tüm geçerli sample rate'leri (48000, 32000 vb.) crash'e zorluyordu.

**Kaynak:** man ffprobe — `-show_entries stream` behavior; lossy codec bit depth semantics; canlı test 2026-04-30 (MP3: `bits_per_sample=0`, 48kHz WAV: `sample_rate=48000`)

**Düzeltme:**
1. `parseAudioMetadataOutput`: `=` içermeyen satırları `continue` ile atla (eski `InvalidMetadata` yerine).
2. `bits_per_sample`: `"0"`, `"N/A"`, parse-fail durumlarında `null` bırak, `orelse 16` fallback uygula.
3. `sample_rate` assert kaldırıldı; yerine `parsed_sample_rate > 0`, `parsed_channels > 0`, `parsed_duration_seconds >= 0.0` runtime assert'leri eklendi.
4. `convertToPcmF32` içindeki `sample_rate` assert `> 0` olarak genişletildi.
5. 4 yeni regresyon testi eklendi: `ffprobe MP3 0ch/0bit tolerance`, `ffprobe N/A bit_depth tolerance`, `ffprobe 48kHz sample_rate tolerance`, `ffprobe missing bits_per_sample fallback`. Tümü geçiyor.

---

## [2026-04-28] — Arkose Audio Outlier VAD Düşük SNR Segmentlerini Reddetti

**Hata:** Canlı audio bypass yeni `analyzeOutlier()` yoluna geçti ama her denemede `error.NoActiveSignal` döndü; motor cevap üretemedi.
**Kök sebep:** `analyzeOutlier()` üç segmentin tamamı için `findActiveRegion()` başarısı istiyordu. Canlı Arkose MP3 segmentlerinde 1 ve 2 aktif/nonzero olmasına rağmen VAD SNR hesabı 3.0 eşiğinin altında kaldı (`2.83`, `2.65`) ve tüm analiz abort edildi.
**Kaynak:** Canlı motor logu `/home/void0x14/.local/share/opencode/tool-output/tool_dd4ff681d001Fqa3MGIddiAD8j` — `Decoded` sonrası `Attempt N: outlier analyze failed: error.NoActiveSignal`; `tmp/audio_challenge_0.mp3` ffmpeg PCM ölçümü 2026-04-28.
**Düzeltme:** `analyzeOutlier()` yalnız `error.NoActiveSignal` için nonzero segmentlerde whole-clip active fallback kullanıyor; sessiz segmentler yine fail ediyor. Regresyon testi eklendi: `fft_analyzer: analyzeOutlier uses whole clip when VAD rejects low SNR active audio`.

---

## [2026-04-27] — Arkose Audio State Machine Fix: Intermediate Challenge Transition Detection

**Hata:** `classifyPostSubmitProof()` binary karar veriyordu (ya wrong ya complete). Arkose'un ara challengelarında (0..N-2) doğru cevap sonrası body'de ne "wrong" ne "complete" metni var. `.unknown` = çöp kutusu, hiçbir işlem yapılmıyordu. Pipeline ilerleyemiyordu.

**Kök sebep:** Arkose 3 durumda çalışır: (1) wrong answer → body'de "Incorrect" text, (2) intermediate transition → doğru cevap, sonraki challenge yükleniyor, body'de hiçbir completion/wrong text yok, (3) complete → sadece SON challenge'da "verification complete" text. Kod yalnızca (1) ve (3)'ü modelledi, (2)'yi `.unknown`'a atıp görmezden geldi.

**Kaynak:** Arkose Labs UI behavior — intermediate challenges don't show completion text (live test 2026-04-27)

**Düzeltme:**
1. `PostSubmitVerdict` enum'a `.transition` eklendi — ara geçiş tespiti için
2. `classifyPostSubmitProof()`: post-submit proof JS'e `input_visible` alanı eklendi; input kaybolduğunda ve wrong/complete text yoksa → `.transition`
3. `detectAudioChallengeCompletion()` → `detectPostSubmitUiState()` yeniden yazıldı: 5 durumlu enum döndürüyor (complete, continue_wait, transition, restarted, query_failed)
4. Verdict switch: `.transition` → successful++, challenge_index++; `.unknown` → artık no-op değil, UI state kontrol edip transition/complete/restart tespit ediyor; `.wrong` → Arkose restart tespiti eklendi
5. 5 yeni semantik test eklendi, 22/22 geçiyor

---

## [2026-04-27] — Arkose Audio .unknown Verdict İlerlemeyi Engelliyor (CRITICAL)

**Hata:** Doğru cevap verildiğinde Arkose bir sonraki challenge'a geçiyor. Post-submit proof script body text'te ne "wrong" ne "complete" buluyor → `.unknown` verdict. `.unknown` durumunda `successful` VE `challenge_index` artmıyor. Loop aynı `challenge_index` ile audio'yu tekrar indiriyor, ama UI zaten ilerlemiş → input bulunamıyor veya yanlış challenge'a enjeksiyon → pipeline çöküyor.

**Kök sebep:** `classifyPostSubmitProof()` body text'te completion/wrong text arayarak binary karar veriyor. Ancak N challenge'lı bir sette, 0..N-2 arası challengelar için doğru cevap sonrası sayfada bir sonraki challenge'ın input'u beliriyor — body'de ne "verification complete" ne "wrong" var. Yalnız son challenge (N-1) completion text üretiyor. Ara challengelardaki `.unknown` verdict'leri handle edilmiyor.

**Kaynak:** Arkose Labs UI behavior — challenge geçişleri arasında DOM güncellenir ama completion text yalnızca tüm challengelar bittiğinde render edilir. `detectAudioChallengeCompletion()` bu durumu kontrol edebiliyor ama yalnızca `.complete` verdict'inde çağrılıyor, `.unknown`'da çağrılmıyor.

**Düzeltme (önerilen):**
1. `.unknown` verdict'inde `detectAudioChallengeCompletion()` çağrılarak UI'nin ilerleyip ilerlemediği kontrol edilmeli
2. Alternatif: Post-submit script input element varlığını ve değerini de döndürmeli; input yoksa veya yeni bir challenge gösteriliyorsa success sayılmalı
3. `.wrong` durumunda aynı audio'yu tekrar indirmek yerine farklı bir cevap denenmeli (eğer FFT aynı sonucu veriyorsa)

---

## [2026-04-27] — Arkose Audio Direct Submitted/Success Complete Sayıldı

**Hata:** Runtime.evaluate direct string `submitted` veya `success` sonucu, post-submit sayfa durumu okunmadan `.complete` kabul edildi.
**Kök sebep:** Submit action sonucu ile Arkose completion kanıtı aynı semantiğe bağlandı. Direct string yalnız JS action dönüşüdür; completion text veya yanlış cevap metni içermez.
**Kaynak:** Kullanıcı review gereksinimi 2026-04-27 — yalnız structured post-submit payload içinde `completion_text=true` complete kanıtıdır; direct `submitted`/`success` unknown kalmalıdır.
**Düzeltme:** `submitResponseSucceeded()` direct `submitted`/`success` için false döndürüyor. `classifyPostSubmitProof()` direct stringleri `.unknown` bırakıyor; `.complete` yalnız structured `completion_text=true` için üretiliyor. Regresyon testleri eklendi.

---

## [2026-04-27] — Arkose Audio Submit Click Kanıt Sanıldı

**Hata:** `clicked_text_submit` Runtime.evaluate sonucu submit sonrası başarı kanıtı sayıldı. Canlı UI aynı anda `Incorrect. Only enter the number of your chosen answer, e.g. 1` gösterdiği halde akış `continue` verdict ile frame içinde kaldı.
**Kök sebep:** Click denemesi ile post-submit Arkose verdict aynı semantiğe bağlandı. Butona tıklanması yalnız `click_attempted` kanıtıdır; yanlış cevap metni veya completion metni ayrıca okunmadan accepted proof olamaz.
**Kaynak:** Canlı kullanıcı kanıtı 2026-04-27 — `Answer injection: filled`, `Submit: clicked_text_submit`, ardından UI wrong text ve completion `continue`; Chrome DevTools Protocol `Runtime.evaluate` string value yalnız evaluate dönüşünü bildirir, sayfa durumunu otomatik başarı kanıtı yapmaz.
**Düzeltme:** `clicked_*` başarı kabulünden çıkarıldı. `classifyPostSubmitProof()` eklendi; post-submit body/input payload'u `wrong`, `complete`, `clicked`, `unknown` verdict'e çevriliyor. `injectAnswerOnTarget()` click sonucunu sadece `click_attempted` logluyor ve yalnız `complete` verdict'i accepted sayıyor.

---

## [2026-04-27] — Arkose Audio Final Success Sıfır Hedefi Başarı Saydı

**Hata:** `audioBypassFinalSuccess()` `target_challenges=0` ve `challenge_complete=false` durumunda `0 >= 0` karşılaştırmasıyla true dönebiliyordu.
**Kök sebep:** Runtime hedef parse edilememiş state ile hedefe ulaşılmış state aynı karşılaştırma dalından değerlendirildi.
**Kaynak:** Kullanıcı review bulgusu 2026-04-27 — hedef parse edilememiş ve completion olmayan state final success olmamalı; gerçek `challenge_complete=true` completion sinyali success kalabilir.
**Düzeltme:** Final success için target-based dal `target_challenges > 0` guard'ı ile sınırlandı; completion sinyali dalı korunarak regresyon testi eklendi.

---

## [2026-04-27] — Arkose Audio Submit Hedefini Captcha Başarısı Sandı

**Hata:** `audioBypassFinalSuccess()` runtime hedef kadar submit yapılınca `challenge_complete=false` olsa bile success true döndürüyordu. Canlı motor `Pipeline ended: 1/1 submitted, complete=false` ve hemen ardından `captcha_frame=true` / `error.Timeout` gösterdi.

**Kök sebep:** Submit sayacı ile captcha çözülme durumu aynı başarı semantiğine bağlandı. `clicked_text_submit` yalnız form submit denemesidir; Arkose completion veya captcha iframe kapanması kanıtı değildir.

**Kaynak:** Canlı motor logu `/home/void0x14/.local/share/opencode/tool-output/tool_dcef88252001e38uS0LZIV8lYT` — satır 3384-3388 submit sonrası completion `continue`, satır 3395 ve devamı `captcha_frame=true`, satır 3673 `error.Timeout`.

**Düzeltme:** Final success yalnız `challenge_complete` sinyaline bağlandı. Runtime hedef sayısı loop sınırı/progress için kullanılmaya devam ediyor; captcha başarısı olarak raporlanmıyor.

---

## [2026-04-27] — Arkose Audio Final Success Completion Flag'e Bağlı Kaldı

**Hata:** Audio bypass döngüsü runtime hedef submit sayısına ulaştığında durabiliyor, ancak final `AudioBypassResult.success` yalnız `challenge_complete` değerine bağlı kaldığı için `complete=false` durumunda sonuç PARTIAL kalabiliyordu.

**Kök sebep:** Bu kayıt sonradan yanlışlandı. Döngü sonlandırma semantiği ile final başarı semantiği ayrıştırılmalıydı; ancak runtime hedefe ulaşmak captcha çözümünü kanıtlamaz. Arkose completion flag'i veya captcha iframe kapanması olmadan success true olmamalıdır.

**Kaynak:** Canlı motor logu `/home/void0x14/.local/share/opencode/tool-output/tool_dcef88252001e38uS0LZIV8lYT` — `1/1 submitted`, `complete=false`, `captcha_frame=true`, ardından `error.Timeout`.

**Düzeltme:** Bu kayıttaki eski düzeltme geri alındı. Final success yalnız `challenge_complete` olduğunda true döner; submit hedefi yalnız progress/loop için kullanılır.

---

## [2026-04-27] — Arkose Audio Loop Deneme Sayısını Hedef Saydı

**Hata:** `shouldContinueAudioChallengeLoop()` hedefe ulaşmayı yalnız başarılı submit sayısıyla değil, `attempted < target_challenges` ile de sınırlıyordu. `target=3` iken iki başarılı submit ve bir başarısız/no_submit denemesi sonrası döngü üçüncü başarıyı denemeden durabiliyordu.

**Kök sebep:** Runtime JSON'dan gelen `audio_challenge_urls.len` başarı hedefidir; deneme sayısı yalnız `MAX_CHALLENGES` safety limit için kullanılmalıydı. Helper, hedef ve safety limit kavramlarını karıştırdı.

**Kaynak:** Kullanıcı gereksinimi 2026-04-27 — loop koşulu hedef biliniyorsa hedefe bağlı olacak, `MAX_CHALLENGES` safety limit kalacak, `no_submit` sahte başarı sayılmayacak.

**Düzeltme:** Helper koşulu `successful_submits < target_challenges && attempted < MAX_CHALLENGES` olarak daraltıldı; focused regresyon testi `target=3, successful=2` devam eder ve `successful=3` durur davranışını doğruluyor.

---

## [2026-04-27] — Arkose Audio Runtime Hedef Sayısı Parse Edilmedi

**Hata:** Statik `5` hedefi kaldırıldıktan sonra audio bypass döngüsü hedef sayıyı `/fc/gfct/` içindeki `audio_challenge_urls` dizisinden okumuyordu; döngü yalnız `MAX_CHALLENGES` ve erken completion sinyaline bağlıydı.

**Kök sebep:** `gfct_response` Runtime.evaluate string payload'u zaten elde edilmesine rağmen bu JSON içindeki `audio_challenge_urls` sayısı parse edilmedi. `shouldContinueAudioChallengeLoop()` `successful_submits` değerini yok sayıyordu.

**Kaynak:** Kullanıcı gereksinimi 2026-04-27 — Arkose `/fc/gfct/` response içindeki `audio_challenge_urls` kaç elemanlıysa audio challenge hedefi o sayı olmalı; completion check yalnız ek erken tamamlanma doğrulaması olabilir.

**Düzeltme:** `parseAudioChallengeTargetFromGfctResponse()` eklendi. Pipeline artık hedef sayıyı Runtime.evaluate string JSON payload'undan alıyor; hedef parse edilemezse statik fallback yapmadan `success=false` partial dönüyor. Döngü koşulu `successful_submits < target_challenges && attempted < MAX_CHALLENGES` oldu.

---

## [2026-04-27] — Arkose Audio Hardcoded 5 Challenge Hedefi

**Hata:** Audio bypass döngüsü `TARGET_CHALLENGES = 5` sabitine bağlıydı; `Challenge N/5 DONE`, `Pipeline complete: N/5` ve üst seviye `N/5` logları gerçek Arkose durumunu değil statik hedefi yansıtıyordu.

**Kök sebep:** Canlı Arkose akışında challenge sayısı runtime durumundan gelirken `runAudioBypass()` başarı koşulunu sabit `5` üzerinden hesaplıyordu. Bu, gerçek submit sonrası tamamlanma sinyali kontrol edilmeden pipeline'ın statik hedefe göre bitmesine neden olabiliyordu.

**Kaynak:** `src/arkose/audio_bypass.zig` eski döngü koşulu `successful < TARGET_CHALLENGES`; kullanıcı gereksinimi 2026-04-27 — başarı hedefi dinamik olmalı, güvenlik üst sınırı yalnız `MAX_CHALLENGES` olmalı.

**Düzeltme:** `TARGET_CHALLENGES` kaldırıldı. Döngü `shouldContinueAudioChallengeLoop()` ile `MAX_CHALLENGES` ve Arkose tamamlanma sinyaline bağlı hale getirildi. Her gerçek submit success sonrası tamamlanma kontrolü yapılıyor; tamamlanma yoksa bir sonraki audio challenge deneniyor.

---

## [2026-04-27] — Arkose Audio no_submit Sahte Başarı Sayacı

**Hata:** Audio bypass logunda `Submit (target)` CDP yanıtı `"no_submit"` döndürmesine rağmen hemen ardından `Challenge N/5 DONE` ve sonunda `Pipeline complete: 5/5` yazıyordu.

**Kök sebep:** `injectAnswerOnTarget()` submit sonucunu semantik olarak döndürmüyordu; `runAudioBypass()` yalnızca fonksiyonun hata fırlatmamasını başarı sayıp `successful += 1` yapıyordu.

**Kaynak:** Canlı koşu kanıtı `/home/void0x14/.local/share/opencode/tool-output/tool_dcc271a620010dFi4UohQ5GBLD` satır 3309-3463 — her `no_submit` yanıtı sonrası sayaç artmış.

**Log alıntısı:**
```text
[AUDIO INJECTOR] Submit (target): {"id":44,"result":{"result":{"type":"string","value":"no_submit"}}}
[AUDIO BYPASS] Challenge 1/5 DONE
...
[AUDIO INJECTOR] Submit (target): {"id":72,"result":{"result":{"type":"string","value":"no_submit"}}}
[AUDIO BYPASS] Challenge 5/5 DONE
[AUDIO BYPASS] Pipeline complete: 5/5 challenges, 69825ms
```

**Düzeltme:** `submitResponseSucceeded()` helper'ı eklendi. `injectAnswerOnTarget()` artık submit semantiğini `bool` döndürüyor; `no_submit` false, `submitted`/`clicked`/`success` true kabul ediliyor. `runAudioBypass()` yalnızca true sonucunda challenge sayacını artırıyor.

---

## [2026-04-25] — CDP Context Evaluate Timeout Eksikliği

**Hata:** Arkose audio answer injection, `context_id > 0` yolunda `Runtime.evaluate` yanıtı gelmiyor gibi görünüyordu. Aynı action main-context fallback veya manual MCP ile çalışabiliyordu.

**Kök sebep:** `injectAnswerOnTarget()` context dalında `CdpClient.evaluateInContext()` kullanıyordu. Bu helper CDP `Runtime.evaluate` parametrelerine `timeout` eklemiyor ve socket receive timeout'unu human action süresine yükseltmiyordu. `evaluateWithTimeout()` ise aynı evaluate için hem CDP `timeout` hem geçici socket timeout uyguluyordu.

**Kaynak:** Chrome DevTools Protocol `Runtime.evaluate` — `contextId` execution context hedefler, `timeout` değerlendirme süresini ms cinsinden sınırlar, `awaitPromise:true` promise çözülene kadar bekler; `man 7 socket` — `SO_RCVTIMEO` socket read timeout davranışı.

**Düzeltme:** `buildRuntimeEvaluateParams()` ortak params builder'ı eklendi. `evaluateInContextWithTimeout()` eklendi ve Arkose `injectAnswerOnTarget()` context dalı bu helper'a taşındı. Regresyon testleri `contextId + timeout` JSON parametrelerini ve default evaluate parametrelerini doğruluyor.

---

## [2026-04-25] — CDP WebSocket Fragmentation ve Timeout Katlanması

**Hata:** `Runtime.evaluate` yanıtı gelmiyor gibi görünüyordu; `sendCommand()` `recvWsTextAlloc()` içinde bekliyor, `recvExact()` ise timeout sonrası 100 kez daha 10ms uyuyarak çağrı süresini büyütüyordu.

**Kök sebep:** `recvWsTextAlloc()` RFC 6455 fragmented message davranışını uygulamıyordu. `FIN=0` text frame geldiğinde ilk fragment payload'unu doğrudan dönüyor, continuation frame'i sonraki bağımsız CDP mesajı gibi bırakıyordu. Ayrıca `recvExact()` zaten `SO_RCVTIMEO` ile zamanlanmış socket read'inden gelen `error.WouldBlock` sonrasında kendi 100×10ms retry loop'unu çalıştırıyordu.

**Kaynak:** RFC 6455 Section 5.4 — WebSocket fragmentation; `vendor/zig-std/std/posix.zig` `read()` satır 400-430 — `EAGAIN` → `error.WouldBlock`; `man 2 read`/`man 7 socket` — `SO_RCVTIMEO` expiry read tarafında timeout üretir.

**Düzeltme:** `recvWsTextAlloc()` text + continuation frame'leri tek message buffer'da birleştiriyor; `recvExact()` `error.WouldBlock` gördüğünde ek uyku/retry yapmadan `error.ReadFailed` döndürüyor. Regresyon testleri eklendi: fragmented server text message ve internal sleep retry loop olmaması.

---

## [2026-04-24] — Arkose Audio Bypass LIVE Test — Endpoint ve Format Farklılıkları

**Ne oldu:** Plan'da `fc/get_audio` endpoint'i, 22050Hz 12sn×3 clip, 0-indexed cevap varsayılmıştı. Canlı testte gerçek endpoint `rtag/audio?challenge=N` çıktı, format 44100Hz mono MP3 (~18-21sn single dosya), cevaplar 1-indexed.

**Kök sebep:** Arkose Labs Audio CAPTCHA implementasyonu plan aşamasında incelenen dokümantasyonla uyuşmuyor. Arkose üç ayrı URL yerine tek bir MP3 dosyası döndürüyor, bu dosya üç farklı "speaker" segmentini ardışık içeriyor.

**Kaynak:**
- Canlı CDP Fetch.requestPaused capture, 2026-04-24: `rtag/audio?challenge=0` (NOT `fc/get_audio`)
- `ffprobe` çıktısı: `44100 Hz, 1 channel, s16le, 18.44s` (plan: 22050Hz 12sn×3)
- Spectral flux analysis ile 3 parçaya bölme: **çalışıyor** (en yüksek delta doğru clip'i buluyor)
- Cevap: `guess + 1` = 1-indexed, 2/5 challenge geçildi

**Düzeltme:**
1. `audio_downloader.zig`: URL pattern `fc/get_audio` → `rtag/audio`, 3 URL capture → 1 URL capture
2. `main.zig`: Pipeline aktifleştirildi, `solveArkoseAudioChallenge` ile 5 challenge döngüsü
3. `fft_analyzer.zig`: Canlı testte `guess` 0/1/2 döndü, `+1` ile 1-indexed cevap

**Yeni bilinenler:**
- `AUDIO_CLIP_COUNT` = 1 (tek MP3, kod içinde 3 parçaya bölünüyor)
- Sample rate: 44100Hz (plan 22050Hz değil)
- Duration: ~18-21sn (plan 12sn×3=36sn değil)
- Başarı: 2/5 challenge (submit sonrası "2 done" onayı)
- Cevap formatı: numeric, 1-3 arası, browser input field'ına yazılıp submit ediliyor

**Tekrar olmaması için:**
- Protocol endpoint'leri önce canlı testle doğrulanmalı, plana güvenilmemeli
- Sample rate/duration gibi parametreler plan değil, gerçek `ffprobe` çıktısına dayanmalı
- Cevapların 0/1-indexed olduğu canlı testte doğrulanmalı

---

## [2026-04-24] — `io.sleep()` API Vendored Zig'de Mevcut Değil (std.Io.Duration Yok)

**Ne oldu:** `injectAndSubmitAnswer` fonksiyonunda `io.sleep(std.Io.Duration.fromMilliseconds(1500), .awake)` kullanıldı ancak vendor/zig-std'de `std.Io.Duration` API'si farklı.

**Kök sebep:** vendor/zig-std versiyonunda `std.Io.Duration` modülü mevcut değil. `std.Io.Duration.fromMilliseconds` path'i çalışmıyor. Bunun yerine `std.os.linux.nanosleep` kullanılmalı.

**Kaynak:** vendor/zig-std/std/Io.zig — API inspection 2026-04-24
**Düzeltme:** `io.sleep(...)` → `std.os.linux.timespec + nanosleep` (digistallone.zig'deki pattern)

---

## [2026-04-24] — BrowserBridge.allocator Field'ı Public Değil

**Ne oldu:** `injectAndSubmitAnswer` fonksiyonu `bridge.allocator` ile allocator'a erişmeye çalıştı ancak `allocator` field'ı public değildi.

**Kök sebep:** browser_bridge.zig'de `BrowserBridge.allocator` field'ı ya private ya da farklı isimle tanımlanmış. doğrudan erişim için `pub` gerekli.

**Kaynak:** src/browser_bridge.zig — BrowserBridge struct definition
**Düzeltme:** `bridge.allocator` yerine fonksiyona allocator parametresi geçildi veya field public yapıldı.

---

Bu dosya gerçek hataların anatomisini, kök neden analizini ve çözüm sürecini kayıt altına alır.
Hem geliştirici hem de yapay zeka modelleri için başvuru kaynağıdır.
**Kural:** Her bug fix sonrası bu dosya güncellenir.

---

## [2026-04-24] — Zig 0.16.0-dev Birden Çok Dosyayı Test Edememe

**Ne oldu:** `src/arkose/audio_downloader.zig` bağımsız olarak test edilemedi çünkü `@import("../browser_bridge.zig")` import'u "import of file outside module path" hatası verdi.

**Kök sebep:** Zig 0.16.0-dev'de `vendor/zig/zig test` komutu birden çok kaynak dosyayı aynı anda kabul etmez (`error: found another zig file after root source file`). `build.zig`'de `b.addSystemCommand` ile her dosya ayrı test edilir, ama bağımlılık içeren dosyalar için `b.addTest` + `addImport()` kullanılması gerekir. `b.addTest` sonrası `addRunArtifact` ise debug binary'lerde `--listen=-` flag'i ekleyerek hang sorununa yol açar.

**Kaynak:** vendor/zig-std/build — `addTest` compile step docs
**Çözüm:**
1. `audio_downloader.zig`'deki import `@import("../browser_bridge.zig")` → `@import("browser_bridge")` olarak değiştirildi
2. `build.zig`'de `b.addTest` + `b.createModule` ile tüm bağımlılıklar (`browser_bridge`, `browser_bundle`, `jitter_core`) `addImport()` ile eklendi
3. `b.addSystemCommand` yerine `b.addRunArtifact` kullanıldı

---

## [2026-04-24] — browser_bridge.zig Private API'leri Public Yapma Zorunluluğu

**Ne oldu:** `audio_downloader.zig` `BrowserBridge.waitForPausedRequest()`, `parseFetchRequestPaused()` ve `PausedRequestCapture` tipini kullanıyordu ama bunlar `fn`/`const` (private) olarak tanımlanmıştı.

**Kök sebep:** Modüler yapıda browser_bridge.zig'in iç API'leri diğer modüllerden erişilebilir olmalı. waitForPausedRequest signup/verify capture için kullanılır, aynı şekilde audio URL capture için de gerekli.

**Kaynak:** Chrome DevTools Protocol — Fetch.requestPaused
**Çözüm:** `parseFetchRequestPaused` → `pub fn`, `PausedRequestCapture` → `pub const`, `waitForPausedRequest` → `pub fn`

---

## [2026-04-16] — CDP Events Silently Dropped By sendCommand Causing waitForPausedRequest Timeout

**Ne oldu:** `Fetch.requestPaused` ve `Network.*` CDP event'leri hiçbir zaman yakalanmıyordu. `waitForPausedRequest` sürekli timeout veriyordu ve `browser-network.ndjson` dosyası boş kalıyordu.

**Gerçek:** `CdpClient.sendCommand()` CDP mesajlarını okurken ID'si eşleşmeyen mesajları `self.allocator.free(response)` ile serbest bırakıyordu. CDP event'leri (Fetch.requestPaused, Network.requestWillBeSent vb.) JSON'da `"id"` alanı taşımaz — bu yüzden `extractTopLevelMessageId()` null dönüyordu ve event'ler sessizce drop edilip free ediliyordu. Sonuç: `waitForPausedRequest` içindeki `dismissPageBlockers()` ve `emitDiagnosticState()` çağrıları evaluate → sendCommand zinciri tetiklediğinde, bu sırada gelen Fetch.requestPaused event'i kayboluyordu.

**Kök sebep:** WebSocket CDP protokolünde iki tür mesaj vardır:
1. **Command response** — `{"id":N,"result":{...}}` — eşleşen ID ile bulunur
2. **Event** — `{"method":"Fetch.requestPaused","params":{...}}` — `"id"` alanı YOKTUR

`sendCommand` her iki türü de aynı döngüde okuyordu ama sadece ID eşleşmesini return ediyordu; event'leri nil olarak free ediyordu.

**Kaynak:**
- Chrome DevTools Protocol spec — command responses carry `"id"` field matching the request; events carry `"method"` field with no `"id"`
- RFC 6455, Section 5.4 — WebSocket message boundaries and multiplexing

**Düzeltme:**
1. `CdpClient.pending_events: std.array_list.Managed([]u8)` alanı eklendi — events için buffer
2. `sendCommand` içinde `"id"` alanı olmayan mesajlar artık free edilmeyip `pending_events` dizisine append ediliyor
3. `hasPendingEvents()` ve `nextPendingEvent()` metodları eklendi — buffered event'ler sıralı okunuyor
4. `waitForPausedRequest` artık her döngü başında `pending_events`'i kontrol ediyor — Fetch.requestPaused ve Network.* event'ler korunuyor
5. `waitForTruthyExpression` aynı şekilde pending event'leri draining ediyor
6. `CdpClient.close()` pending event'lerin hepsini free ediyor
7. `Network.enable` CDP komutu eklendi — `enableNetworkMonitoring()` metodu ile
8. `BrowserBridge.init()` içinde `cdp.enableNetworkMonitoring()` çağrısı eklendi
9. `processCdpEvent()` — buffered event'leri parse edip Network.requestWillBeSent/responseReceived event'lerini browser-network.ndjson'a logluyor
10. `computeRiskAndLogTelemetry()` — observeUiState + risk level hesaplayıp browser-network.ndjson'a telemetry NDJSON satırı yazıyor

**Tekrar olmaması için:**
- CDP WebSocket okuma her zaman event buffering yapmalı; command response olmayan mesajlar drop EDİLEMEZ
- waitForPausedRequest ve benzeri döngüler önce pending_events'i check etmeli, sonra yeni mesaj okumalı
- Ağaç: src/browser_bridge.zig — CdpClient.sendCommand, CdpClient.pending_events, BrowserBridge.waitForPausedRequest

---

---

## [2026-04-18] — --use-angle=opengl Causes Mesa Software Renderer / Empty WebGL in Headless Mode

**Ne oldu:** `browser_init.zig` satır 387'de `--use-angle=opengl` flag'i kullanılıyor. Kod yorumları `--use-angle=vulkan` ve `--use-gl=angle` öneriyor ama uygulama farklı. Bu uyumsuzluk headless Chrome'da WebGL context'in ya tamamen başlatılamamasına (boş string) ya da Mesa/SwiftShader yazılım renderer'ına düşmesine neden oluyor.

**Gerçek:** `--use-angle=opengl` ANGLE'ın OpenGL backend'ini kullanır. Headless Linux ortamında (X11/Wayland olmadan), OpenGL path'i Mesa software rasterizer'a (llvmpipe/SwiftShader) düşer çünkü gerçek GPU'ya erişmek için GLX/EGL surface gerekir ve `EGL_PLATFORM=surfaceless` ile surface yok. Buna karşılık `--use-angle=vulkan` ANGLE'ın Vulkan backend'ini kullanır ve `/dev/dri/renderD128` üzerinden doğrudan gerçek GPU'ya erişir — surface gerektirmez.

**Kaynak:** Chromium ANGLE Implementation — https://chromium.googlesource.com/angle/angle/+/HEAD/doc/Implementation.md
**Kaynak:** Chrome --headless=new GPU rendering — https://developer.chrome.com/docs/chromium/new-headless
**Kaynak:** Mesa DRM render nodes — https://dri.freedesktop.org/docs/drm/gpu/overview.html

**Düzeltme:** `--use-angle=opengl` → `--use-angle=vulkan` ve `--use-gl=egl` → `--use-gl=angle`. İkisi birlikte çalışmalıdır. FAZ 7.1.1 ve 7.1.2'de uygulanacak.

**Tekrar olmaması için:** `--use-angle=vulkan` dışındaki ANGLE backend'leri headless modda gerçek GPU'ya erişemez. OpenGL ANGLE backend'i X11/Wayland surface gerektirir ve headless'ta software fallback'e düşer.

---

## [2026-04-18] — MESA_LOADER_DRIVER_OVERRIDE=iris Hardcoded for Intel, Breaks on AMD GPU

**Ne oldu:** `browser_init.zig` satır 309'da `MESA_LOADER_DRIVER_OVERRIDE=iris` sabit olarak ayarlanıyor. Ama sistemde hem Intel i5-13500H hem de AMD RX 460 var. `iris` driver'ı AMD GPU'da çalışmaz ve Mesa fallback'e neden olur.

**Gerçek:** Mesa driver isimleri GPU vendor'a özeldir: Intel Gen12+ için `iris`, AMD GCN+ için `radeonsi`. Sabit hardcode her iki GPU'yu da destekleyemez. Runtime'da hangi render node'un hangi GPU'ya ait olduğunu tespit etmek gerekir.

**Kaynak:** Mesa driver documentation — iris for Intel Gen12+, radeonsi for AMD GCN+

**Düzeltme:** Runtime GPU detection ile dinamik driver seçimi yapılmalı. `/dev/dri/renderD128` device'ından `libdrm` veya `lspci` ile GPU vendor tespit edilip uygun driver override uygulanmalı. FAZ 7.3.1'de uygulanacak.

**Tekrar olmaması için:** Driver override değeri asla sabit hardcode edilmemeli. Runtime'da tespit edilmeli.

---

## [2026-04-18] — DISPLAY=:99 Environment Variable Causes X11 Session Leak in Headless Mode

**Ne oldu:** `buildSafeEnvironment` fonksiyonu satır 298'de `DISPLAY=:99` set ediyor. Ama `--headless=new` modunda DISPLAY gereksiz ve X11 sızıntısına neden olabilir. Ayrıca Xvfb spawn kodu zaten FAZ 6.2.1'de kaldırılmış ama DISPLAY sabiti kalmış.

**Gerçek:** `--headless=new` Chrome'un kendi render pipeline'ını kullanır ve X11/Xvfb'ye ihtiyaç duymaz. DISPLAY environment variable'ı bırakmak anti-bot sistemler tarafından "X11 session potential" olarak tespit edilebilir.

**Kaynak:** man 7 environ — X11/Wayland session variables
**Kaynak:** Chrome --headless=new — https://developer.chrome.com/docs/chromium/new-headless

**Düzeltme:** `XVFB_DISPLAY` sabiti kaldırılacak ve `DISPLAY` `PURGED_ENV_VARS` listesine eklenecek. FAZ 7.1.4 ve 7.1.5'te uygulanacak.

**Tekrar olmaması için:** Headless Chrome ortamında DISPLAY ve XAUTHORITY gibi X11 değişkenleri asla set edilmemeli.

---

## [2026-04-14] — WebGL Empty Vendor/Renderer And chrome.runtime Missing Flagged By Arkose BDA

**Hata:** `browser-fingerprint.ndjson` diagnostic verisi `webgl_vendor = ""` ve `webgl_renderer = ""` gösteriyordu. Ayrıca `chrome_runtime_connect = false` ve `chrome_runtime_sendMessage = false` idi. Arkose Labs BDA (Browser Data Analytics) bu alanları topluyor ve boş/eksik değerleri bot işareti olarak kullanıyor.

**Kök sebep:** `browser_init.zig` içindeki Chrome launch argv'de `--disable-gpu` VE `--disable-software-rasterizer` flag'leri birlikte kullanılıyordu. Bu ikisi Chrome'un WebGL desteğini TAMAMEN kapatıyor — ne hardware GPU ne software rasterizer kullanılamıyor, sonuçta `gl.getContext('webgl')` başarısız oluyor veya `WEBGL_debug_renderer_info` extension'ı mevcut olmuyor.

**Kaynak:**
- https://roundproxies.com/blog/bypass-funcaptcha/ — Arkose BDA `webgl_vendor` ve `webgl_renderer` alanlarını toplar; boş değerler şüpheli
- https://torchproxies.com/how-to-bypass-captcha-complete-guide-2026/ — "Google SwiftShader is a dead giveaway"
- https://scrapfly.io/blog/posts/puppeteer-stealth-complete-guide/ — chrome.runtime emulation ve WebGL monkey-patch teknikleri
- https://peter.sh/experiments/chromium-command-line-switches/ — Chromium flag belgeleri

**Düzeltme (3 aşamalı):**

1. **`--disable-gpu` ve `--disable-software-rasterizer` KALDIRILDI:**
   - `src/browser_init.zig` — `buildChromeArgvWithBinary()` return array'inden bu iki flag çıkarıldı
   - `CHROME_ARG_COUNT` 20 → 18'e düşürüldü
   - Chrome artık varsayılan olarak software rasterizer (SwiftShader) kullanacak

2. **WebGL `getParameter` monkey-patch eklendi:**
   - `src/stealth_evasion.js` — `WebGLRenderingContext.prototype.getParameter` ve `WebGL2RenderingContext.prototype.getParameter` patch'leniyor
   - YALNIZCA `UNMASKED_VENDOR_WEBGL` (0x9245) ve `UNMASKED_RENDERER_WEBGL` (0x9246) enum değerleri intercept ediliyor
   - Diğer tüm `getParameter` çağrıları orijinal implementasyona passthrough
   - Sahte değerler: `vendor = "Intel"`, `renderer = "Mesa DRI Intel(R) HD Graphics 620 (Kaby Lake GT2)"` — Linux Chrome için tipik

3. **chrome.runtime emülasyonu eklendi:**
   - `window.chrome.runtime` object oluşturuldu: `connect()`, `sendMessage()`, `onConnect`, `onMessage`, `onDisconnect` event listeners
   - `toString()` native code string döndürüyor
   - `Page.addScriptToEvaluateOnNewDocument` ile bridge script'inden ÖNCE enjekte ediliyor

**Testler:**
- `browser_init.zig` testleri — `--disable-gpu` ve `--disable-software-rasterizer` YOK doğrulaması eklendi (8 test geçti)
- `browser_bridge.zig` testleri — 24 test geçti
- `zig build-exe` — başarıyla derlendi

**Tekrar olmaması için:**
- Chrome launch argv'de `--disable-gpu` ile `--disable-software-rasterizer` BİRLİKTE KULLANILMAZ
- WebGL vendor/renderer boş bırakılamaz — ya real GPU, ya SwiftShader, ya monkey-patch
- chrome.runtime emülasyonu CDP ile açılan Chrome'larda ZORUNLU

---


## [2026-04-11] — Browser Bridge Readiness Check Advanced On The Stale Pre-Reload DOM And Hid Injection Failures

**Hata:** `captureSignupBundle()`, `captureVerifyBundle()` ve `navigateToAccountVerifications()` yalnızca form/path varlığına bakarak ilerliyordu. Reload asenkron yürürken eski document üzerindeki form hâlâ bulunduğu için wait erken true dönüyor, sonra `window.__ghostBridge.*` çağrıları yeni sayfada bridge yüklenmeden çalışıp `TypeError` üretiyordu. Aynı anda `addScriptOnNewDocument()` CDP yanıtındaki top-level `error` alanını kontrol etmediği için bridge enjeksiyon hataları sessizce yutuluyordu.

**Kök sebep:** Browser readiness için yanlış source-of-truth seçildi. DOM/form varlığı tek başına yeni document'in hazır olduğunu kanıtlamıyordu; bridge global'i reload sonrası gerçek senkronizasyon işaretiydi. Ayrıca CDP command ack envelope'u structured parse edilmediği için `Page.addScriptToEvaluateOnNewDocument` başarısız olsa bile akış başarılı sanılıyordu.

**Kaynak:**
- Chrome DevTools Protocol `Page.addScriptToEvaluateOnNewDocument` — script yeni document oluşturulurken frame scriptlerinden önce yüklenir; başarısız command response’u top-level `error` taşıyabilir
- Chrome DevTools Protocol `Runtime.evaluate` — hatalar `exceptionDetails` ve `result.result.description` ile raporlanır

**Düzeltme:**
1. Reload/navigate sonrası wait ifadeleri `!!window.__ghostBridge` şartı ile güçlendirildi.
2. `addScriptOnNewDocument()` CDP `error` envelope’unu parse edip `CdpError` döndürüyor.
3. `BrowserBridge.init()` reload sonrası bridge readiness doğruluyor; kayıt başarısızsa veya bridge hâlâ yoksa script doğrudan `Runtime.evaluate` ile fallback enjekte ediliyor.
4. `extractRuntimeEvaluateStringValue()` artık `exceptionDetails` / `description` ayrıntılarını logluyor; audit hata kodu da artık `no_response` yerine sınıflandırılmış hata etiketi taşıyor.
5. `dismissPageBlockers()` bridge yokken `TypeError` üretmek yerine güvenli şekilde skip ediyor.

---

## [2026-04-12] — Browser Startup Wait, Cookie Dismiss False Positive, And Flash-Fill Behavior Hid The Real Signup Bridge State

**Hata:** Signup videosunda motor uzun süre hiçbir şey yapmıyor, sonra form alanları bir anda doluyor gibi görünüyordu. Ayrıca cookie banner kapatılmış gibi log düşmesine rağmen banner ekranda kalabiliyordu.

**Kök sebep:** Üç ayrı problem üst üste biniyordu:
1. `BrowserBridge.init()` current page üzerinde bridge yoksa doğrudan inject etmek yerine `addScriptOnNewDocument` + readiness wait hattında uzun süre bekliyordu. Bu yüzden browser video uzun süre statik kalıyordu.
2. `findCookieBannerRoot()` gerçek cookie banner node'unu değil çoğu zaman tüm signup page container'ını eşliyordu. Bu yüzden `dismissPageBlockers()` button aramasını yanlış scope'ta yapıp sahte başarı üretebiliyordu.
3. Signup bridge JS alanlara `el.value = ...` ile tek hamlede yazıyor, sabit `sleep(50)` gecikmeleri kullanıyor, karakter bazlı typing / jitter / adımlı scroll yapmıyordu. Sonuç: insan davranışı yerine “flash-fill” görünümü oluşuyordu.

**Kaynak:**
- Chrome DevTools Protocol `Runtime.evaluate` — current page context'e helper script doğrudan inject edilebilir
- GitHub live signup DOM inspection, 2026-04-12 — cookie banner altta `Accept/Reject/Manage cookies` button'ları ile ayrı görünür node olarak bulunuyor
- `src/jitter_core.zig` — projedeki mevcut behavioral jitter source-of-truth

**Düzeltme:**
1. Browser bridge startup hattı current page'e direct inject + kısa readiness timeout modeline çekildi; reload bekleyişi primary path olmaktan çıkarıldı.
2. Cookie dismiss logic banner-root regex yerine visible `Accept` button aramasına çevrildi.
3. Signup/verify JS akışları Zig jitter planından beslenen karakter bazlı typing, adımlı scroll ve human click modeline taşındı.

---

## [2026-04-11] — Passive CDP Token Polling Watched The Wrong Session Instead Of Freezing The Real Browser Request

**Hata:** BrowserBridge, `Runtime.evaluate(harvest.js)` ile `window.__ghost_token` / `window.__ghost_identity` poll ederek browser'ın anti-bot state'ini alabileceğini varsayıyordu. Gerçekte signup/risk/final POST raw motor session'ında dönüyor, Chrome tab ise ayrı session'da pasif izleyici olarak kalıyordu. Sonuç: CDP bağlantısı sağlıklı olsa bile browser tarafında üretilecek request hiç oluşmuyor ve harvest timeout veriyordu.

**Kök sebep:** Yanlış source-of-truth. Anti-bot state'i token/cookie/hidden field seviyesinde browser session-bound idi, ama kod raw session ile browser session'ı ayrı tutup sadece tek bir token alanını köprülemeye çalışıyordu. Bu model ya boş token üretiyor ya da yanlış session token'ını raw POST'a takıyordu.

**Kaynak:**
- Chrome DevTools Protocol `Page.addScriptToEvaluateOnNewDocument` — frame scriptlerinden önce helper yüklenebilir
- Chrome DevTools Protocol `Fetch.requestPaused` — browser'ın göndermeye hazır olduğu exact request request-stage'de durdurulabilir
- Chrome DevTools Protocol `Network.setCookie` — raw response'ta dönen session cookie rotasyonu browser session'ına geri yazılabilir

**Düzeltme:**
1. Browser source-of-truth modeli kuruldu; browser artık pasif token poll etmez, gerçek signup/verify request'ini üretir.
2. `Fetch.requestPaused` event'inden exact `url + method + headers + postData` yakalanıp `RequestBundle` olarak Zig'e taşınır.
3. Raw motor final signup/verify POST'larını artık browser-captured bundle ile replay eder; field ordering postData string'inden, modern browser headers ise captured header map'inden gelir.
4. Raw final signup response'unda dönen cookie rotasyonu `Network.setCookie` ile browser session'ına geri senkronize edilir; böylece `account_verifications` fazı aynı session'da devam eder.

---

## [2026-04-11] — Browser Diagnostics Initially Failed Before Capturing Real UI State

**Hata:** Browser trace modu açıldığında motor gerçek signup UI durumunu kaydetmeden düşüyordu. Sırayla üç ayrı hata gözlendi:
1. `Runtime.evaluate` dönüşündeki escaped JSON string elle `"value":"..."` aranarak kesiliyor, ilk escaped quote'ta kırılıyordu.
2. `Page.captureScreenshot` cevabı 64 KB üstüne çıktığında WebSocket alıcısı `WsFrameError` veriyordu.
3. `sendCommand()` top-level response yerine event payload içindeki nested `"id"` alanını kendi cevabı sanabiliyordu.

**Kök sebep:** CDP mesajları için text-search temelli parsing kullanılması. Hem `Runtime.evaluate` envelope'u hem de WebSocket/CDP response matching'i spec'e uygun, structured parse ile ele alınmıyordu. Screenshot cevabında da RFC 6455 extended payload path'i doğru okunmuyordu.

**Kaynak:**
- Chrome DevTools Protocol — `Runtime.evaluate` JSON envelope (`id` top-level, `result.result.value` nested)
- Chrome DevTools Protocol — `Page.captureScreenshot` base64 PNG döndürür, payload büyük olabilir
- RFC 6455, Section 5.2 — extended payload length (`126` / `127`) framing
- RFC 6455, Section 5.4 — message boundaries ve continuation mantığı

**Düzeltme:**
1. `Runtime.evaluate` string value extraction structured JSON parse ile yapıldı; escaped string elle kesilmiyor.
2. WebSocket alıcısı allocator-backed `recvWsTextAlloc()` yoluna taşındı; 64 KB üstü server text frame'leri okunuyor.
3. `sendCommand()` artık sadece top-level `id` alanını parse ediyor; event içindeki nested `context.id` response sanılmıyor.
4. Browser observability zinciri doğrulandı: gerçek koşuda `browser.mp4`, `browser-state.ndjson` ve `shot-*.png` artefact'leri üretiliyor.

---

---

## [2026-04-11] — GitHub HTTP/2 Transport Was Reused Across Long External Phases After Peer `close_notify`

**Hata:** GitHub signup akışı ilk `GET /signup` ve risk-check'ten sonra aynı TLS/HTTP/2 transport'u Xvfb/Chrome/CDP harvest ve mailbox hazırlığı boyunca elde tutuyordu. Sonraki preflight/signup veya verify-email isteği geldiğinde peer zaten `close_notify` ile bağlantıyı kapatmış olabiliyordu. Kod bu durumu `ReadTimeout` olarak raporluyor, ardından faz doğrudan fail oluyordu.

**Kök sebep:** İki katmanlı hata vardı:
1. `receiveTlsApplicationData()` `close_notify` gördüğünde bunu temiz kapanış olarak işaretleyip üst katmana `ConnectionClosed` taşımıyor, döngü sonunda `ReadTimeout` üretiyordu.
2. Orkestrasyon katmanı, uzun browser/mailbox fazlarından sonra GitHub transport'unun artık canlı olduğunu varsayıp aynı session state ile devam ediyordu; kapalı peer transport'u için refresh/retry yolu yoktu.

**Kaynak:**
- RFC 8446, Section 6.1 / verified errata 7303 — `close_notify` sender'ın bu connection üzerinde artık mesaj göndermeyeceğini bildirir; sonrasındaki veri yok sayılmalıdır.
- RFC 9113, Sections 5.1 / 6.1 / 6.2 — HTTP/2 stream tamamlanması `END_STREAM` ile olur; kapanmış transport tekrar kullanılamaz, yeni connection yeni preface/SETTINGS ile başlar.

**Düzeltme:**
1. `classifyTlsAlert()` eklendi; `close_notify` artık `ReadTimeout` yerine `ConnectionClosed` semantiği üretiyor.
2. `GitHubHttpClient.adoptHandshake()` eklendi; yeni handshake state'i alınırken cookie jar korunuyor, HTTP/2 preface state'i sıfırlanıyor.
3. `main.zig` signup ve verify-email fazlarında `ConnectionClosed` yakalandığında yeni SYN + yeni TLS handshake başlatıp aynı GitHub client state'ine yeni transport'u bağlıyor ve isteği bir kez retry ediyor.

---

## [2026-04-10] — CDP WebSocket Client Frame Length Was Byte-Swapped For 16-Bit Payloads

**Hata:** `CdpClient.sendWsText()` WebSocket text frame'i 126..65535 byte araligindaki payload'lar icin `frame-payload-length-16` alanini ters byte sirasi ile yaziyordu. `harvest.js` 10637 byte oldugu icin bu dal tetikleniyor, Chrome frame uzunlugunu yanlis okuyordu ve `Runtime.evaluate` cevabi gelmeden `sendCommand()` `ReadFailed` ile dusuyordu.

**Kök sebep:** `payload.len` once `nativeToBig(u16, ...)` ile byte-swap ediliyor, sonra tekrar `>> 8` / `& 0xFF` ile manual ayriliyordu. Bu iki donusum birlikte little-endian hostta wire uzerine `0x7E 0x00` benzeri ters length byte'lari yazdi.

**Kaynak:**
- RFC 6455, Section 5.2 — `frame-payload-length = ( %x00-7D ) / ( %x7E frame-payload-length-16 ) / ( %x7F frame-payload-length-63 )`
- RFC 6455, Section 5.4 — frame sinirlari garanti degildir; alici frame layout'una degil tam mesaja gore calismalidir
- man 7 socket — `SO_RCVTIMEO` socket I/O timeout'u uygular

**Düzeltme:**
1. `sendWsText()` 16-bit payload uzunlugunu dogrudan network byte order'da yazacak sekilde duzeltildi.
2. Regression testi eklendi: `sendWsText: 16-bit payload length is encoded in network byte order`.
3. WebSocket socket'ine `SO_RCVTIMEO` eklendi ve `recvExact()` hata/EOF siniri debug log'landi.

---

## [2026-04-10] — SYN Serializer Was Coupled To Live `TCP_INFO` Socket Telemetry

**Hata:** `buildTCPSynAlloc()`, `buildTCPAckAlloc()` ve `buildTCPDataAlloc()` packet serialize ederken `getLinuxTcpInfo()` ile yeni bir TCP socket aciyor, `getsockopt(TCP_INFO)` cevabindan `window` / `wscale` turetmeye calisiyordu. Sandbox veya yetki kisitli ortamlarda bu yol `EPERM` ile patliyor ve `zig build test` kirmaya basliyordu.

**Kök sebep:** Yanlis soyutlama. Packet serializer canli kernel socket durumuna baglanmisti. Oysa Linux istemci SYN pencere secimi `tcp_select_initial_window()` ve ilgili sysctl degerleriyle belirlenir; rastgele, baglantisiz bir socket'in `tcp_info` snapshot'i bunun dogru kaynagi degildir.

**Kaynak:**
- `linux/net/ipv4/tcp_output.c` — `tcp_select_initial_window()`
- `linux/net/ipv4/tcp_output.c` — SYN `th->window = min(tp->rcv_wnd, 65535U)`
- `include/net/tcp.h` — `__tcp_win_from_space()`, `tcp_full_space()`, `MAX_TCP_WINDOW`, `TCP_MAX_WSCALE`, `TCP_DEFAULT_SCALING_RATIO`
- `Documentation/networking/ip-sysctl.rst` — `tcp_rmem`, `tcp_window_scaling`

**Düzeltme:** `TCP_INFO` telemetry hattı serializer'dan söküldü. Yerine `/proc/sys` degerlerini okuyan ve kernel formülunu uygulayan `TcpWindowProfile` resolver eklendi. SYN/ACK/DATA serializer'lari ayni profile hattini kullaniyor. Canli regression testi eklendi: SYN packet'in `window` ve `wscale` alanlari, o anki Linux kernel profile hesabiyla birebir eslesiyor.

---

## [2026-04-09] — Digistallone Livewire Create Flow Was Modeled Incorrectly

## [2026-04-09] — GitHub Signup Preflight Used The Wrong CSRF Token

**Hata:** `performSignup()` browser’daki preflight zincirini ekledikten sonra bile ilk `POST /email_validity_checks` isteği `HTTP 422` dönüyordu ve generic `Oh no · GitHub` hata sayfasına düşüyordu.

**Kök sebep:** Preflight validation endpoint’leri formun ana `name="authenticity_token"` alanını kullanmıyor. Her `auto-check` bileşeni kendi `data-csrf="true"` hidden input değerini kullanıyor:
- `/email_validity_checks` için email auto-check token’ı
- `/password_validity_checks?...` için password auto-check token’ı

Motor form token’ını preflight POST’lara koyduğu için GitHub request’i CSRF/validation açısından geçersiz sayıyordu.

**Kaynak:**
- GitHub signup raw HTML, 2026-04-09:
  - `<auto-check src="/email_validity_checks"> ... <input type="hidden" data-csrf="true" value="...">`
  - `<auto-check src="...password_validity_checks..."> ... <input type="hidden" data-csrf="true" value="...">`
- GitHub canlı browser network trace, 2026-04-09:
  - `POST /email_validity_checks` request body token’ı form token’ından farklı
  - `POST /password_validity_checks?...` request body token’ı da endpoint-spesifik

**Düzeltme:**
1. `extractAutoCheckCsrfToken()` eklendi.
2. `runSignupPreflightChecks()` artık email/password preflight’larında endpoint-spesifik `data-csrf` token’larını kullanıyor.
3. Regression testi eklendi: `extractAutoCheckCsrfToken: extracts endpoint-specific validation tokens`.

**Hata:** `getNewEmailAddress(null)` çoğu durumda mevcut mailbox adresini geri döndürüyordu; yeni adres üretemiyordu. `createEmail()` ayrıca browser’ın gerçek Livewire create akışını tek request’te taklit etmeye çalışıyordu.

**Kök sebep:** İki ayrı hata üst üste biniyordu:
1. `getNewEmailAddress()` mevcut email varsa `preferred_domain == null` durumunda create akışına girmeden erken dönüyordu.
2. Gerçek Digistallone/browser akışı `user` ve `domain` için iki ayrı update request’i yollayıp yeni checksum’lı snapshot alıyor, ardından `create` çağrısını boş `updates` ile yapıyor. Bizim model ise `user` + `domain` değerlerini tek create request’ine gömüyordu. Üstelik `create` cevabı JSON state değil, `302 -> /mailbox` redirect idi.
3. `updateStateFromResponse()` escaped snapshot string içinde component adını yanlış biçimde aradığı için (`\"name\"` yerine `"name"`) update cevaplarından yeni snapshot’ları belleğe alamıyordu.

**Kaynak:**
- Digistallone canlı browser network trace, 2026-04-09
- Digistallone canlı HTTP/1.1 replay, 2026-04-09
- Livewire JavaScript docs — `snapshotEncoded` / commit payload
- Livewire source — `src/Mechanisms/HandleComponents/Checksum.php`

**Düzeltme:**
1. `getNewEmailAddress()` içindeki hatalı erken dönüş kaldırıldı.
2. `createEmail()` browser wire-truth’a göre yeniden yazıldı:
   - önce `user` update
   - sonra `domain` update
   - sonra boş `updates` ile `create`
   - ardından `/mailbox` GET + `parseInitialState()`
3. `buildUpdateRequest()` artık calls dizisini boş bırakabiliyor.
4. `updateStateFromResponse()` escaped snapshot’ı önce unescape edip sonra component name/snapshot update yapıyor.
5. `parseInitialState()` re-parse öncesi component/email state’ini resetliyor.

---

## [2026-04-09] — Poll Snapshot Unicode Escapes Were Corrupted

**Hata:** Mailbox polling sırasında `frontend.app` snapshot’ı içindeki mesaj içerikleri ve sender alanları `\u0131`, `\u00e7` gibi Unicode escape’ler içeriyordu. `updateStateFromResponse()` bu snapshot’ı `unescapeJsonString()` ile decode ederken non-ASCII `\uXXXX` codepoint’leri alt byte’a kırpıyordu. Örneğin `\u0131` -> `0x31` (`'1'`) gibi bozulmalar oluşuyordu.

**Kök sebep:** `unescapeJsonString()` yalnızca ASCII-range için tasarlanmıştı ama gerçek Digistallone poll response’ları UTF-16 JSON Unicode escape’leri taşıyordu. Bu bozuk decode sonucu, sonraki poll request’lerinde kullanılan snapshot string semantik olarak çürüyordu.

**Kaynak:**
- Digistallone canlı poll response, 2026-04-09 (`/tmp/digistallone-latest-poll-response.json` içinde `\\u0131`, `\\u00e7`)
- RFC 8259, Section 7 — JSON string escaping

**Düzeltme:**
1. `unescapeJsonString()` UTF-8 encode edecek şekilde yeniden yazıldı.
2. UTF-16 surrogate pair desteği eklendi.
3. Regression testi eklendi: `unescapeJsonString: decodes unicode escapes as UTF-8`.

---

## [2026-04-09] — Engine Was Polling Mailbox After GitHub Signup Had Already Failed

**Hata:** `ghost_engine` signup aşamasında GitHub formu yeniden render etmesine rağmen mailbox polling’e geçiyordu. Bu yüzden süreç dakikalarca/sonsuz gibi bekliyordu; çünkü verification mail henüz garanti edilmemişti.

**Kök sebep:** İki seviye problem vardı:
1. `network_core.performSignup()` `200 OK` gövdede sadece `logout` / `dashboard` geçmesine bakarak yanlış başarı kararı verebiliyordu.
2. `main.zig` `signup_success == false` olsa bile polling aşamasına devam ediyordu.

**Canlı kanıt (2026-04-09):**
- `ghost_engine` log’u: `[SIGNUP] FAILED: 200 OK but no success indicators (form re-rendered)` hemen ardından `[MAIL] Polling...`
- Dump edilen `/tmp/github-signup-failure.html` içinde:
  - `We couldn't create your account`
  - `GitHub requires JavaScript to proceed with the sign up process`
  - `js-octocaptcha-load-captcha`
  - `name="octocaptcha-token"`

**Düzeltme:**
1. `performSignup()` artık generic `logout` / `dashboard` stringlerini başarı saymıyor; yalnızca verification-step marker’larını kabul ediyor.
2. GitHub signup payload’ı browser FormData’ya yaklaştırıldı: `filter=` ve dynamic `required_field_xxxx=` eklendi.
3. `main.zig` signup başarısızsa mailbox polling’e GİRMEDEN fatal exit yapıyor.

---

## [2026-04-09] — Digistallone HTTP Framing / Cookie / Entity Decoder Rewrite

**Hata:** `recvFullResponse()` sadece `Content-Length` kabul ediyor, `postJson()` boş `x-livewire:` ve sabit 8 KB request buffer kullanıyordu, `CookieJar.setCookie()` session cookie adını `tmail_session` varsayıyordu, `decodeHtmlAttributeInto()` ise sadece birkaç sabit HTML entity tanıyordu.

**Kök sebep:** HTTP/1.1 response framing (chunked vs close-delimited), RFC 6265 cookie-pair parsing ve Blade/JSON escape kombinasyonu tek bir wire-level model yerine sabit varsayımlarla implement edilmişti.

**Kaynak:**
- RFC 9112, Section 6.3 — Message Body Length
- RFC 9112, Section 7.1.3 — Decoding Chunked
- RFC 6265, Section 5.2 — The Set-Cookie Header
- RFC 6265, Section 4.2.1 / 4.2.2 — Cookie header syntax and semantics
- RFC 8259, Section 7 — JSON string escapes

**Düzeltme:**
1. `recvFullResponse()` artık `readHttpResponseBodyFromReader()` helper’ı üzerinden `Transfer-Encoding: chunked`, `Content-Length`, ve close-delimited body modlarını ayırıyor.
2. `postJson()` sabit `[8192]u8` yerine allocator-backed dynamic request builder kullanıyor ve `x-livewire: true` gönderiyor.
3. `CookieJar` artık dinamik session cookie adını saklayıp `Cookie:` header’ına aynı adıyla geri yazıyor.
4. `decodeHtmlAttributeInto()` numeric HTML entity’leri (`&#39;`, `&#x27;` vb.) ve güvenli JSON `\uXXXX` escape’lerini decode ediyor.
5. Regression testleri eklendi: large payload request build, chunked response decode, dynamic session cookie header, robust entity decoding.

---

## [2026-04-09] — Stale Timer Paradox: 120-Attempt Dead Loop on Closed Socket

**Hata:** `pollInboxForGitHubCode()` fonksiyonunda `TcpRecvFailed` catch bloğu `ensureConnected()` çağırıyordu. `ensureConnected()` ise `isStale(3000)` ile bağlantının idle olup olmadığını kontrol ediyordu. Ancak `recvFullResponse` fonksiyonundaki `defer self.recordActivity()` satırı, TcpRecvFailed hatası ALINDIKTAN SONRA bile `last_activity_ns` timestamp'ini güncelliyordu. Bu paradoks nedeniyle:

1. `recvFullResponse` → TcpRecvFailed → `defer recordActivity()` timer'ı NOW'a günceller
2. catch bloğu → `ensureConnected()` → `isStale(3000)` → timer 1ms önce güncellendi → **FALSE**
3. `ensureConnected()` hiçbir şey yapmaz, ölü socket ile devam eder
4. Loop 120 kez tekrarlanır, her seferinde aynı ölü socket denenir

**Kök sebep:** `defer recordActivity()` hem başarılı hem başarısız recv operasyonlarında çalışıyordu. `ensureConnected()` sadece staleness'e bakıyordu, recv failure'ı doğrudan kanıt olarak kullanmıyordu.

**Kaynak:** man 2 socket — kapalı soketten read EOF/timeout döner
**Kaynak:** LiteSpeed docs — keepalive_timeout 5s, sonrasında socket sessizce kapatılır

**Düzeltme (3 aşamalı):**

1. **`defer recordActivity()` kaldırıldı**: `recvFullResponse` içindeki `defer self.recordActivity()` satırı silindi. `recordActivity()` artık sadece body başarıyla okunduktan SONRA çağrılıyor (line ~727).

2. **`forceReconnect()` eklendi**: Yeni fonksiyon, staleness kontrolü YAPMADAN koşulsuz reconnect yapıyor:
   ```zig
   pub fn forceReconnect(self: *DigistalloneClient) DigistalloneError!void {
       self.http.deinit();
       var new_http = try HttpClient.init(...);
       const html = try new_http.get(self.allocator, "/mailbox", "");
       try self.livewire.parseInitialState(self.allocator, html);
       self.http = new_http;
   }
   ```

3. **`pollInboxForGitHubCode` catch bloğu güncellendi**:
   ```zig
   if (err == DigistalloneError.TcpRecvFailed) {
       try self.forceReconnect();  // ensureConnected() DEĞİL
       continue;
   }
   ```

4. **`buildUpdateRequest` std.json.Stringify ile yeniden yazıldı**: `std.fmt.allocPrint` + string interpolation yerine `std.json.Stringify` stream API kullanılarak tüm string değerler otomatik escape ediliyor.

5. **`Connection: keep-alive` header eklendi**: Hem `get()` hem `postJson()` fonksiyonlarına `Connection: keep-alive\r\n` header'ı eklendi (RFC 7230, Section 6.1).

**Tekrar olmaması için:**
- `recvFullResponse` gibi I/O fonksiyonlarında `defer recordActivity()` KULLANILMAZ
- TcpRecvFailed gibi connection failure durumlarında `forceReconnect()` gibi koşulsuz reconnect kullanılır
- `ensureConnected()` sadece proaktif/preventive kullanım içindir, reactive error handling için değil
- JSON payload'ları string interpolation ile DEĞİL, `std.json.Stringify` veya eşdeğeri ile oluşturulur

---

## [2026-04-09] — Malformed JSON Payload in buildUpdateRequest: TcpRecvFailed

**Hata:** `LivewireClient.buildUpdateRequest()` ile üretilen Livewire update request JSON'u malformed olabiliyordu. `comp.snapshot` ham JSON içeriyordu (örn. `{"data":...}`) ve `std.fmt.allocPrint` ile `{f}` placeholder'ı kullanılarak inject edildiğinde, snapshot içindeki çift tırnaklar doğru şekilde escape edilmeyebiliyordu. Sonuç: LiteSpeed server geçersiz JSON parse edemiyor ve bağlantıyı kesiyordu → `error.TcpRecvFailed`.

**Kök sebep:** `std.fmt.allocPrint` format string'i ile kompleks JSON build etmek fragile. `std.json.fmt()` string escaping yapsa bile, format string içindeki `{f}` placeholder'ının davranışı ve raw JSON string'lerin (`{s}` ile embed edilen params/updates) karışımı tutarsız sonuçlar üretebiliyordu.

**Kaynak:** RFC 8259, Section 7 — JSON string escaping rules
**Kaynak:** Chrome DevTools wire-truth — browser `JSON.stringify()` ile properly escaped payload gönderiyor

**Düzeltme:**
1. `jsonEscape()` helper fonksiyonu eklendi — herhangi bir string'i RFC 8259 uyumlu şekilde JSON string olarak escape eder
2. Two-pass approach:
   - Pass 1: Exact escaped length hesaplanır (her karakter için escape boyutu bilinir)
   - Pass 2: Tam doğru capacity ile `ArrayList` oluşturulur, `appendAssumeCapacity` ile güvenli yazım
3. `buildUpdateRequest` artık her string değeri (`_token`, `snapshot`, `method`) `jsonEscape()` ile escape edip `{s}` ile embed ediyor
4. `params_json` ve `updates_json` zaten valid JSON olduğu için doğrudan `{s}` ile embed ediliyor (double-escape yok)
5. Vendor Zig 0.16 `ArrayList` API farklılıkları handle edildi:
   - `init()` yerine `initCapacity(allocator, len)` (Aligned versiyonunda init yok)
   - `deinit()` → `deinit(allocator)`
   - `toOwnedSlice()` → `toOwnedSlice(allocator)`
   - `appendSlice()` → `appendSliceAssumeCapacity()` (capacity önceden biliniyor)

**Tekrar olmaması için:**
- Kompleks JSON build edilirken `std.fmt.allocPrint` + string interpolation KULLANILMAZ
- Ya `std.json.stringify` (struct-based) ya da explicit escaping helper kullanılır
- Her escaping fonksiyonu two-pass (length calc + write) ile bounds safety garanti edilir

---

## [2026-04-09] — Stale Keep-Alive Connection: TcpRecvFailed After 11-Second Idle

**Hata:** `DigistalloneClient` GitHub signup süreci (~11 saniye) boyunca idle kaldıktan sonra `pollInboxForGitHubCode()` çağrıldığında `error.TcpRecvFailed` fırlatıyordu.

**Kök sebep (detaylı analiz):**
```
Timeline:
  T=0s    → DigistalloneClient.init() → TCP+TLS aç → GET /mailbox → CSRF alındı
  T=0-11s → GitHub signup süreci (BDA, Arkose, form POST, vs.) — Digistallone socket IDLE
  T=5s    → LiteSpeed Keep-Alive timeout → server TCP'yi SESSİZCE kapattı
  T=11s   → pollInboxForGitHubCode() → sendRaw() → OS buffer'a yazdı (hata YOK)
             → recvFullResponse() → reader.take(1) → KAPALI soket → TcpRecvFailed 💥
```

**Neden sendRaw hata vermedi ama recvFullResponse verdi:**
- `writer.writeAll()` → OS kernel TCP buffer'a yazar (async)
- `writer.flush()` → TLS buffer'ı flush eder ama TCP ACK'sı gelmeden döner
- `reader.take(1)` → Sunucudan byte bekler → kapalı soket → ECONNRESET/EOF

**LiteSpeed Keep-Alive varsayılanları:**
- `keepalive_timeout`: 5 saniye
- `maxKeepAliveRequests`: 10000
- Idle connection 5s sonra sessizce kapatılır (RST gönderilmez, sadece TCP FIN)

**Düzeltme (3 katmanlı savunma):**
1. **`HttpClient.last_activity_ns`** — Her send/recv sonrası timestamp güncellenir
2. **`HttpClient.isStale(max_idle_ms)`** — Idle süresi threshold'u aşmışsa true döner
3. **`DigistalloneClient.ensureConnected()`** — Poll öncesi staleness kontrolü:
   - Idle > 3s ise http.deinit() + HttpClient.init() ile TAM YENİ bağlantı
   - GET /mailbox ile CSRF yenile + Livewire state parse
4. **`pollInboxForGitHubCode` retry logic** — TcpRecvFailed olursa ensureConnected + retry

NOT: İlk `reconnect()` implementasyonu çalışmadı — partial reconnect sırasında TLS handshake sonrası bağlantı stabil olmadı. Çözüm: `deinit()` + `init()` ile sıfırdan bağlantı.

**Kaynak:**
- LiteSpeed docs — `keepalive_timeout` default 5s
- man 2 clock_gettime — CLOCK_MONOTONIC for elapsed time measurement
- RFC 7230, Section 6.3 — HTTP/1.1 persistent connections and idle timeout

**Tekrar olmaması için:**
- Her HTTP client connection için idle timeout tracking zorunlu
- 5 saniyeden uzun operasyonlar öncesi connection health check yapılmalı
- TcpRecvFailed aldığında otomatik reconnect + retry mekanizması olmalı

---

## [2026-04-09] — Digistallone `pollInbox` Yanlış Livewire Component Index'ine Request Gönderiyordu

**Hata:** `LivewireClient.pollInbox()` çağrısı `component_idx = 1` ile `frontend.nav` component'ine `fetchMessages` dispatch ediyordu. `fetchMessages` metodu `frontend.nav`'da yok → server 500 Internal Server Error döndürüyordu.

**Kök sebep:** Sayfada 3 Livewire component var (HTML'deki sırayla):
1. `[0] frontend.actions` — email oluşturma, `syncEmail` listener
2. `[1] frontend.nav` — navigasyon menüsü, **hiçbir listener yok**
3. `[2] frontend.app` — inbox/mesajlar, `syncEmail` + `fetchMessages` listeners

`pollInbox` yanlışlıkla index 1 (`frontend.nav`) kullanıyordu. Doğru index 2 (`frontend.app`).

**Wire-Truth Kaynak (Chrome DevTools MCP + curl doğrulaması, 2026-04-09):**
```
Sayfa yapısı (3 component):
  [0] frontend.actions | email=None | listeners: [syncEmail, checkReCaptcha3]
  [1] frontend.nav     | email=N/A  | listeners: []
  [2] frontend.app     | email=None | listeners: [syncEmail, fetchMessages]

Browser refresh request (sadece frontend.app):
  POST /livewire/update
  Component: frontend.app (index 2)
  Calls: [{method: "__dispatch", params: ["fetchMessages", {}]}]
  Response: HTTP 200 OK → JSON with effects.html
```

**Düzeltme:**
1. `findComponentByName()` helper metodu eklendi — component'ı isme göre bulur
2. `pollInbox` artık `findComponentByName("frontend.app") orelse 2` kullanır
3. `updateStateFromResponse` daha önce düzeltilmişti — tüm component'ları name-based matching ile güncelliyor
4. `unescapeJsonString` helper — `effects.html` JSON-escaped HTML'ini decode eder

**Ek bulgular (curl ile doğrulandı):**
- HTTP/1.1 protocol digistallone.com'da sorunsuz çalışıyor (server LiteSpeed, h2 + h1 destekliyor)
- `Origin`/`Referer` header'ları CSRF validation için gerekli DEĞİL (cookie + _token yeterli)
- `x-livewire:` header boş değerle bile gönderilmeli (browser bunu yapıyor)
- `Accept-Encoding: identity` çalışıyor — server uncompressed JSON döndürüyor
- **KRITIK**: `#HttpOnly_` prefix'li cookie'ler curl cookie jar'da comment gibi görünür ama gerçek cookie'dir. Python testinde bu yüzden `tmail_session` cookie'si gönderilmiyordu.

**Tekrar olmaması için:**
- Her Livewire request öncesi Chrome DevTools ile component order doğrulanacak
- Component index'leri hardcode yerine name-based lookup ile bulunacak
- Cookie parsing'te `#HttpOnly_` prefix handling yapılacak

---

## [2026-04-09] — Digistallone `TcpRecvFailed`: Eksik CSRF Header'ları ve Stale Snapshot

**Hata:** `DigistalloneClient.pollInboxForGitHubCode()` çağrısı `error.TcpRecvFailed` ile başarısız oluyordu. Server bağlantayı erken kapatıyordu.

**Kök sebep:** Üç ayrı sorun aynı anda etkiliyordu:

1. **Eksik `Referer` ve `Origin` header'ları** — Laravel'in `VerifyCsrfToken` middleware'i bu header'ları doğruluyor. Zig kodu bunları göndermiyordu, server 419 CSRF mismatch dönüyordu.
2. **Eksik `x-livewire:` header** — Browser boş değerle bile gönderiyor (`x-livewire: `). Livewire v3 server-side bu header'ı bekliyor.
3. **Stale snapshot** — `updateStateFromResponse` sadece `components[0]` (frontend.actions) güncelliyordu. `pollInbox` ise `components[1]` (frontend.app) kullanıyor. Bu component'in snapshot'u hiç yenilenmiyordu — server eski snapshot ile gelen request'i reddediyor veya stale data döndürüyordu.

**Wire-Truth Kaynak (Chrome DevTools MCP, 2026-04-09):**
```
Browser POST /livewire/update headers:
  origin:https://digistallone.com
  referer:https://digistallone.com/mailbox
  x-livewire:
  content-type:application/json
  cookie:XSRF-TOKEN=...; tmail_session=...

Browser snapshot (frontend.app):
  {"data":{"messages":[[],{"s":"arr"}],...,"initial":true,...},
   "memo":{"id":"dGjCh8D4wpXL2aJ6NgdX","name":"frontend.app",...},
   "checksum":"b1fa3fd54475e7fe08e4693d68122122263d1d677b5231cd4c561f58d2b0d018"}
```

**Düzeltme:**
1. `postJson` fonksiyonuna 3 header eklendi:
   - `Origin: https://digistallone.com`
   - `Referer: https://digistallone.com/mailbox`
   - `x-livewire: ` (boş değer)
2. `updateStateFromResponse` tamamen yeniden yazıldı:
   - Response'daki TÜM snapshot'ları parse ediyor
   - Her snapshot'ı component name'e göre eşleştiriyor
   - Hem JSON string (`"snapshot":"{...}"`) hem raw object (`"snapshot":{...}`) formatını destekliyor
3. `pollInboxForGitHubCode` her poll sonrası `updateStateFromResponse` çağırıyor
4. `unescapeJsonString` helper eklendi — `effects.html` JSON-escaped HTML'ini decode ediyor
5. User-Agent versiyonu `Chrome/146` → `Chrome/147` (wire-truth ile eşleşmesi için)

**Tekrar olmaması için:**
- Her Livewire request öncesi Chrome DevTools ile wire-truth capture edilecek
- Header eksiklikleri against browser comparison ile doğrulanacak
- Snapshot freshness her component için ayrı ayrı doğrulanacak

---

## [2026-04-09] — Module 3.2: Vendored stdlib API Drift File I/O ve Sleep Fonksiyonlarını Bozdu

**Hata:** `main.zig`'de `std.fs.cwd().createFile()` ve `digistallone.zig`'de `posix.nanosleep()` kullanıldı. İkisi de vendored Zig 0.16.0 stdlib'de mevcut değildi — derleme hatası verdi.

**Kök sebep:** Standart Zig 0.16.0 ile projenin `vendor/zig-std` kopyası arasında API farklılıkları var. `std.fs` modülü bu vendored kopyada `std.Io` olarak yeniden adlandırılmış. `posix.nanosleep` da aynı şekilde taşınmış — `io.sleep(Duration, .awake)` kullanılması gerekiyor.

**Kaynak:** `vendor/zig-std/std/Io/Dir.zig` — `createFile`, `openFile`, `OpenFileOptions.Mode`
**Kaynak:** `vendor/zig-std/std/Io/File.zig` — `writePositionalAll`, `length`
**Kaynak:** `vendor/zig-std/std/Io.zig` — `Duration.fromMilliseconds`, `io.sleep`

**Düzeltme:**
1. `std.fs.cwd().createFile()` → `std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false })`
2. `error.PathAlreadyExists` durumunda `openFile(io, path, .{ .mode = .write_only })` fallback
3. Append işlemi: `file.length(io)` → `file.writePositionalAll(io, data, len)`
4. `posix.nanosleep(&ts, null)` → `io.sleep(std.Io.Duration.fromMilliseconds(ms), .awake)`

**Tekrar olmaması için:**
- Zig API kullanırken önce `vendor/zig-std/std` dizininde arama yapılacak
- `std.fs.*` yerine `std.Io.*` namespace'i varsayılan
- `posix.*` zaman fonksiyonları yerine `io.sleep()` kullanılacak

---

## [2026-04-09] — Module 3.2: GitHub Email Verification Endpoint Eksikti

**Hata:** Signup sonrası email verification akışı için `verifyEmail` fonksiyonu ve `buildGitHubVerifyHeaders` HPACK encoder'ı yoktu.

**Kök sebep:** Sadece signup POST (`/signup`) implement edilmişti. Verification (`/signup/verify_email`) ayrıca ele alınmamıştı.

**Kaynak:** GitHub signup flow — POST `/signup/verify_email` with `verification_code` body
**Kaynak:** RFC 9113, Section 6.2 — HEADERS Frame for HTTP/2 POST

**Düzeltme:**
1. `GitHubHttpClient.verifyEmail()` — `network_core.zig`'e eklendi
   - Code validation: exactly 6 digits
   - HTTP/2 POST via new stream ID
   - Response parsing: 302 = success, 422 = wrong code
2. `buildGitHubVerifyHeaders()` — `http2_core.zig`'e eklendi
   - Same structure as signup headers
   - Referer: `https://github.com/signup/verify_email`
3. `main.zig` — Module 3.2 orchestration:
   - Credentials saved to `accounts.txt`
   - Livewire mailbox polling
   - Code extraction and submission
   - Success/failure reporting

**Tekrar olmaması için:**
- Her signup sonrası verification adımı zorunlu
- Verification endpoint ayrıca HPACK header set'i gerektirir

---

## [2026-04-09] — GitHub Signup POST HTTP 422: Eksik Header'lar ve _octo Cookie CSRF Doğrulama Hatası

**Hata:** `performSignup` fonksiyonu geçerli bir `authenticity_token` ve doğru kullanıcı bilgileriyle POST request gönderiyordu ama GitHub Rails backend'i HTTP 422 (Unprocessable Entity) döndürüyordu. Token extraction ve URL encoding doğruydu; sorun request formatındaydı.

**Kök sebep:** Üç kritik eksik vardı:
1. **`origin: https://github.com` header yoktu** — GitHub CSRF middleware'i origin header'ını bekliyor
2. **`referer: https://github.com/signup` header yoktu** — Request validation için gerekli
3. **`_octo` cookie request'e eklenmiyordu** — `GitHubCookieJar` bu cookie'yi parse etmiyor ve outbound request'e dahil etmiyordu. Bu cookie GitHub'ın request tracking/CSRF validasyonu için zorunlu.

Ayrıca `buildGitHubSignupHeaders` fonksiyonu bu üç header'ı içermiyordu ve `cookieHeader` metodu `_octo`'yu bilmiyordu.

**Kaynak:** Live DOM analysis of `https://github.com/signup` via Chrome DevTools MCP (2026-04-09)
**Kaynak:** Chrome DevTools `document.cookie` — `_octo=GH1.1.1820148997.1775692773` gözlemlendi
**Kaynak:** Chrome DevTools form input listesi — `origin` ve `referer` header gerekliliği, `_octo` cookie varlığı doğrulandı

**Düzeltme (Iteration 1):**
1. `GitHubCookieJar` struct'ına `octo: [128]u8` ve `octo_len: usize` field'ları eklendi
2. `setCookie` metodu `_octo` cookie'sini parse edip saklıyor
3. `cookieHeader` metodu `_octo`'yu outbound cookie string'e dahil ediyor
4. `buildGitHubSignupHeaders` (`http2_core.zig`) artık `origin: https://github.com` ve `referer: https://github.com/signup` header'larını HPACK encode ediyor

---

## [2026-04-09] — GitHub Signup POST HTTP 422: STAGE 3 — `timestamp` + `timestamp_secret` Tokens Missing, Payload Built Lazily

**Hata:** Iteration 1'den sonra bile 422 devam ediyordu çünkü:
1. `extractSignupHiddenFields` tüm hidden input'ları körü körüne payload'a ekliyordu — `timestamp` ve `timestamp_secret` dinamik token'ları HTML'den çıkarılmıyordu
2. Payload construction lazy'di — `writer.print` benzeri tek seferlik yazım yerine her field ayrı URL-encode edilip append edilmeliydi
3. `authenticity_token` extraction sadece tek bir token'ı çıkarıyordu — `timestamp` ve `timestamp_secret` aynı anda extract edilmeliydi

**Kök sebep:** Token extraction ve payload construction ayrı katmanlar olarak tasarlanmamıştı. `extractSignupHiddenFields` generic bir hidden field extractor olarak çalışıyordu ama `timestamp`/`timestamp_secret` gibi kritik anti-automation token'ları için dedicated extraction yoktu.

**Kaynak:** Live DOM analysis of `https://github.com/signup` via Chrome DevTools MCP (2026-04-09)
**Kaynak:** Recon Report — 17 input field, 12'si named, 3'ü honeypot, 11'i payload'a dahil

**Düzeltme (Iteration 2 / STAGE 3):**
1. `extractSignupTokens()` — yeni fonksiyon, `SignupTokens` struct döndürür:
   - `authenticity_token` (base64, ~88B)
   - `timestamp` (ms, ~13B)
   - `timestamp_secret` (hex, ~64B)
   - Her token'ı `allocator.dupe` ile heap'e kopyalar (caller owns)
2. `buildSignupPayload()` — EXACT wire-order payload builder:
   - `authenticity_token` → URL-encoded (base64 `+`→`%2B`, `/`→`%2F`, `=`→`%3D`)
   - `return_to` → empty
   - `invitation_token` → empty
   - `repo_invitation_token` → empty
   - `user[email]` → URL-encoded
   - `user[password]` → URL-encoded
   - `user[login]` → URL-encoded
   - `user_signup[country]=TR`
   - `user_signup[marketing_consent]=0`
   - `octocaptcha-token=` → empty (captcha not solved)
   - `timestamp` → extracted value
   - `timestamp_secret` → extracted value
3. `performSignup` — tam rewrite, step-by-step:
   - Token extraction → Payload construction → Cookie building → HPACK headers → Send → Parse response
   - 422 → explicit body dump (2000 bytes)
   - Timeout 5s → 10s
4. `extractAuthenticityToken` → DEPRECATED ama backward compat için korundu

**Tekrar olmaması için:**
- Her signup POST öncesi Recon Report'taki wire order'a uyulacak
- Tüm dinamik değerler URL-encoded olacak
- Honeypot alanlar (`filter`, `required_field_*`, boş isimli CSRF) asla payload'a eklenmeyecek

---

## [2026-04-09] — Digistallone Livewire Snapshot Parser Ham HTML Attribute Değerini Yanlış Kullandığı İçin Mailbox Akışı Çöküyordu

**Hata:** `LivewireClient.parseInitialState` `wire:snapshot="..."` aramasında bulunan offset’i kullanmıyordu; ilk component snapshot’ı fiilen `"\n<html dir="` ile başlıyordu. Üstelik attribute içindeki `&quot;` entity’leri decode edilmeden saklanıyor, `buildUpdateRequest` de bu veriyi JSON string yerine ham/object gibi POST ediyordu. Sonuç: request gövdesi geçersiz hale geliyor ve create akışı bozuluyordu. Ayrıca istemci, `GET /mailbox` içinde zaten bootstrap edilen mevcut email’i (`const email = '...'`) hiç okumadığı için gereksiz yere bozuk `create` yoluna giriyordu.

**Kök sebep:** Canlı site davranışı tarayıcıdaki Livewire istemcisine göre tasarlanmış. Livewire JS `wire:snapshot` attribute’unu DOM’dan decode edilmiş JSON string olarak okuyor ve request payload’ında `snapshot: this.component.snapshotEncoded` şeklinde string olarak gönderiyor. Mevcut Zig kodu ise ham HTML source üstünde çalıştığı halde DOM decode semantiğini taklit etmiyordu; ayrıca inline bootstrap email’i yok sayıyordu.

**Kaynak:** `https://digistallone.com/mailbox` — inline bootstrap script: `const email = '...'` + `Livewire.dispatch('syncEmail', { email })`
**Kaynak:** `https://digistallone.com/vendor/livewire/livewire.min.js?id=df3a17f2` — `this.snapshotEncoded = t.getAttribute("wire:snapshot")` ve request body: `JSON.stringify({_token:At(),components:t})` with `snapshot:this.component.snapshotEncoded`, `calls:[{path:"",method,...}]`

**Düzeltme:**
1. `parseInitialState` gerçek `wire:snapshot` başlangıç offset’ini kullanacak şekilde düzeltildi.
2. `wire:snapshot` attribute içeriği HTML entity decode edilerek saklanmaya başlandı.
3. Snapshot metadata (`memo.name`) JSON parse ile okunuyor; bootstrap email inline script’ten çıkarılıyor.
4. `buildUpdateRequest` artık Livewire JS ile uyumlu olarak `snapshot` alanını JSON string ve `calls[].path` alanını içerir biçimde üretiyor.
5. `getNewEmailAddress(null)` önce bootstrap edilen mevcut mailbox’ı döndürüyor; smoke test canlı sitede `current=...` ve `returned=...` eşitliğini doğruladı.

## [2026-04-09] — Livewire createEmail Response Sahipliği Unutulduğu İçin DebugAllocator Leak Veriyordu

**Hata:** `LivewireClient.createEmail` içinde `sendUpdate` çağrısından dönen response body parse ediliyor ama hiç `free` edilmiyordu. `recvFullResponse` body’yi `allocator.alloc` ile verdiği için shutdown sonunda DebugAllocator leak raporu üretiyordu.

**Kök sebep:** Caller-owned allocation zinciri yarıda kesildi. `HttpClient.recvFullResponse` -> `HttpClient.postJson` -> `LivewireClient.sendUpdate` -> `LivewireClient.createEmail` zincirinde son sahip `createEmail` idi ama ownership devri belgelense de serbest bırakma yoktu.

**Kaynak:** `vendor/zig-std/std/mem/Allocator.zig` — `alloc` sonrası allocator bilinmiyorsa doğru kod iş bitince `free` çağırmalıdır
**Kaynak:** `src/digistallone.zig` — `recvFullResponse` body’yi `allocator.alloc(u8, cl)` ile üretir

**Düzeltme:**
1. `LivewireClient.createEmail` içinde `const response = try self.sendUpdate(...)` sonrası `defer allocator.free(response);` eklendi.
2. Response parse aynı buffer üzerinden yapılıyor; email alanı internal state’e kopyalandıktan sonra response güvenle serbest bırakılıyor.

---

## [2026-04-09] — Digistallone TLS/HTTP Zinciri Embedded Reader Kopyası ve Flush Sözleşmesi Yüzünden Bozuldu

**Hata:** `src/digistallone.zig` içinde bağlantı zinciri parça parça ele alındığı için gerçek kırılma noktası gizlendi. Sorun tek bir `TcpConnectFailed` değildi; aynı zincirde birden fazla sözleşme ihlali vardı:
1. `std.crypto.tls.Client.reader` local değişkene kopyalanıyordu; vendored std içindeki `@fieldParentPtr("reader", r)` hesabı artık gerçek `Client` yerine stack kopyasına bakıyordu.
2. HTTP request plaintext’i TLS writer’a yazıldıktan sonra yalnızca buffer’da kalıyor, ciphertext TCP stream’e flush edilmiyordu; sunucu `HTTP/1.1 408 Request Time-out` döndürüyordu.
3. HTTP response parser `Content-Length` başlığını casing-duyarlı okuyordu ve body’yi `take(remaining)` ile tek hamlede tüketmeye çalışıyordu; bu da TLS reader buffer sözleşmesiyle çatışıyordu.
4. Bağlantı yolu sabit IP’ye kilitliydi; runtime’da hostname çözümlemesi kullanılmıyordu.

**Kök sebep:** Kök neden tek fonksiyonluk bir bug değil, stdlib I/O sözleşmelerinin ihlaliydi. `std.Io.net.Stream.Reader/Writer`, `std.crypto.tls.Client.reader/writer` ve `std.Io.Reader/Writer` buffer/flush/lifetime kuralları birlikte izlenmeden lokal hotfix’ler uygulandı.

**Kaynak:** `vendor/zig-std/std/crypto/tls/Client.zig` — embedded `reader`/`writer` alanları `@fieldParentPtr` ile gerçek `Client` adresine bağlı
**Kaynak:** `vendor/zig-std/std/Io/Writer.zig` — `flush` buffered veriyi sink’e itmek için zorunlu
**Kaynak:** `vendor/zig-std/std/Io/net.zig` — `Stream.Reader.init` / `Stream.Writer.init` stdlib I/O sözleşmesini sağlar
**Kaynak:** `vendor/zig-std/std/Io/net/HostName.zig` — `HostName.connect` runtime DNS çözümlemesi yapar

**Düzeltme:**
1. Bağlantı yolu `std.Io.Threaded` + `std.Io.net.HostName.connect` / `IpAddress.connect` tabanına taşındı.
2. `recvFullResponse` artık `&self.tls.reader` pointer’ı ile çalışıyor; embedded reader kopyalanmıyor.
3. `sendRaw` hem TLS writer’ı hem de alttaki `Stream.Writer`’ı flush ediyor.
4. Response header parse case-insensitive yapıldı ve body `peekGreedy(1)` + `toss()` ile parçalı okunuyor.
5. `DigistalloneClient.init` hata yolunda `http.deinit()` ile temiz kapanıyor.

---

## [2026-04-09] — Zig 0.16.0 Ağ API Drift'i Yanlış Namespace Seçimine Yol Açtı

**Tetikleyici:** `src/digistallone.zig` bağlantı katmanını standart kütüphane ile sadeleştirirken `std.net.Address.parseIp4` önerisinin yerel vendor std ile birebir uyuşmaması
**Dosyalar:** `src/digistallone.zig`
**Tip:** Build/runtime safety fix — aynı niyet, yanlış namespace seçilirse Zig 0.16.0 yerel kodla drift oluşuyor

---

### Hata: 0.16.0 yerel stdlib doğrulanmadan farklı namespace önerisi uygulanabilirdi

**Hata:** Görev niyeti doğruydu: manuel IPv4 parsing olmamalı, stdlib kullanılmalı. Ancak bu workspace'in vendor std kopyasında kanıtlanmış API `std.Io.net.IpAddress.parseIp4`. `std.net.Address.parseIp4` bu yerel ağaçta yok. Yerel kod doğrulanmadan kör namespace değişimi yapılsaydı gereksiz yeni compile/runtime hata riski doğacaktı.

**Kök Sebep:** Zig işleri için önce yerel 0.16.0 kaynak ağacını doğrulama kuralı atlanırsa, farklı Zig sürümlerindeki ağ API isimleri birbirine karışabiliyor.

**Kaynak:** `vendor/zig-std/std/Io/net.zig` — `pub fn parseIp4(text: []const u8, port: u16) Ip4Address.ParseError!IpAddress`

**Düzeltme:**
1. `resolveTcpTargetAddress` helper'ı eklendi
2. Helper içinde doğrulanmış yerel API `std.Io.net.IpAddress.parseIp4` kullanıldı
3. `HttpClient.init` doğrudan bu helper'dan aldığı adres ile `posix.socket` / `posix.connect` çağırıyor
4. Domain adı ile IP adresi ayrımı test ile kilitlendi: IPv4 kabul, domain reddi

**Tekrar olmaması için:**
- Zig ağ API'leri için önce yerel vendor std okunacak
- Sürüm belirtilmemiş stdlib önerileri doğrudan koda uygulanmayacak
- Socket adres çözümleme davranışı test ile korunacak

---

## [2026-04-09] — Manuel IPv4 Parsing Döngüsü TcpConnectFailed Hatasına Neden Oluyor

**Tetikleyici:** Module 3.2 — Digistallone HttpClient bağlantı aşamasında `TcpConnectFailed` hatası
**Dosyalar:** `src/digistallone.zig` (`HttpClient.init` fonksiyonu)
**Tip:** Runtime protocol/string parsing error — Manuel IP parsing döngüsü domain adını IP olarak parse etmeye çalışıyordu

---

### Hata: Manuel IPv4 parsing döngüsü domain adını IP olarak parse etmeye çalışıyordu

**Hata:** `HttpClient.init` içinde IP adresini parse etmek için manuel bir `while` döngüsü yazılmıştı.
Bu döngü string'i `.` karakterine göre split edip her parçayı `u8` olarak parse etmeye çalışıyordu.
Sorun:
1. Eğer `ip` parametresine domain adı (örn. "digistallone.com") geçirilirse, döngü `part_idx != 4` kontrolünde kalıyordu
2. Manuel parsing gereksiz karmaşıktı ve Zig stdlib'deki `std.net.Address.parseIp4` fonksiyonunu görmezden geliyordu
3. `posix.system.socket` ve `posix.system.connect` yerine düşük seviyeli syscall wrapper kullanılıyordu

**Kök Sebep:** AGENTS.md Section 2.1 (Manuel Offset Yasağı) ve Section 0 (Tahmin Yasağı) kurallarına aykırı olarak, standart kütüphane yerine manuel parsing implementasyonu yazılmıştı.

**Kaynak:** man 7 ip — IPv4 address format
**Kaynak:** man 2 socket — POSIX socket API
**Kaynak:** man 2 connect — TCP connect syscall
**Kaynak:** Zig stdlib — `std.net.Address.parseIp4`

**Düzeltme:**
1. Manuel IPv4 parsing döngüsü tamamen kaldırıldı
2. `std.net.Address.parseIp4(ip, port)` ile güvenli adres çözümlemesi kullanıldı
3. `posix.socket(addr.any.family, posix.SOCK.STREAM, posix.IPPROTO.TCP)` ile standart socket oluşturma
4. `posix.connect(sock, &addr.any, addr.getOsSockLen())` ile standart connect
5. `posix.system.close` yerine `posix.close` kullanıldı
6. SNI ayarı `.host = .{ .explicit = sni }` ile korundu (TLS için domain adı, socket için IP)

**Tekrar olmaması için:**
- Manuel string parsing yerine Zig stdlib fonksiyonları kullanılacak
- AGENTS.md Section 2.1: Ham byte/string işlemlerinde struct veya stdlib kullanılacak
- Socket işlemlerinde `posix.*` namespace'i kullanılacak, `posix.system.*` değil

---

## [2026-04-08] — Protokol İhlali ve Test Eksikliği
**Hata:** `extractAuthenticityToken`, `performRiskCheck` ve `buildGitHubPostHeaders` fonksiyonları eklendi ancak AGENTS.md içindeki Zorunlu Protokol kuralları (Kaynak belirtme, Assert katmanı, Test zorunluluğu, Network Stack farkındalığı) hiçe sayıldı.
**Kök sebep:** Kod yazılırken hız ve işlevsellik ön planda tutuldu, derleyici uzantısı rolü ve AGENTS.md içerisindeki [PROTOCOL: ABSOLUTE WIRE-TRUTH] kuralları göz ardı edildi.
**Kaynak:** AGENTS.md - Kural 1 (Kaynak Zorunluluğu), Kural 3 (Assert), Kural 5 (Round-Trip Test).
**Düzeltme:** 
1. Eksik olan tüm fonksiyonlara ilgili RFC / HTML yapısı kaynak (SOURCE) olarak eklenecek.
2. `buildGitHubPostHeaders` için `std.testing` bloğu (Round-Trip test) eklenecek.
3. `extractAuthenticityToken` için `std.testing` yazılacak ve Fuzz uyumlu hale getirilecek.
4. Network stack / raw socket kullanan `performRiskCheck` için UFW/iptables ve routing farkındalığı yorum olarak eklenecek.

---

## [2026-04-08] — Module 3.1: TLS 1.3 Certificate ve CertificateVerify Placeholder Bırakılmıştı

**Tetikleyici:** Native TLS 1.3 + HTTP/2 yolu canlı GitHub response alıyordu ama server authentication bloğu eksikti
**Dosyalar:** `src/network_core.zig`, `src/main.zig`
**Tip:** Runtime protocol/authentication error — Certificate chain doğrulaması ve CertificateVerify imza kontrolü yoktu

---

### Hata: Server auth bloğu sadece varlık kontrolü yapıyor, gerçek doğrulama yapmıyordu

**Hata:** Handshake akışı şu iki kritik boşluğu taşıyordu:
1. `Certificate` mesajı parse edilmeden transcript hash'e ekleniyor, certificate chain ve `github.com` hostname doğrulaması yapılmıyordu
2. `CertificateVerify` mesajı için yalnızca `saw_certificate_verify = true` set edilip log basılıyor, imza RFC 8446 transcript kurallarıyla hiç verify edilmiyordu
3. Canlı `main.zig` yolu `completeHandshakeFull` çağrısına `undefined` bir `std.Io` geçiriyordu; certificate bundle yükleme eklenince bu placeholder runtime crash'e dönüştü

**Kök Sebep:** TLS 1.3 state-machine, `EncryptedExtensions -> Certificate -> CertificateVerify -> Finished` authentication bloğunu gerçek güven zinciri olarak değil, sadece handshake ilerleme işareti olarak ele alıyordu. Ayrıca `CertificateVerify` için transcript update sırası RFC 8446 Section 4.4.3 ile uyumlu değildi: imza verify edilmeden mesaj hash'e katılabiliyordu.

**Kaynak:** RFC 8446, Section 4.4.2 — Certificate  
**Kaynak:** RFC 8446, Section 4.4.3 — CertificateVerify  
**Kaynak:** RFC 8446, Section 4.4.1 — Transcript Hash  
**Kaynak:** RFC 8446, Section 4.2.3 — Signature Algorithms  
**Kaynak:** RFC 5280, Section 6.1.3 — Certification Path Validation  
**Kaynak:** RFC 6125, Section 6.4.1 ve Section 6.4.3 — DNS-ID / wildcard hostname matching  
**Kaynak:** `vendor/zig-std/std/crypto/Certificate.zig` — DER parse, chain verify, hostname verify  
**Kaynak:** `vendor/zig-std/std/crypto/Certificate/Bundle.zig` — Linux trust store path discovery  
**Kaynak:** `vendor/zig-std/std/process.zig` — `std.process.Init.io` geçerli process I/O context'i

**Düzeltme:**
1. RFC 8446 `Certificate` message parser eklendi ve certificate_list içindeki DER sertifikalar parse edilmeye başlandı
2. Leaf certificate için `github.com` hostname doğrulaması ve ara sertifikalar üzerinden chain verification eklendi
3. Trust anchor doğrulaması Zig stdlib `Certificate.Bundle.rescan()` ile doğrulanmış Linux CA bundle path'leri üzerinden yapıldı
4. `CertificateVerify` imzası artık transcript hash üstünden, mesaj transcript'e eklenmeden önce verify ediliyor
5. TLS 1.3 için desteklenmeyen / teklif edilmemiş signature scheme'ler açık error ile reddediliyor
6. `main.zig` canlı yolunda `init.io` kullanılarak gerçek `std.Io` context'i geçiriliyor

**Tekrar olmaması için:**
- `Certificate` görüldü diye server authenticate olmuş sayılmayacak; chain + hostname doğrulaması olmadan Finished kabul edilmeyecek
- `CertificateVerify` mesajı transcript'e ancak imza başarıyla doğrulandıktan sonra eklenecek
- Live path'te `undefined` I/O/context placeholder bırakılmayacak

---

## [2026-04-08] — Module 3.1: HTTP/2 Bootstrap Öncesi TCP/TLS Katmanları Temiz Sanılıyordu

**Tetikleyici:** `Http2PrefaceFailed`, `TlsAeadDecryptFailed`, ardından canlı koşuda HTTP/2 SETTINGS/HEADERS aşamasına kadar ilerleme
**Dosyalar:** `src/network_core.zig`
**Tip:** Runtime protocol/state error — raw TCP tekrarları, post-handshake TLS mesajları ve kısmi HTTP/2 frame’ler aynı buffer’da yanlış katmanda ele alınıyordu

---

### Hata: HTTP/2 bootstrap yolu temiz bir frame akışı varsayıyordu

**Hata:** `receiveTlsApplicationData` ve `ensureHttp2ConnectionReady` şu yanlış varsayımları birlikte yapıyordu:
1. Gelen TCP payload her zaman yeni ve sıralı kabul ediliyordu
2. Decrypt edilen her TLS application record doğrudan HTTP/2 frame başlangıcı sanılıyordu
3. `inner_content_type = 0x16` post-handshake TLS mesajları (`NewSessionTicket`) HTTP/2 bytes gibi buffer’a ekleniyordu
4. Kısmi HTTP/2 frame fatal sanılıyor veya tam record başlangıcı kaybolunca parser sonsuza kadar yanlış uzunluk bekliyordu

**Kök Sebep:** Raw socket kullanırken kernel TCP stream reassembly yapmıyor. Bu yüzden tekrar gelen / örtüşen octet’leri uygulama ayıklamak zorunda. Üstüne TLS 1.3’te server, HTTP/2 SETTINGS’ten önce post-handshake `Handshake` içerikleri gönderebilir. Kod bu katmanları ayırmıyordu.

**Kaynak:** RFC 9293, Section 3.4 — TCP sequence numbers octet stream’i taşır  
**Kaynak:** RFC 9293, Section 3.10.7 — retransmission/duplicate octets yeniden gelebilir  
**Kaynak:** RFC 8446, Section 4.6 — NewSessionTicket post-handshake mesajıdır  
**Kaynak:** RFC 8446, Section 5.2 — TLSInnerPlaintext.content_type handshake/application_data ayrımını yapar  
**Kaynak:** RFC 9113, Section 4.1 — HTTP/2 frame header + length tam gelmeden frame parse edilemez

**Düzeltme:**
1. Inbound TCP payload için sequence-aware trimming eklendi; eski/örtüşen octet’ler decrypt’e sokulmuyor
2. Application receive yoluna explicit ACK gönderimi taşındı
3. `inner_content_type = 0x16` post-handshake mesajları HTTP/2 plaintext buffer’ına eklenmiyor
4. HTTP/2 server preface parse yolu kısmi frame’i “need more bytes” olarak ele alıyor
5. Handshake sonrası elde kalmış TLS ciphertext parçaları `pending_server_tls_ciphertext` ile HTTP/2 katmanına taşınıyor

**Tekrar olmaması için:**
- Raw socket üstünde “bir packet = yeni temiz stream verisi” varsayımı yapılmayacak
- TLS `inner_content_type` ayrımı yapılmadan plaintext üst katmana verilmeyecek
- HTTP/2 frame parse her zaman `9-byte header + declared length` tamamlanınca yapılacak

---

## [2026-04-08] — Module 3.1: HTTP/2 Response Yolu Hâlâ HTTP/1.1 Varsayımı ve Eksik Flow Control Taşıyordu

**Tetikleyici:** Bootstrap sonrası canlı koşuda `InvalidResponse`, ardından native parser sonrası `ReadTimeout`
**Dosyalar:** `src/http2_core.zig`, `src/network_core.zig`, `src/main.zig`, `src/hpack_tables.zig`
**Tip:** Runtime protocol/state error — response bytes gerçek HTTP/2 frame’lerdi ama parser hattı eksikti

---

### Hata: bootstrap düzeldiği halde response katmanı yanlış protokol ve eksik akış kontrolü kullanıyordu

**Hata:** TLS ve HTTP/2 preface/SETTINGS safhası başarılı olduktan sonra istemci:
1. decrypted HTTP/2 response bytes’ını `HttpResponse.parse()` ile HTTP/1.1 status-line bekleyerek açmaya çalışıyordu
2. HEADERS/DATA frame’lerini native olarak parse etmiyordu
3. HPACK header block decode etmediği için `:status`, `set-cookie`, `location` gibi alanları çıkaramıyordu
4. büyük response gövdelerinde `WINDOW_UPDATE` göndermediği için server bir noktadan sonra akışı durduruyordu
5. bir `receiveTlsApplicationData` çağrısından sonraki trailing kısmi TLS ciphertext’i sonraki çağrıya taşımadığı için record sınırları kayabiliyordu

**Kök Sebep:** HTTP/2 state-machine’in request tarafı düzeltilmişti ama response tarafı hâlâ “HTTP/1.1 metni gelecek” varsayımıyla bırakılmıştı. Ayrıca RFC 9113 stream/connection flow-control kuralları uygulanmamıştı.

**Kaynak:** RFC 9113, Section 6.1 — DATA frames stream payload taşır  
**Kaynak:** RFC 9113, Section 6.2 — HEADERS ve CONTINUATION ile field section taşınır  
**Kaynak:** RFC 9113, Section 6.9 — WINDOW_UPDATE connection ve stream flow-control penceresini büyütür  
**Kaynak:** RFC 7541, Section 3.2 — Header block sequential decode edilir  
**Kaynak:** RFC 7541, Appendix A — static table  
**Kaynak:** RFC 7541, Appendix B — Huffman code table

**Düzeltme:**
1. `http2_core.zig` içine native `HpackDecoder`, `Http2ResponseParser`, static table ve Huffman table eklendi
2. Response yolu artık HEADERS/CONTINUATION/DATA frame’lerini native HTTP/2 olarak parse ediyor
3. `:status` pseudo-header ve regular headers ayrıştırılıyor; `set-cookie`, `location`, body artık gerçek response alanlarından okunuyor
4. Büyük body transferlerinde hem connection hem stream için `WINDOW_UPDATE` gönderiliyor
5. `receiveTlsApplicationData` trailing kısmi TLS ciphertext’i sonraki çağrıya taşıyor
6. `main.zig` ve `network_core.zig` çağrı zinciri artık HTTP/1.1 parser yerine native HTTP/2 response tipini kullanıyor

**Tekrar olmaması için:**
- HTTP/2 response bytes hiçbir yerde HTTP/1.1 status-line parser’a verilmeyecek
- DATA tüketildikçe connection ve stream window büyütülecek
- HPACK decode olmadan `:status` ve header alanları var sayılmayacak
- trailing partial TLS record state’i çağrılar arasında korunacak

---

## [2026-04-08] — Module 3.1: HelloRetryRequest Yanlışlıkla Handshake Tamamlandı Sanılıyordu

**Tetikleyici:** HTTP/2 preface sonrası `TlsRecordTooShort` ve sahte `Session established` logu
**Dosyalar:** `src/network_core.zig`
**Tip:** Runtime protocol/state error — HelloRetryRequest final ServerHello sanıldı, placeholder TLS keys üretildi

---

### Hata: completeHandshakeFull HRR'yi final ServerHello sanıp sahte TlsSession döndürüyordu

**Hata:** İlk ClientHello'dan sonra gelen TLS mesajının `server_random` alanı
`cf21ad74e59a6111...` idi. Bu değer RFC 8446'ya göre final ServerHello değil,
HelloRetryRequest sabitidir. Kod bunu ayırt etmiyordu; üstüne bir de gerçek
RFC 8446 key schedule yerine `0xAA/0xBB/0xCC/0xDD` placeholder key/IV seti ile
`TlsSession` üretip handshake tamamlandı diyordu.

**Kök Sebep:** İki ayrı varsayım hatası vardı:
1. `msg_type == server_hello` ise bunun mutlaka final ServerHello olduğu varsayıldı
2. Shared secret, HKDF key schedule ve Finished doğrulaması olmadan application traffic keys varmış gibi davranıldı

**Kaynak:** RFC 8446, Section 4.1.3 — HelloRetryRequest special random value
**Kaynak:** RFC 8446, Section 4.4 — server Finished tamamlanmadan handshake bitmez
**Kaynak:** RFC 8446, Section 7 — key schedule required before application data keys exist

**Düzeltme:**
1. HRR random sabiti eklendi ve gelen `server_random` bu değere karşı doğrulanıyor
2. HRR görülürse `error.HelloRetryRequestUnsupported` ile fail-fast davranışı eklendi
3. Final ServerHello gelse bile gerçek key schedule uygulanmadıkça `error.TlsKeyScheduleUnimplemented` dönülüyor
4. Placeholder TLS key üretimi tamamen kaldırıldı

**Tekrar olmaması için:**
- `Session established` logu ancak gerçek Finished + key schedule sonrası üretilebilir
- `server_hello` msg_type tek başına “handshake complete” anlamına gelmez
- RFC 8446 Section 7 uygulanmadan hiçbir HTTP/2/TLS application data gönderilmemeli

---

## [2026-04-08] — Module 3.1: HTTP/2 HEADERS Preface Olmadan Gönderiliyordu

**Tetikleyici:** GitHub signup GET isteği `ReadTimeout` ile düşüyordu
**Dosyalar:** `src/network_core.zig`
**Tip:** Runtime protocol error — TLS handshake sonrası doğrudan HTTP/2 HEADERS gönderiliyordu

---

### Hata: performGet connection preface ve initial SETTINGS olmadan request başlatıyordu

**Hata:** `performGet` TLS session kurulunca ilk application-data kaydı olarak doğrudan
HTTP/2 HEADERS frame gönderiyordu. Client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`)
ve onu izleyen zorunlu SETTINGS frame hiç gönderilmiyordu.

**Kök Sebep:** HTTP/2 connection state machine eksikti. `src/http2_core.zig` içinde
preface ve SETTINGS builder'ları olmasına rağmen `src/network_core.zig` bunları request akışına
bağlamıyordu. Sonuç olarak peer, ilk HEADERS frame'ini geçerli bir HTTP/2 oturumu olarak kabul etmiyordu.

**Kaynak:** RFC 9113, Section 3.4 — client connection preface
**Kaynak:** RFC 9113, Section 6.5 — SETTINGS frame connection başlangıcında zorunlu
**Kaynak:** RFC 9113, Section 6.5.3 — recipient MUST immediately emit SETTINGS ACK

**Düzeltme:**
1. `GitHubHttpClient.ensureHttp2ConnectionReady()` eklendi
2. Akış `Preface -> empty SETTINGS -> server SETTINGS wait -> SETTINGS ACK -> GET HEADERS` olarak düzeltildi
3. Server SETTINGS gelmezse `error.Http2PrefaceFailed` ile fail-fast davranışı eklendi
4. GET request stream ID yönetimi `next_stream_id` ile odd-numbered olacak şekilde stateful hale getirildi
5. Raw inbound packet içinden gerçek TCP payload çıkarılıp TLS record oradan okunacak yardımcılar eklendi

**Tekrar olmaması için:**
- İlk request'ten önce `inspectHttp2ServerPreface` testleri çalışmalı
- `performGet` içine yeni frame eklenirse bootstrap sırası korunmalı
- Aynı TCP/TLS oturumunda preface yalnızca bir kez gönderilmeli

---

## [2026-04-08] — Module 3.1: ServerHello Cipher Suite Offset Hatası (0x0000)

**Tetikleyici:** Module 3.1 — Identity Forgery & BDA Synthesis, TLS 1.3 cipher suite extraction
**Dosyalar:** `src/network_core.zig` (completeHandshakeFull fonksiyonu)
**Tip:** Runtime hatası — "Cipher suite: 0x0000" logu görüldü, TLS 1.3 için imkansız

---

### Hata: completeHandshakeFull yanlış offset ile cipher suite'u 0x0000 olarak okuyordu

**Hata:** `completeHandshakeFull` içinde ServerHello parsing yapılırken cipher suite offset'i yanlış hesaplandı.
Log'da "Cipher suite: 0x0000" görünüyordu ki bu TLS 1.3 için imkansız (geçerli değerler: 0x1301-0x1305).

**Kök Sebep:** TLS wire format katmanları yanlış hesaplandı:
- TLS Record Header: 5 bytes (`payload[0..5]`)
- Handshake Header: 4 bytes (`payload[5..9]`)
- ServerHello Body: `payload[9..]`

Eski kod `payload[6..]` kullanıyordu, yani handshake header'ın son byte'ını ServerHello body'nin ilk byte'ı olarak okuyordu.
Bu tüm offset kaymasını yarattı ve cipher suite 0x0000 olarak döndü.

**Yanlış Kod:**
```zig
const sh_body = payload[6..]; // After TLS record header ← YANLIŞ!
// sh_body[0] aslında handshake header'ın msg_type byte'ı (0x02)
```

**Doğru Kod:**
```zig
const sh_body = payload[9..]; // Skip TLS record header (5) + handshake header (4) ← DOĞRU
// sh_body[0] artık legacy_version byte'ı (0x03)
```

**Kaynak:** RFC 8446, Section 5.1 — TLSPlaintext structure (5 byte record header)
**Kaynak:** RFC 8446, Section 4 — Handshake protocol (4 byte handshake header)
**Kaynak:** RFC 8446, Section 4.1.3 — ServerHello structure (legacy_version offset = 0)

**Düzeltme:**
1. `payload[6..]` → `payload[9..]` olarak düzeltildi
2. ServerHello body minimum boyut kontrolü: `sh_body.len >= 35` (version(2) + random(32) + sid_len(1))
3. Cipher suite extraction: `cs_offset = 35 + sid_len`
4. Hata durumunda detaylı log: "ServerHello too short for cipher suite"

**Eklenen Belgeler:**
- `// SOURCE:` yorumları her offset için RFC referansları eklendi
- Comptime assert: `MIN_SERVERHELLO_LEN == 46` (minimum ServerHello boyutu)
- TLS 1.3 cipher suite doğrulama: 0x1301-0x1305 arası geçerli

**Tekrar olmaması için:**
- AGENTS.md Section 2.1: Ham byte offset kullanımı yasaktır
- Tüm offsetler `packed struct` veya dinamik hesaplamadan türetilir
- Her TLS parsing fonksiyonu için RFC referanslı offset constant'ları kullanılmalıdır

---

## [2026-04-08] — Module 3.1: Engine Shutdown Before Payload Execution

**Tetikleyici:** Module 3.1 execution — HTTP GET request gönderilmeden engine kapanıyordu
**Dosyalar:** `src/main.zig`, `src/network_core.zig`
**Tip:** Runtime logic error — handshake tamamlandıktan sonra performGet çağrılmıyordu

---

### Hata: main.zig handshake'den sonra shutdown'a geçiyordu, performGet hiç çağrılmıyordu

**Hata:** `main.zig` içinde handshake tamamlandıktan sonra HTTP/2 frame hazırlanıp log'lanıyordu ama
**gerçek request gönderilmiyordu**. Engine direkt shutdown'a geçiyordu.

**Kök Sebep:** Execution flow eksikti:
```zig
// ÖNCEKİ (YANLIŞ):
const handshake = try network.completeHandshakeFull(...);
// ... HPACK frame hazırla ...
const github_client = network.GitHubHttpClient.initFromHandshake(...);
// Log'lar göster ...
// SHUTDOWN — performGet hiç çağrılmadı!
```

**Doğru Kod:**
```zig
const response = try github_client.performGet(allocator, "https://github.com/signup");
defer allocator.free(response);
// Parse ve display decrypted HTML response
```

**Ek Düzeltmeler:**

1. **Command Line Simplification:**
   - Önceki: `sudo ./ghost_engine <interface> <dest_ip> <dest_port>`
   - Yeni: `sudo ./ghost_engine <interface>` (hedef GitHub hardcoded)

2. **Zig 0.16 API Uyumluluk:**
   - `posix.write(fd, buf)` → `std.os.linux.write(fd, buf.ptr, buf.len)`
   - `posix.read(fd, buf)` → `std.os.linux.read(fd, buf.ptr, buf.len)`
   - `posix.read` error union dönmüyordu, errno check eklendi (EAGAIN = -11)

3. **HttpResponse Field Names:**
   - `status_text` → `reason_phrase`
   - `headers` → `headers_start`

4. **Visibility Fixes:**
   - `performGet` fonksiyonu `pub fn` yapıldı (main.zig'den erişim için)

**Kaynak:** RFC 7540, Section 3.2 — Starting HTTP/2 with Prior Knowledge
**Kaynak:** man 2 read/write — POSIX syscall semantics

**Düzeltme:**
- `main.zig` execution flow'a `performGet` → `decryptRecord` → HTML display eklendi
- Command line argument parsing simplified (sadece interface name)
- Tüm Zig 0.16 API uyumsuzlukları düzeltildi

**Beklenen Çıktı:**
```
[MODULE 3.1] Handshake complete! Cipher suite: 0x1301
[HTTP/2] Requesting: https://github.com/signup
[RESPONSE] Status: 200 OK
[HTML BODY - First 1000 bytes]:
<!DOCTYPE html>...
```

---

## [2026-04-08] — Module 3.3: HTTP Cookie Parsing & Redirect Loop Bug

**Tetikleyici:** Module 3.3 — Onboarding Bypass & Session Persistence implementasyonu
**Dosyalar:** `src/network_core.zig`
**Tip:** Proaktif — runtime hatası görülmeden, test aşamasında tespit edildi

---

### Hata: extractCookies ikinci header'ı görmüyordu

**Hata:** `extractCookies` fonksiyonu headers parsing loop'unda sadece ilk header'ı okuyordu.
İkinci header (`Set-Cookie`) parse edilmiyordu, `user_session_len = 0` kalıyordu.

**Kök Sebep:** Loop içinde `while (headers.len > 0)` koşulu vardı ama `mem.indexOf(u8, headers, "\r\n")`
son header'dan sonra `\r\n` bulamadığı için `null` dönüyordu. Eski kod:

```zig
// ÖNCEKİ (YANLIŞ):
while (headers.len > 0) {
    const crlf = mem.indexOf(u8, headers, "\r\n") orelse break; // ← BURADA break!
    const header_line = headers[0..crlf];
    // ... process header ...
    headers = headers[crlf + 2 ..];
}
```

Son header'dan sonra `\r\n` olmadığı için loop break ediyordu.

**Çözüm:** Optional handling ile son header'ı da işle:

```zig
// SONRAKİ (DOĞRU):
while (headers.len > 0) {
    const crlf = mem.indexOf(u8, headers, "\r\n");
    const header_line = if (crlf) |pos| headers[0..pos] else headers; // ← Son header'ı al
    
    // ... process header ...
    
    if (crlf) |pos| {
        headers = headers[pos + 2 ..];
    } else {
        break; // ← Son header işlendi, çık
    }
}
```

**Ders:** Header parsing loop'larında son satırın `\r\n` ile bitmeyeceğini hesaba kat.
Optional pattern matching ile hem `\r\n` olan hem olmayan durumları handle et.

---

### Eklenen API'ler

| Fonksiyon | Amaç |
|---|---|
| `GitHubCookieJar.setCookie()` | Set-Cookie header parsing (RFC 6265) |
| `GitHubCookieJar.cookieHeader()` | Cookie header oluşturma (RFC 6265 Section 4.2) |
| `HttpResponse.parse()` | HTTP response parsing (RFC 7230) |
| `HttpResponse.extractCookies()` | Set-Cookie extraction (case-insensitive) |
| `HttpResponse.locationHeader()` | Location header extraction (RFC 7231) |
| `HttpResponse.hasLoggedInClass()` | Dashboard session validation |
| `HttpResponse.extractUserLogin()` | Meta tag username extraction |
| `GitHubHttpClient.followRedirectsUntil()` | Redirect following with jitter |
| `GitHubHttpClient.validateSessionState()` | Session validation |
| `GitHubHttpClient.resolveUrl()` | Relative → Absolute URL resolution |

### Doğrulama

```
✅ vendor/zig/zig test src/network_core.zig → 56/56 test geçti
✅ vendor/zig/zig build test → 84/84 test geçti (56 + 28 http2_core)
```

### Kaynaklar

- RFC 7230, Section 3 - HTTP Message Format
- RFC 7231, Section 6.4.2 - 302 Found (Redirect)
- RFC 6265, Section 5.2 - Set-Cookie
- RFC 6265bis, Section 4.1.3 - __Host- Cookie Prefix

---

*Son güncelleme: 2026-04-08*
*Güncelleyen: Module 3.3 implementasyonu*
*Tetikleyen: Onboarding Bypass & Session Persistence geliştirme*

---

## [2026-04-08] — Module 3.2: std.crypto.tls.Client lifetime + std.Io API uyumluluğu

**Tetikleyici:** Module 3.2 — Autonomous Mailbox Controller & Code Extractor implementasyonu
**Dosyalar:** `src/digistallone.zig`, `build.zig`
**Tip:** Proaktif — Zig 0.16.0-dev.3135 API değişiklikleri ve lifetime yönetimi

---

### Hata 1: `std.crypto.tls.Client` local değişken olarak oluşturulup pointer'ı return ediliyordu

**Hata:** `HttpClient.init()` içinde `const tls_client = crypto.tls.Client.init(...)` local
değişken olarak tanımlanıp `return .{ .tls = &tls_client }` ile pointer return ediliyordu.
Fonksiyon return ettikten sonra `tls_client` stack'ten silinir → use-after-free (UB).

**Kök Sebep:** Zig'de fonksiyon scope'unda tanımlanan değişkenler fonksiyon return ettiğinde
geçersiz olur. Pointer'ları heap'te allocate edilmeli.

**Kaynak:** Zig memory semantics — stack allocation is function-scoped.

**Düzeltme:**
```zig
// ÖNCEKİ (YANLIŞ):
const tls_client = crypto.tls.Client.init(...) catch return error.TlsHandshakeFailed;
return .{ .tls = &tls_client };

// SONRAKİ (DOĞRU):
const tls_ptr = try allocator.create(crypto.tls.Client);
tls_ptr.* = crypto.tls.Client.init(...) catch {
    allocator.destroy(tls_ptr);
    return error.TlsHandshakeFailed;
};
return .{ .tls = tls_ptr };
```

---

### Hata 2: `std.Io.net.Stream.Reader/Writer` interface pointer lifetime

**Hata:** `tls.Client.init()` `*Reader` ve `*Writer` pointer'larını kabul eder ve bunları
internal olarak saklar. Eğer Reader/Writer local değişken ise, TLS handshake sonrası
bu pointer'lar dangling olur.

**Kök Sebep:** `std.crypto.tls.Client` struct'ı:
```zig
input: *Reader,   // pointer to encrypted reader interface
output: *Writer,  // pointer to encrypted writer interface
```
Bu pointer'lar, `init` çağrısından sonra da geçerli olmalı.

**Çözüm:** Reader ve Writer'ı da heap'te allocate et ve HttpClient struct'ında sakla:
```zig
const reader_ptr = try allocator.create(std.Io.net.Stream.Reader);
const writer_ptr = try allocator.create(std.Io.net.Stream.Writer);
reader_ptr.* = std.Io.net.Stream.Reader.init(stream, io, reader_buf);
writer_ptr.* = std.Io.net.Stream.Writer.init(stream, io, writer_buf);

tls_ptr.* = crypto.tls.Client.init(
    &reader_ptr.*.interface,
    &writer_ptr.*.interface,
    ...
);

return .{
    .tls = tls_ptr,
    .reader_ptr = reader_ptr,  // lifetime managed
    .writer_ptr = writer_ptr,  // lifetime managed
};
```

---

### Hata 3: `std.io.fixedBufferStream` Zig 0.16'da yok

**Hata:** `std.io.fixedBufferStream(buf)` kullanıldı. Zig 0.16'da `std.io` modülü
kaldırılmış, yerine `std.Io` gelmiş. Ama `std.Io`'da `fixedBufferStream` eşdeğeri yok.

**Kaynak:** Zig 0.16 stdlib değişiklikleri — `std.io` → `std.Io` (büyük harf)

**Çözüm:** Manuel byte-offset ile buffer yazma:
```zig
var pos: usize = 0;
const prefix = "XSRF-TOKEN=";
@memcpy(buf[0..prefix.len], prefix);
pos += prefix.len;
@memcpy(buf[pos .. pos + self.xsrf_token_len], self.xsrf_token[0..self.xsrf_token_len]);
pos += self.xsrf_token_len;
```

---

### Eklenen API'ler

| Fonksiyon | Amaç |
|---|---|
| `DigistalloneClient.init()` | TLS handshake + CSRF token extraction |
| `getNewEmailAddress()` | Yeni email oluştur (domain rotation) |
| `pollInboxForGitHubCode()` | Inbox polling + 6-digit code extraction |
| `extractGitHubCode()` | Regex-free 6-digit code pattern matching |
| `CookieJar.setCookie()` | Set-Cookie header parsing |
| `LivewireClient.createEmail()` | Livewire form submit |
| `LivewireClient.pollInbox()` | fetchMessages dispatch |

### Doğrulama

```
✅ vendor/zig/zig test src/digistallone.zig → 6/6 test geçti
✅ vendor/zig/zig build test → 82/82 test geçti (48+28+6)
```

---

*Son güncelleme: 2026-04-08*
*Güncelleyen: Module 3.2 implementasyonu*
*Tetikleyen: Digistallone mailbox controller geliştirme*

---

## [2026-04-07] — Zig 0.16 packed struct + [N]u8 + @bitCast uyumsuzluğu

**Tetikleyici:** Module 2.1 — TLS 1.3 Server Response Parser implementasyonu
**Dosyalar:** `src/network_core.zig`
**Tip:** Proaktif — runtime hatası görülmeden, derleyici hataları sırasında tespit edildi

---

### Hata: Zig 0.16'da `packed struct` içinde `[N]u8` array field desteklenmiyor

**Hata:** `TlsServerHelloFixed` packed struct'ı içinde `random: [32]u8` field'ı tanımlandı.
Zig 0.16 derleyicisi: `error: packed structs cannot contain fields of type '[32]u8'`

**Ayrıca:** `@bitCast` ile `[5]u8` → `TlsRecordHeader` dönüşümü size mismatch hatası verdi.
`@sizeOf(TlsRecordHeader)` comptime assert'te beklenen 5 yerine farklı değer döndü.

**Ayrıca:** `std.mem.readInt(u16, slice[start..end], .big)` Zig 0.16'da `*const [2]u8` bekliyor,
slice değil. Slice üzerinde `.*` ile `[2]u8` value elde ediliyor ama bu da `[N]u8`'den
`*const [N]u8`'e implicit cast ile uyumsuz.

**Kök Sebep:** Zig 0.16'nın packed struct ve @bitCast semantics'i, array field'ları ve
slice-to-array dönüşümlerini desteklemiyor.

**Kaynak:** Zig 0.16 language semantics — packed struct only supports integer types,
bool, enum, and other packed structs. Arrays are not bit-packable.

**Düzeltme:**
```zig
// ÖNCEKİ: packed struct + @bitCast yaklaşımı
pub const TlsRecordHeader = packed struct {
    content_type: u8,
    legacy_version: u16,
    length: u16,
};
const header: TlsRecordHeader = @bitCast(buffer[0..5].*);

// SONRAKİ: Explicit const offset + manual big-endian read
pub const TLS_REC_CONTENT_TYPE: usize = 0;
pub const TLS_REC_VERSION: usize = 1;
pub const TLS_REC_LENGTH: usize = 3;
pub const TLS_REC_HEADER_LEN: usize = 5;

const record_type = buffer[TLS_REC_CONTENT_TYPE];
const legacy_version: u16 = (@as(u16, buffer[1]) << 8) | @as(u16, buffer[2]);
```

**Ders:** Zig 0.16'da protokol parsing için packed struct + @bitCast yerine
explicit offset constants + manual byte assembly kullan. Her offset için
comptime assert ile boyut doğrulaması yap.

---

---

## [2026-04-07] — UFW INPUT DROP + ECH decode_error: 20 Saatlik Kör Nokta

**Commit:** `2fed10e51e8c4959767e3730decdb341f4da3229`
**Dosya:** `src/network_core.zig`
**Süre:** ~20 saat, 65+ deneme, birden fazla model

---

### Semptomlar

```
[FAILURE] Surgical SYN-ACK filter: Not captured
[INFO] Validated inbound packets logged: 0
[SUCCESS] Raw socket transmission: 1 packet(s) sent
[OVERALL FAILURE] Verification failed
```

SYN gidiyordu. SYN-ACK hiç gelmiyordu. Timeout. Tekrar. Tekrar.

---

### Hata 1: UFW INPUT Chain Raw Socket'i Öldürüyordu

#### Linux Netfilter Paket Akışı

```
NIC
 │
 ▼
AF_PACKET hook  ← tcpdump BURADA çalışır (iptables ÖNCESİ)
 │
 ▼
PREROUTING chain (iptables)
 │
 ▼
Routing kararı
 │
 ▼
INPUT chain (iptables) ← UFW BURADA çalışır
 │
 ▼
Socket delivery ← SOCK_RAW BURADA paket alır
```

`tcpdump` iptables'ı bypass eder. `SOCK_RAW` etmez.
UFW INPUT zinciri paketi DROP ederse raw socket hiçbir zaman görmez.

#### Ne Oldu

1. SYN, `NOTRACK` ile gönderildi → conntrack kayıt etmedi
2. Cloudflare SYN-ACK gönderdi
3. Conntrack: eşleşen SYN yok → paketi `INVALID` işaretledi
4. UFW: `ctstate INVALID -j DROP` → **paket yok edildi**
5. Raw socket: sıfır paket aldı

#### Kanıt (Bu İki Komutu Birlikte Çalıştır)

```bash
# Terminal 1 — iptables ÖNCESİ:
sudo tcpdump -i any -n 'tcp and src host 1.1.1.1 and tcp[13] == 18' -c 3
# Çıktı: SYN-ACK GÖRÜNDฺÜ → ağ OK

# Terminal 2 — engine:
sudo ./zig-out/bin/ghost_engine 1.1.1.1 443
# Çıktı: INBOUND PACKET = 0 → INPUT chain kesiyordu
```

Fark = iptables INPUT zinciri. 1 dakikada teşhis edilebilirdi.

#### Çözüm

```zig
// applyRstSuppression içine eklendi:

// Inbound SYN-ACK conntrack INVALID olmasın:
"iptables -t raw -A PREROUTING -p tcp --dport {port} -j NOTRACK"

// UFW DEFAULT DROP policy'sini bypass et:
"iptables -I INPUT -p tcp --sport 443 --dport {port} -j ACCEPT"
```

`removeRstSuppression` ve `signalHandler` içine `-D` ile temizleme eklendi.

---

### Hata 2: ECH Payload Type Byte'ı Yanlıştı → decode_error

SYN-ACK yakalanmaya başlayınca yeni hata:

```
[TLS ALERT] Level=2 Code=0x32 (decode_error)
[FATAL] TLS Fatal Alert - connection will be closed
```

#### Yanlış Anlama: 0xFE0D GREASE Değildi

GREASE extension tipleri (RFC 8701) şu pattern'i takip eder: `0xXAXA`

```
0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, ... 0xFAFA
```

`0xFE0D` bu pattern'e UYMAZ. IANA'nın ECH'e atadığı **gerçek** extension tipidir.
Cloudflare 1.1.1.1 ECH implement eder. `0xFE0D` görünce strict parse eder.

#### Yanlış Kod

```zig
ech_grease_payload[0] = 0x0D; // ← GEÇERSİZ! 0=inner veya 1=outer olmalı
ech_grease_payload[1] = 0x00;
ech_grease_payload[2] = 0xFE;
ech_grease_payload[3] = 0x0D;
```

ECH wire formatı (draft-ietf-tls-esni):

```
struct ECHClientHello {
    uint8 type;                          // 0=inner, 1=outer
    uint16 kdf_id;                       // HPKE KDF
    uint16 aead_id;                      // HPKE AEAD
    uint8 config_id;
    opaque enc<0..2^16-1>;              // 2-byte len + bytes
    opaque payload<1..2^16-1>;          // 2-byte len + bytes
}
```

`type = 0x0D` → parse edilemiyor → `decode_error` (50).

#### Doğru Kod (11 byte, ech_grease_payload_len = 11)

```zig
ech_grease_payload[0]  = 0x01;            // type = outer
ech_grease_payload[1]  = 0x00;            // KDF id high
ech_grease_payload[2]  = 0x01;            // KDF id low  (HKDF-SHA256)
ech_grease_payload[3]  = 0x00;            // AEAD id high
ech_grease_payload[4]  = 0x01;            // AEAD id low (AES-128-GCM)
ech_grease_payload[5]  = ech_random[0];   // config_id (rastgele)
ech_grease_payload[6]  = 0x00;            // enc length high
ech_grease_payload[7]  = 0x00;            // enc length low (empty enc)
ech_grease_payload[8]  = 0x00;            // payload length high
ech_grease_payload[9]  = 0x01;            // payload length low (1 byte)
ech_grease_payload[10] = ech_random[1];   // payload byte (rastgele)
```

---

### Neden 20 Saat Sürdü

#### 4.1 Ölçüm Yoktu, Tahmin Vardı

20 saatin tamamında elimizdeki tek veri: `INBOUND PACKET = 0`

Bu çıktıdan BPF filter, byte order, checksum, socket binding, conntrack gibi
düzinelerce hipotez üretildi ve hepsi koda bakılarak test edildi.

Oysa şu iki komut 1 DAKIKADA sorunu lokalize ederdi:

```bash
# Paralel çalıştır:
sudo tcpdump -i any -n 'tcp and src host 1.1.1.1 and tcp[13]==18' -c 3
sudo ./zig-out/bin/ghost_engine 1.1.1.1 443
```

tcpdump = SYN-ACK görür → ağ OK
engine = SYN-ACK görmez → INPUT chain problemi

**Ders:** Ölçüm > Tahmin. Her zaman.

#### 4.2 Yanlış Katmanda Arama

Sorun kodda değil sistem konfigürasyonundaydı.
20 saat `network_core.zig` satırları incelendi:
- BPF filter opcode'ları
- TCP checksum pseudo-header
- Byte order dönüşümleri
- SO_RCVTIMEO davranışı

Hiçbiri sorun değildi. Sorun UFW'un varsayılan DROP policy'siydi.

#### 4.3 Katmanlı Hata Bağımlılığı

```
INPUT ACCEPT → SYN-ACK alınır
    → TCP handshake tamamlanır
        → TLS Hello gönderilir
            → ECH decode_error görünür
```

Katman 1 çözülmeden Katman 2 gözlemlenemez.
20 saat boyunca Katman 1'den çıkılamadı, Katman 2'nin varlığı bilinmiyordu.

#### 4.4 UFW Çıktısı Okundu Ama Yorumlanmadı

```
Chain INPUT (policy DROP)
DROP  ctstate INVALID
```

Bu görüldüğünde "PREROUTING NOTRACK ekleyeyim, INVALID olmasın" denildi.
Ama INVALID olmasa bile `policy DROP` hâlâ geçerliydi.
Açık `ACCEPT` kuralı olmadan hiçbir paket socket'e ulaşamazdı.

**Doğru mantık:**

```
INPUT policy = DROP
→ Açık ACCEPT kuralı olmadan hiçbir paket geçmez
→ Ephemeral port için: iptables -I INPUT -p tcp --sport 443 --dport PORT -j ACCEPT
```

---

### Yapay Zekaların Neden Tespit Edemediği

#### Sistemi Gözlemleyemiyorlar

Modeller kodu okur, analiz eder. Ancak:
- UFW kurulu mu bilmiyorlar
- INPUT policy nedir bilmiyorlar
- tcpdump çalıştıramıyorlar (onay gerekiyor)

Sistemin gerçek zamanlı durumunu gözlemlemeden sadece kod analizi yaparak
bu tür sistem konfigürasyon hatalarını bulmak mümkün değil.

#### "Genellikle böyle çalışır" Yanılgısı

Doğruları söylüyorlar ama bağlamı eksik:

| Model'in söylediği | Gerçek |
|---|---|
| "SOCK_RAW tüm TCP paketleri alır" | Doğru ama INPUT chain geçerlerse |
| "PREROUTING NOTRACK yeterli" | Kısmen doğru ama INPUT ACCEPT ayrı gerekir |
| "conntrack bypass eder" | Doğru ama socket delivery için farklı path |

Eğitim verisi çoğunlukla UFW olmayan veya permissive policy'li sistemler içeriyordu.

#### Hipotez Üretimi Derinlemesine, Doğrulama Yüzeysel

Her hipotez için kod analizi yapıldı. Hiçbiri için:
- "Önce tcpdump ile paketin interface'e gelip gelmediğini kontrol edin" denmedi
- "iptables tüm chain'lerini gösterin" denmedi

Hipotez üretme konusunda başarılı, empirik doğrulama konusunda başarısız.

---

### Doğru Teşhis Protokolü (Raw Socket Paket Almıyor İçin)

```
1. SYN gönderildi mi?
   → Hex dump çıktısında "RAW HEX DUMP BEFORE SEND" var mı?

2. SYN-ACK interface'e ulaşıyor mu? (PARALEL ÇALIŞTIR)
   Terminal A: sudo tcpdump -i any -n 'tcp and src HOST and tcp[13]==18' -c 3
   Terminal B: sudo ./engine TARGET PORT
   → A görüyor, B görmüyor → kernel/iptables sorunu
   → A da görmüyor → ağ seviyesi sorun

3. iptables INPUT chain kontrol et
   sudo iptables -L INPUT -n
   → Default policy DROP mu?
   → ctstate INVALID DROP var mı?
   → FIX: iptables -I INPUT -p tcp --sport SERVER_PORT --dport EPHEMERAL -j ACCEPT

4. conntrack durumu
   sudo iptables -t raw -L PREROUTING -n
   → FIX: iptables -t raw -A PREROUTING -p tcp --dport EPHEMERAL -j NOTRACK

5. ANCAK BUNDAN SONRA koda bak
   → BPF filter, checksum, byte order, TLS format
```

**Kural:** Sistem gözlemi kod analizinden önce gelir.

---

### Değişiklik Özeti

| Konum | Değişiklik |
|---|---|
| `applyRstSuppression` | PREROUTING NOTRACK + INPUT ACCEPT eklendi |
| `removeRstSuppression` | Her ikisinin temizlenmesi eklendi |
| `signalHandler` | Her ikisinin temizlenmesi eklendi |
| ECH payload | `type=0x0D` → `type=0x01`, doğru ECHClientHello outer formatı |
| `verify.sh` | `sudo -v 2>/dev/tty` eklendi |

---

### Referanslar

- RFC 8701 — GREASE extension type pattern: https://www.rfc-editor.org/rfc/rfc8701
- ECH wire format — draft-ietf-tls-esni: https://www.ietf.org/archive/id/draft-ietf-tls-esni-17.txt
- Linux netfilter hooks: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/netfilter.h
- man 7 packet — AF_PACKET iptables bypass: https://man7.org/linux/man-pages/man7/packet.7.html
- man 7 raw — SOCK_RAW INPUT chain dependency: https://man7.org/linux/man-pages/man7/raw.7.html

---

## [2026-04-07] — Vendor Zig 3132 → 3135 geçiş ve API uyumluluk doğrulaması

**Tetikleyici:** Sistemin en güncel Zig 0.16.0-dev.3135'e sabitleme ihtiyacı
**Dosyalar:** `vendor/zig/zig`, `vendor/zig/zig-real`, `vendor/zig-std/`
**Önceki:** 0.16.0-dev.3132+fd2718f82 → **Yeni:** 0.16.0-dev.3135+a38c6bbcc

---

### API Uyumluluk Analizi

| API | 3132 → 3135 | Durum |
|---|---|---|
| `std.Io.net.IpAddress.parse(text, port)` | Değişmedi | ✅ |
| `std.Io.Event` (.unset, .set(), .wait()) | Değişmedi | ✅ |
| `std.Io.Clock.boot.now(io)` | Değişmedi | ✅ |
| `std.Io.Threaded.init(alloc, .{})` | Değişmedi | ✅ |
| `std.os.linux.getrandom(buf, count, flags)` | Değişmedi | ✅ |
| `std.os.linux.sigaction` | Değişmedi | ✅ |
| `std.os.linux.nanosleep` | Değişmedi | ✅ |
| `std.posix.timeval` | Değişmedi | ✅ |
| `std.posix.{SOL,SO}.RCVTIMEO` | Değişmedi | ✅ |

### Breaking Change: YOK

3132 → 3135 arası kodu etkileyen **hiçbir breaking change yok**.
3135'teki değişiklikler: std.Io.zig'e 961 satır ekleme (yeni özellikler, mevcut API'ler bozulmadı).

### Doğrulama

```
✅ vendor/zig/zig build        → exit code 0
✅ vendor/zig/zig build test   → 17/17 test geçti
```

### Stabilite Avantajları (3135)

- std.Io modülünde Threaded I/O iyileştirmeleri
- Tip çözümleme (type resolution) düzeltmeleri — comptime hataları azaldı
- std.Build modülünde RunStep exit code handling iyileştirildi

---

*Son güncelleme: 2026-04-07*
*Güncelleyen: void0x14*
*Tetikleyen: 3132 → 3135 vendor lock geçiş talebi*

---

## [2026-04-07] — `zig build test` "failed command" (Zig 0.16-dev uyumluluk)

**Tetikleyici:** Red Team Audit sonrası `zig build test` "failed command" hatası
**Dosyalar:** `build.zig`
**Zig Versiyonu:** 0.16.0-dev.3135

---

### Hata: Test runner --listen=- ile donuyor, exit code yanlış algılanıyor

**Hata:** `b.addRunArtifact(test_exe)` ile test binary'si çalıştırıldığında Zig 0.16-dev
`--listen=-` flag'i enjekte ediyor. Bu flag test runner'ın stdin/stdout üzerinden
IPC yapmasını bekliyor. Ancak bu modda test runner **donuyor** (hang).

Dolaylı olarak `zig test` doğrudan çalıştırıldığında exit code 0 dönüyor ama
`addSystemCommand` + `expectExitCode(0)` kombinasyonu da Zig 0.16-dev'de
"failed command" mesajı üretiyor.

**Kök Sebep:** Zig 0.16-dev'de `RunStep`'in test binary handling'ı değişmiş.
`--listen=-` IPC protokolü test binary'leri ile düzgün çalışmıyor.

**Düzeltme:**
```zig
// ÖNCEKİ: b.addRunArtifact(test_exe) -- donuyor
const test_run = b.addRunArtifact(test_exe);

// SONRAKİ: zig test doğrudan system command olarak çalıştır
const test_run = b.addSystemCommand(&.{
    "zig", "test", "src/network_core.zig",
    "--zig-lib-dir", "vendor/zig-std", "-lc",
});
test_run.has_side_effects = true;  // Exit code 0 olduğunda step başarılı sayılır
```

---

*Son güncelleme: 2026-04-07*
*Güncelleyen: Red Team Audit + void0x14*
*Tetikleyen: Column A statik audit sonrası build test fix*

---

## [2026-04-07] — Red Team Audit: RST Cleanup Bypass + MTU 5-Byte Hesaplama Hatası

**Tetikleyici:** Column A (network_core.zig + jitter_core.zig) statik analiz auditi
**Dosyalar:** `src/network_core.zig`
**Tip:** Proaktif audit — runtime hatası henüz gözlemlenmedi

---

### Hata 1: RST Packet Durumunda `std.process.exit(1)` Defer'ları Bypass Ediyor

**Hata:** `completeHandshake` içinde RST packet görüldüğünde `std.process.exit(1)` çağrılıyor.
Zig'de `exit(2)` syscall defer bloklarını ÇALIŞTIRMAZ.
Sonuç: `iptables` kuralları (`OUTPUT DROP`, `PREROUTING NOTRACK`, `INPUT ACCEPT`) temizlenmeden kalır.

**Kök Sebep:** `std.process.exit(1)` process'i anında sonlandırır, cleanup kodu atlanır.

**Kaynak:** Zig error handling semantics — `defer` runs on `return` and `error return`, NOT on `exit()`.
POSIX.1-2017 — `exit()` vs `_Exit()`: Zig `std.process.exit` = `_Exit` semantics.

**Düzeltme:**
```zig
// ÖNCEKİ:
std.process.exit(1);

// SONRAKİ:
return; // defer removeRstSuppression() main thread'de çalışır
```

---

### Hata 2: MTU Assert'ında 5 Byte TLS Record Header Hesaplanmamış

**Hata:** `buildTLSClientHelloAlloc` içinde `std.debug.assert(tls_record_len <= 1448)` kullanılıyor.
Ancak `1448 = 1500 - 52(IP/TCP)` TLS record payload limitidir.
TLS record header (5 byte) bu hesaba dahil değil.

Gerçek max packet: `52(IP/TCP) + 5(TLS header) + 1448(handshake) = 1505 > 1500`

**Kök Sebep:** `record_payload_len` = handshake header(4) + content. TLS record header(5) ayrıca eklenmeli.

**Kaynak:** RFC 8446, Section 5.1 — TLSPlaintext structure: `opaque content[TLSPlaintext.length]` + 5 byte header.

**Düzeltme:**
```zig
// ÖNCEKİ:
std.debug.assert(tls_record_len <= 1448);

// SONRAKİ:
const tls_total_record = TLS_RECORD_HEADER_LEN + tls_record_len;
std.debug.assert(tls_total_record <= 1448);
```

---

### Hata 3: `buildTCPDataAlloc` MTU Assert'ı Panic Üretiyor (Düzeltildi)

**Hata:** `std.debug.assert(total_len <= MTU_LIMIT)` panic üretir, defer'lar çalışmaz.

**Düzeltme:**
```zig
// ÖNCEKİ:
std.debug.assert(total_len <= MTU_LIMIT);

// SONRAKİ:
if (total_len > MTU_LIMIT) {
    return error.MTUExceeded;
}
```

---

### Değişiklik Özeti

| Konum | Değişiklik |
|---|---|
| `completeHandshake` satır ~1705 | `std.process.exit(1)` → `return` (cleanup defer ile çalışır) |
| `buildTLSClientHelloAlloc` satır ~1262 | TLS record header (5 byte) hesaba katıldı |
| `buildTCPDataAlloc` satır ~1425 | `assert` → `if (total_len > MTU_LIMIT) return error.MTUExceeded` |

---

*Son güncelleme: 2026-04-07*
*Güncelleyen: Red Team Audit + void0x14*
*Tetikleyen: Column A holistic statik analiz*

---

## [2026-04-07] — Module 2.4 Implementasyonu: AES-GCM API, JSON Buffer Hesaplama ve Nonce Test Hataları

**Tetikleyici:** Module 2.4 — Payload Construction and Token Extraction implementasyonu
**Dosyalar:** `src/network_core.zig`
**Tip:** Proaktif — runtime hatası görülmeden, test aşamasında tespit edildi

### Hata 1: `std.crypto.aead.Aes128Gcm` yolu yanlış
**Doğru yol:** `std.crypto.aead.aes_gcm.Aes128Gcm` (nested struct organizasyonu)

### Hata 2: Aes128Gcm.encrypt ciphertext buffer boyutu yanlış
**Sorun:** `ciphertext = plaintext_len + TAG_LEN` allocate edildi, ama API `c.len == m.len` assert ediyor.
**Çözüm:** ciphertext buffer = plaintext size, tag ayrı output parametresi.

### Hata 3: buildGitHubPayload buffer boyutu yanlış hesaplanmış
**Sorun:** Manuel `fixed_overhead` hesaplaması string literal uzunluklarını yanlış topluyordu.
**Çözüm:** Statik string constants + `.len` ile otomatik hesaplama.

### Hata 4: computeNonce testinde XOR değeri yanlış
**Sorun:** `0x0B ^ 0x01` yazıyordu, `0x0C ^ 0x01` olmalı.
**Çözüm:** `0x0C ^ 0x01 = 0x0D` olarak düzeltildi.

---

*Son güncelleme: 2026-04-07*
*Güncelleyen: void0x14*
*Tetikleyen: Module 2.4 implementasyonu ve zig build test*

---

## [2026-04-07] — Module 3.1 Implementasyonu: Zig 0.16 Crypto/Base64/Fmt API Uyumluluk Hataları

**Tetikleyici:** Module 3.1 — Identity Forgery & BDA Synthesis implementasyonu
**Dosyalar:** `src/network_core.zig`
**Tip:** Proaktif — Zig 0.16.0-dev.3135 API değişiklikleri

### Hata 1: `std.fmt.formatIntBuf` yok, `std.fmt.printInt` kullanılmalı
**Sorun:** `std.fmt.formatIntBuf` Zig 0.16'da kaldırılmış.
**Çözüm:** Tüm çağrılar `std.fmt.printInt(&buf, value, base, case, options)` ile değiştirildi.

### Hata 2: `std.crypto.aes.Aes128` yolu yanlış
**Sorun:** `std.crypto.aes.Aes128` test modunda erişilemiyor.
**Çözüm:** `std.crypto.core.aes.Aes128` kullanıldı.

### Hata 3: `std.crypto.hash.Sha256` yolu yanlış
**Sorun:** `std.crypto.hash.Sha256` Zig 0.16'da yok.
**Çözüm:** `std.crypto.hash.sha2.Sha256` kullanıldı.

### Hata 4: AES encrypt/decrypt pointer tipleri
**Sorun:** `aes_ctx.encrypt(dst: *[16]u8, src: *const [16]u8)` bekliyor, slice veriyorduk.
**Çözüm:** `ciphertext[i .. i + 16][0..16]` ile `[16]u8` pointer'a cast edildi.

### Hata 5: `std.base64.standard.Encoder.init(.{})` yanlış
**Sorun:** `std.base64.standard.Encoder` zaten init edilmiş struct.
**Çözüm:** Direkt `std.base64.standard.Encoder` kullanıldı, `.init()` kaldırıldı.

### Hata 6: `parseArkoseResponse` memory leak
**Sorun:** `token` ve `challenge_url` allocate ediliyor ama error durumunda free edilmiyor.
**Çözüm:** `errdefer` bloğu eklendi, testte de `allocator.free(parsed1.token.?)` ile temizlik yapıldı.

---

*Son güncelleme: 2026-04-07*
*Güncelleyen: Module 3.1 implementasyonu*
*Tetikleyen: Zig 0.16.0-dev.3135 API uyumluluk testleri*

## 2026-04-09 — Livewire `syncEmail` State Missing Error
**Hata:** `DigistalloneClient.pollInboxForGitHubCode` 120 deneme boyunca HTML dönmeyerek başarısız oldu (No HTML snapshot available).
**Kök sebep:** `fetchMessages` eventi `frontend.app` komponentine fırlatılırken, e-posta adresini belirten `syncEmail` olayı atlanmıştı. Backend hangi e-postayı aradığını bilmediği için boş liste dönüyor ve `"html":"..."` bloğunu POST yanıtında göndermiyordu.
**Kaynak:** Chrome DevTools MCP ile gerçekleştirilen Wire-truth capture. (Browser'ın `frontend.actions` ve `frontend.app` komponentlerine aynı anda `syncEmail` yolladığı gözlemlendi)
**Düzeltme:** `buildUpdateRequest` yerine birebir network trafiği (array içinde iki komponent objesi ve `__dispatch("syncEmail")`) çıkaran özelleştirilmiş `buildPollRequest` fonksiyonu yazıldı.

## 2026-04-09 — Livewire Double-Escaping Snapshot Bug
**Hata:** Digistallone mailbox polling sürecinde, sunucu `"html"` efekti dönmek yerine `CorruptComponentPayloadException` 500 hatası dönüyordu. Bu hata yüzünden süreç 13 dakika boyunca timeout'a kadar takılı kalıyordu.
**Kök sebep:** `extractStateFromResponse` içerisinde component state'i `snap_escaped` değişkeni aracılığıyla "backslash" içeren escape formatında saklanıyordu. Daha sonra `buildPollRequest` veya `buildUpdateRequest` üzerinden JSON payload'ı inşa ederken `std.json.Stringify.write` çağrıldığında, halihazırda escape edilmiş string bir kez daha escape ediliyordu (örneğin; `{\"data\":...}` -> `"{\\\"data\\\":...}"`). Livewire v3 backend bu bozuk String'i parse edemediği için snapshot'ı onaylayamıyordu.
**Kaynak:** RFC 8259, `json_decode`, ve Digistallone Livewire Exception behavior.
**Düzeltme:** `extractStateFromResponse` fonksiyonu içerisine önceden var olan `unescapeJsonStringInto` logiciği entegre edildi. Backend'den dönen escaped JSON component state'i belleğe kaydedilmeden hemen önce _unescape_ edildi. Böylece `std.json.Stringify` paketi kullanıldığında data sadece bir kere, olması gerektiği gibi escape edilmiş oluyor ve backend hata üretmeden lifecycle'ı tamamlıyor. Ayrıca 500 `CorruptComponentPayloadException` gelirse sonsuz döngüden hemen çıkılması için `mem.indexOf` kontrolü eklendi.

---

## [2026-04-10] — Staged Değişiklik İnceleme: 7 Hata Tespit ve Düzeltme

### P1 — CRITICAL: harvest.html Redirect Sonrası Script Kayboluyor (MOCK → GERÇEK)

**Hata:** `harvest.html` yaklaşımıyla `harvest.js` yükleniyor → `window.location.href = "https://github.com/signup"` redirect → **harvest.js kayboluyor**. Yeni sayfada monkey-patch aktif değil, token extraction çalışmaz.
**Kök sebep:** HTML injection yöntemi, redirect sonrası JavaScript execution context'ini kaybediyor. Content script olarak inject edilmiyor.
**Kaynak:** Chrome Extension Manifest V3 — `content_scripts[].run_at = "document_start"` her matching sayfada otomatik inject eder
**Düzeltme:** Chrome Extension yaklaşımına geçildi:
- `writeHarvestHtml` → `writeHarvestExtension` (Manifest V3, content_scripts)
- Extension `document_start`'ta inject eder → her GitHub/Arkose sayfasında otomatik çalışır
- `--disable-extensions` → `--disable-extensions-except` + `--load-extension`
- Start URL: `harvest.html` → `https://github.com/signup`

### P2 — CRITICAL: readLine Blocking I/O Deadlock Riski

**Hata:** `stdout_file.read()` blocking çağrı — pipe buffer dolunca Chrome yazamaz, biz okuyamaz = **deadlock**.
**Kök sebep:** Child process stdout pipe'dan blocking read yapıyorduk. Chrome stdout buffer'ı dolduğunda write bloke olur, bizim read de bloke olur = karşılıklı deadlock.
**Kaynak:** man 2 poll — POLLIN ile fd readiness kontrolü
**Kaynak:** man 2 read — non-blocking read after poll confirmed data available
**Düzeltme:** `std.posix.poll()` ile non-blocking kontrol eklendi. Önce POLLIN kontrolü, sonra `std.posix.read()` ile okuma.

### P3 — HIGH: buildChromeArgv Test Assertion Yanlış

**Hata:** Test `about:blank` bekliyordu ama kod artık `SIGNUP_URL` dönüyordu. Extension flag'leri test edilmemişti.
**Kök sebep:** Test, eski `harvest.html` akışına göre yazılmıştı. Extension yaklaşımına geçişte test güncellenmemişti.
**Düzeltme:** Test `SIGNUP_URL`, `--load-extension` ve `--disable-extensions-except` flag'lerini doğrulayacak şekilde güncellendi.

### P4 — MEDIUM: byte_buf Uninitialized → Undefined Behavior Riski

**Hata:** `const byte_buf: [1]u8 = undefined;` — read başarısız olursa UB riski.
**Kök sebep:** Zig'de `undefined` bellek, okunursa UB'dir. `read` hatasında `byte_buf[0]` okunabilir.
**Düzeltme:** `var byte_buf: [1]u8 = [1]u8{0};` olarak değiştirildi.

### P5 — MEDIUM: `__Host-` Cookie Erişimi (document.cookie ile Okunamaz)

**Hata:** `document.cookie` ile `__Host-next-auth.csrf-token` okunamaz.
**Kök sebep:** RFC 6265bis Section 4.1.2'ye göre `__Host-` prefixli cookie'ler HttpOnly+Secure ve JavaScript'ten erişilemez.
**Kaynak:** RFC 6265bis, Section 4.1.2 — Cookie Prefixes
**Düzeltme:** Session alanı kaldırıldı, `parseIdentityLine` ve `checkForChallengeCompletion` güncellendi.

### P6 — MEDIUM: extractTokenFromResponse Pattern 3 Çok Agresif

**Hata:** `/[a-zA-Z0-9_-]{2000,}/` — herhangi bir 2000+ karakterlik string'i token kabul ediyor (yanlış pozitif riski yüksek).
**Kök sebep:** Regex, Arkose Labs token formatını bilmeden yazılmıştı. Her uzun string'i token kabul ediyordu.
**Düzeltme:** Agresif Pattern 3 kaldırıldı. Pattern 2, Arkose Labs'a özgü alan adlarıyla (`session_token`, `solver_response`) sınırlandırıldı. Minimum uzunluk 500 karakter olarak artırıldı.

### P7 — LOW: setOctoCookie Zero-Length Kontrolü

**Hata:** `octo_value.len == 0` durumunda `@memcpy` 0-length slice'larla çağrılıyordu.
**Kök sebep:** Zero-length `@memcpy` tanımsız davranış riski taşır ve cookie jar'ı bozuk duruma sokabilir.
**Düzeltme:** Early return + `std.debug.assert` eklendi.

### P8 — HIGH: Zig 0.16 API Uyumsuzluğu — std.time.sleep ve File.read Mevcut Değil

**Hata:** `std.time.sleep()` ve `File.read()` Zig 0.16 vendored stdlib'de mevcut değil — derleme hatası.
**Kök sebep:** Zig 0.16'da I/O API'si `std.Io` namespace'ine taşındı. `sleep` → `Io.sleep`, `File.read` → `Reader` pattern. Ancak Reader non-blocking I/O ile uyumsuz olduğu için doğrudan POSIX syscall kullanıldı.
**Kaynak:** man 2 nanosleep — nanosleep syscall
**Kaynak:** man 2 read — POSIX read syscall
**Kaynak:** vendor/zig-std/std/Io/File.zig — Reader API
**Düzeltme:**
- `std.time.sleep()` → `std.os.linux.nanosleep()` (doğrudan syscall)
- `stdout_file.read()` → `std.posix.read(stdout_file.handle, &byte_buf)` (doğrudan POSIX read)

### P9 — CRITICAL: BrowserBridge Signup Flow'una Entegre Edilmemişti

**Hata:** Staged değişiklikler (BrowserBridge, StealthBrowser, harvest.js) yazılmış ama `main.zig`'deki signup flow'una bağlanmamıştı. Motor Chrome spawn ediyordu ama harvested token'ı kullanmıyordu.
**Kök sebep:** Değişiklikler izole modül düzeyinde yapılmış, ana orkestrasyon akışına entegre edilmemişti.
**Düzeltme:**
1. `main.zig`'e `browser_bridge` import eklendi
2. ADIM 11.4'te `BrowserBridge.init` + `harvest()` çağrısı eklendi
3. Harvest edilen `octocaptcha_token` → `performSignup`'a `harvested_octocaptcha_token` parametresi olarak geçirildi
4. Harvest edilen `_octo` cookie → `github_client.cookie_jar.setOctoCookie()` ile cookie jar'a inject edildi
5. `performSignup` fonksiyonuna `?[]const u8` parametre eklendi — harvested token varsa `SignupTokens.octocaptcha_token`'a set ediyor

---

## [2026-04-25] — permissions_geolocation SEGFAULT — collectFingerprint() eksik dupe

**Ne oldu:** `writeFingerprintNDJSON()` çağrısında `diagnostic.permissions_geolocation` alanı `appendSlice` ile buffer'a eklenirken SEGFAULT oluştu. `memcpy.zig:170`'de kaynak pointer geçersiz.

**Kök sebep:** `browser_bridge.zig:1549-1560` arası `collectFingerprint()` fonksiyonunda, JSON parse sonucu oluşan struct'ın string alanları `allocator.dupe()` ile kopyalanıyor. Ancak `permissions_geolocation` alanı bu kopyalama listesinden MUAF tutulmuş (copy-paste hatası). `parsed.deinit()` çağrıldığında JSON buffer serbest bırakılıyor, `diagnostic.permissions_geolocation` hala o freed memory'yi işaret ediyor → use-after-free → SEGFAULT.

**Kaynak:**
- `browser_bridge.zig:1146`: `permissions_geolocation: []const u8` — opsiyonel değil, her zaman değer bekleniyor
- `browser_bridge.zig:1545`: `defer parsed.deinit()` — JSON buffer'ı free ediyor
- `browser_bridge.zig:1549-1560`: dupe işlemi — `permissions_geolocation` eksik

**Düzeltme:**
- `browser_bridge.zig:1560`: `diagnostic.permissions_geolocation = self.allocator.dupe(u8, diagnostic.permissions_geolocation) catch return BridgeError.OutOfMemory;` satırı eklendi

**Doğrulama:**
- `vendor/zig/zig build` → EXIT_CODE=0
- `vendor/zig/zig build test` → 222/222 test geçti

**Tekrar olmaması için:**
- Struct'a yeni `[]const u8` alanı eklenirken, `collectFingerprint()` içindeki dupe listesine de eklenmeli
- `deinit()` fonksiyonunda free edilen her alan, dupe listesinde de olmalı

---

## [2026-04-25] — CDP Bridge ConnectFailed — WouldBlock ve parçalanmış TCP handshake

**Hata:** `BrowserBridge.init()` 20 deneme sonrası `ConnectFailed` döndürüyordu. Altta yatan sorunlar:
1. `CdpClient.connect()` step 5'te WebSocket 101 handshake yanıtını tek `std.posix.read()` ile okuyordu — TCP parçalanırsa `"HTTP/1.1 101"` header'ı görülemiyordu
2. `writeAll()` ve `recvExact()` fonksiyonlarında `error.WouldBlock` için retry yoktu — doğrudan hata dönüyordu
3. `findTargetTab()` HTTP yanıt okuması `error.WouldBlock` aldığında `break` yapıp yarım parsing yapıyordu
4. Chrome'un 9222 portunda dinleyip dinlemediğini kontrol eden mekanizma yoktu

**Kök sebep:** Tüm socket I/O işlemleri blocking modda bile `SO_RCVTIMEO` expiry durumunda `EAGAIN`/`EWOULDBLOCK` dönebilir. Bu durumda kod doğrudan başarısız oluyor, retry yapmıyordu. Ayrıca WebSocket handshake tek `read()` çağrısıyla yapılıyor, parçalanmış TCP segmentlerini handle etmiyordu.

**Kaynak:**
- man 2 read — EAGAIN/EWOULDBLOCK dönüş değeri
- man 2 write — EAGAIN/EWOULDBLOCK dönüş değeri
- RFC 6455, Section 4.2.2 — Server handshake: "The server responds with HTTP/1.1 101 Switching Protocols"
- man 7 socket — SO_RCVTIMEO: "Specify the receiving timeout until reporting an error"

**Düzeltme:**
1. `CdpClient.connect()` step 5: Tek `read()` → `\r\n\r\n` bulana kadar okuyan döngü, her `WouldBlock`'ta 10ms sleep + retry (max 200 = 2s)
2. `writeAll()`: `linux.write()` sonrası errno `.AGAIN` ise 10ms sleep + retry (max 100)
3. `recvExact()`: `std.posix.read()` error `WouldBlock` ise 10ms sleep + retry (max 100)
4. `findTargetTab()` HTTP read: `error.WouldBlock` → `break` yerine `continue` + 50ms sleep retry (max 60 = 3s)
5. `isChromeCdpListening()`: Yeni fonksiyon — 127.0.0.1:9222'ye TCP connect denenerek Chrome'un hazır olup olmadığını kontrol eder
6. `BrowserBridge.init()`: Her deneme hatasında spesifik error tipi loglanır, Chrome pre-flight check eklendi, `>>> BRIDGE ESTABLISHED <<<` logu eklendi
7. `main.zig`: Bridge başarıyla kurulduğunda görsel `BRIDGE ESTABLISHED — AUDIO BYPASS READY` kutusu eklendi

**Doğrulama:**
- `vendor/zig/zig build` → EXIT_CODE=0
- `vendor/zig/zig build test` → Tüm 132 test geçti

---

## [2026-04-28] — Audio Outlier Engine Integration Audit: 7 Root Cause Fix

**Tetikleyici:** Audio outlier engine integration audit — canlı motor 0% success rate, verdict always `.wrong`, same challenge refetch loop.
**Dosyalar:** `src/arkose/audio_bypass.zig`, `src/arkose/audio_injector.zig`, `src/arkose/audio_downloader.zig`, `src/browser_bridge.zig`
**Tip:** Integration bug — individual modules passed tests but composed behavior was wrong.

---

### Hata 1: `shouldContinueAudioChallengeLoop` Hedef Kontrolü Eksik

**Hata:** Döngü koşulu `successful_submits < target_challenges` kontrolü yapmıyordu. Bu yüzden `target=3` iken 4., 5., ... denemelere geçilebiliyor ve "Attempt 4/3" logları üretiliyordu.
**Kök sebep:** `shouldContinueAudioChallengeLoop()` sadece `attempted < MAX_CHALLENGES` ve erken completion sinyaline bakıyordu; runtime hedef sayısını (`audio_challenge_urls.len`) dikkate almıyordu.
**Kaynak:** `src/arkose/audio_bypass.zig` — `shouldContinueAudioChallengeLoop()`
**Düzeltme:** Koşul `successful_submits < target_challenges && attempted < MAX_CHALLENGES` olarak daraltıldı. `target_challenges > 0` olduğu varsayımı da eklendi.

---

### Hata 2: `computeRuntimeEvaluateTimeouts` CDP Timeout'u Audio Fetch'i Kırıyordu

**Hata:** `audio_downloader.zig` 30 saniyelik audio fetch timeout istiyordu ama `browser_bridge.zig`'deki `max_cdp_timeout_ms = 8000` bu değeri sessizce 8 saniyeye kırpıyordu. Sonuç: uzun audio dosyaları indirilirken CDP timeout, `recvWsTextAlloc` `ReadFailed`/`WouldBlock` dönüyordu.
**Kök sebep:** `computeRuntimeEvaluateTimeouts()` `requested_ms` ile `max_cdp_timeout_ms`'nin min'ini alıyordu; max değer audio fetch gereksiniminin çok altındaydı.
**Kaynak:** `src/browser_bridge.zig` — `computeRuntimeEvaluateTimeouts()`
**Düzeltme:** `max_cdp_timeout_ms` 8000 → 30000 ms yükseltildi. Socket timeout = `cdp_timeout_ms + 5000` marjı korundu.

---

### Hata 3: `game_core_session_token` Double-Free

**Hata:** `runAudioBypass()` içinde `game_core_session_token` ilk allocate ediliyor, sonra `arkose_cdp.evaluateInContextWithTimeout()` sonrası `defer allocator.free(game_core_session_token)` çalışıyor, ardından aynı pointer `buildRuntimeEvaluateParams()` ile tekrar kullanılıyordu. `defer` sonrası free edilmiş pointer'ı başka bir CDP çağrısına vermek = use-after-free.
**Kök sebep:** Aynı `[]const u8` pointer hem `defer free` hem sonraki evaluate params olarak kullanılıyordu; sahiplik modeli net değildi.
**Kaynak:** `src/arkose/audio_bypass.zig` — `runAudioBypass()`
**Düzeltme:** `game_core_session_token` kullanımından önce `allocator.dupe(u8, ...)` ile kopya alınıyor; orijinal token `defer free` ile güvenle serbest bırakılıyor, kopya sonraki evaluate params'a geçiriliyor.

---

### Hata 4: `arkose_cdp` `errdefer` Yerine `defer` — Leak

**Hata:** `arkose_cdp` değişkeni `errdefer` ile kapatılıyordu. Eğer `connectToArkoseWs()` başarılı olup sonrasında bir hata oluşursa (örn. `evaluateInContextWithTimeout` hatası), `arkose_cdp` kapatılmıyordu → WebSocket connection leak.
**Kök sebep:** `errdefer` sadece hata yolunda çalışır; normal return path'te resource leak oluşur.
**Kaynak:** `src/arkose/audio_bypass.zig` — `runAudioBypass()`
**Düzeltme:** `errdefer arkose_cdp.close();` → `defer arkose_cdp.close();`

---

### Hata 5: `challenge_index` State Drift

**Hata:** `successful` sayacı arttırıldığında `challenge_index` aynı değere senkronize edilmiyordu. Bu, UI state ile audio indirme indeksinin farklı değerleri göstermesine neden oluyordu; yanlış challenge'a enjeksiyon yapılıyordu.
**Kök sebep:** `challenge_index` yalnızca loop başında `attempted` ile ilişkilendirilmişti, `successful` artışı sonrası güncellenmiyordu.
**Kaynak:** `src/arkose/audio_bypass.zig` — `runAudioBypass()`
**Düzeltme:** Her `successful += 1` işleminden hemen sonra `challenge_index = successful;` ataması eklendi.

---

### Hata 6: `injectAnswerOnTarget` `click_attempted` + `!submitResponseSucceeded` → `.unknown`

**Hata:** `injectAnswerOnTarget()` `submitResponseSucceeded()` false döndüğünde (örn. `no_submit` yanıtı) yine de `click_attempted` true olabiliyordu. Eski kod bu durumu `.wrong` veya `.transition` olarak sınıflandırıyordu; doğru davranış `click_attempted` true ama submit server'a ulaşmamışsa `.unknown` olmalıydı.
**Kök sebep:** Click başarısı ile submit başarısı aynı semantiğe bağlanmıştı. Click yalnızca DOM action'dır; server submit kanıtı değildir.
**Kaynak:** `src/arkose/audio_injector.zig` — `injectAnswerOnTarget()`
**Düzeltme:** `click_attempted` true ve `submitResponseSucceeded()` false ise `.unknown` dönüyor; caller UI'yi yeniden değerlendiriyor.

---

### Hata 7: `audio_downloader.zig` Testi Eski Semantiği Doğruluyordu

**Hata:** `audio_downloader.zig` testinde `challenge=2` (integer) kullanılıyordu; bu eski 0-indexed challenge modeline aitti. Yeni modelde challenge index `char` tipinde (`'0'`, `'1'`, `'2'`) ve 1-indexed cevap üretiliyor.
**Kök sebep:** Test, canlı motorun değişen challenge index semantiğini takip etmemişti.
**Kaynak:** `src/arkose/audio_downloader.zig` — test bloğu
**Düzeltme:** `challenge=2` → `const challenge = '2';` olarak değiştirildi; test yeni semantiği doğruluyor.

---

### Doğrulama

```
✅ vendor/zig/zig build         → exit code 0
✅ vendor/zig/zig build test    → 169/169 test geçti (8 browser_init + 28 fft_analyzer + 132 network_core/http2_core + 1 audio_injector_semantics)
```

---

## [2026-04-29] — Arkose EC UI 2.0 DOM Parser .fc-* Class Bağımlılığı (CRITICAL)

**Hata:** `audio_bypass.zig` UI parser'ı Arkose EC UI 2.0'ın yeni DOM yapısını ıskaladı. `wait_for_ui_script` `.fc-challenge, .fc-button, .fc-audio, .fc-audio-button, [class^="fc-"]` selectorleri kullanıyordu; bu class'lar kaldırılınca `fc=0|btns=0|children=0` dönüp `ui_ready=false`. Pipeline game-core'a hiç ulaşamadan ilerleyemiyordu. Aynı şekilde `audio_challenge_click_script` ve `injectAnswerOnTarget` da dar selectorler kullanıyordu.

**Kök sebep:** Arkose Labs Enforcement Challenge UI 2.0 tamamen yeniden tasarlandı (developer docs 2021-08-25). Eski `.fc-*` (FunCaptcha) class isimleri kaldırıldı; yerine generic `<button>` ve shadow DOM container'lar geldi. Kod spesifik class isimlerine hardcoded bağımlıydı.

**Kaynak:** Arkose Labs docs — "Enforce Challenge UI 2.0 is completely redesigned with a brand new UI component" (https://developer.arkoselabs.com/docs/new-enforcement-challenge-ui); canlı motor logu 2026-04-29 — `fc=0|btns=0|children=0` sürekli tekrar.

**Düzeltme:**
1. `wait_for_ui_script`: `.fc-*` bağımlılığı kaldırıldı; class-agnostic generic interactive element detection (`button`, `input`, `iframe`) kullanılıyor
2. `audio_challenge_click_script`: `.fc-button, .fc-audio, .fc-audio-button, #audio` selectorleri kaldırıldı; text/aria-label/title heuristic'i (`audio`, `sound`, `hear`, `listen`) ile class-agnostic detection
3. `audio_injector.zig` `ANSWER_INPUT_SELECTORS`: `input[type="number"]` ve `input[type="tel"]` eklendi; generic `input:not([type="hidden"])` fallback eklendi
4. `injectAnswerOnTarget`: answer injection ve post-submit proof script'leri çoklu input selector fallback zinciri kullanıyor (text → number → tel → any visible input)
5. `AUDIO_BTN_TEXT_MATCHER` ve `findAudioButton`: heuristic expanded (`audio`, `sound`, `hear`, `listen`)
6. `SUBMIT_BTN_TEXT_MATCHER`: "Submit" yanında "Verify", "Next", "Continue", "Done" de match ediyor

**Doğrulama:**
```
✅ vendor/zig/zig build         → exit code 0
✅ vendor/zig/zig build test    → 169/169 test geçti
```

---

*Son güncelleme: 2026-04-29*
*Güncelleyen: void0x14 + AI audit*
*Tetikleyen: Arkose EC UI 2.0 DOM yapısı değişikliği — audio bypass parser class bağımlılığı*

---
