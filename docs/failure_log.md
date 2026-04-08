# Ghost Engine — Failure Log

Bu dosya gerçek hataların anatomisini, kök neden analizini ve çözüm sürecini kayıt altına alır.
Hem geliştirici hem de yapay zeka modelleri için başvuru kaynağıdır.
**Kural:** Her bug fix sonrası bu dosya güncellenir.

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
