# Ghost Engine — Failure Log

Bu dosya gerçek hataların anatomisini, kök neden analizini ve çözüm sürecini kayıt altına alır.
Hem geliştirici hem de yapay zeka modelleri için başvuru kaynağıdır.
**Kural:** Her bug fix sonrası bu dosya güncellenir.

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
