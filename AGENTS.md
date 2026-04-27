# AGENTS.md — Otonom Kod Üretimi için Zorunlu Protokol

Bu dosya, her AI oturumunun başında ve her yeni bileşen yazılmadan önce uygulanacak kuralları tanımlar.
Kurallar tavsiye niteliğinde değildir; ihlal = çıktı kabul edilmez.

---

## 0.0 DEĞİŞTİRİLEMEZ KESİN VE SABİT KURAL: CANLI MOTOR TESTİ VE GERÇEKTEN KODLARI DERLEME AŞAMASI

Build yapacağın zaman her zaman 'vendor/zig/zig build' komutunu kullancaksın,motoru çalıştıracağın zamanda her zaman bu komutu kullanacaksın 'sudo ./zig-out/bin/siege_engine enp37s0'

---

## 0.1 Temel İlke: Tahmin Yasağı

Sen bir istatistiksel tahmin motoru değil, bu projede bir **derleyici uzantısısın**.
Herhangi bir byte offseti, pointer aritmetiği, protokol alan sırası veya kernel davranışı için **tahmin yapamazsın**.

Eğer bir değeri bilmiyorsan yapman gereken tek şey şudur:

```
// COMPILE ERROR: Bu değer doğrulanmamıştır.
// Kaynak gerekli: <RFC numarası veya kernel source dosyası ve satırı>
@compileError("UNVERIFIED: ip_header_len assumed to be 20, provide exact IHL calculation");
```

Sessizce devam etmek, sessizce bir değer koymak veya "genellikle bu olur" demek yasaktır.

---

## 1. Kaynak Zorunluluğu (Source Grounding)

### 1.1 Kural

Aşağıdaki kategorilerde her satır kod için kaynak belirtmek zorundasın:

| Kategori | Kabul Edilen Kaynak |
|---|---|
| Ağ protokolü yapıları (IP, TCP, TLS, ECH) | RFC numarası + bölüm numarası |
| Linux kernel davranışı (soket, netfilter, conntrack) | `linux/net/` kaynak dosyası veya `man 7 <socket_tipi>` |
| IANA kayıtlı değerler (extension type, cipher suite) | IANA registry URL'si |
| Platform-spesifik sistem çağrısı davranışı | `man 2 <syscall>` veya kernel docs |

### 1.2 Format

Her fonksiyonun üstüne şu blok zorunludur:

```zig
// SOURCE: RFC 8446, Section 4.1.2 — ClientHello structure
// SOURCE: RFC 9180, Section 5.1 — HPKE KEM output length
// SOURCE: linux/net/ipv4/raw.c — IP_HDRINCL behavior on SOCK_RAW
fn buildClientHello(...) ![]u8 { ... }
```

Kaynak yoksa fonksiyon yazılmaz.

### 1.3 Kaynağa Erişim Hiyerarşisi - Fetch Zorunluluğu

Kaynaklara şu sırayla başvurulur; üstteki mevcut değilse alttakine geç:

1. **RFC metni** https://www.rfc-editor.org/rfc/rfcNNNN.txt (tools.ietf.org — plaintext versiyonu tercih et)
2. **Linux kernel source** (https://elixir.bootlin.com/linux/latest/source üzerinden aranabilir)
3. **IANA registry** (https://www.iana.org/assignments)
4. **Wireshark dissector kodu** (gerçek implementasyon referansı olarak)
5. **Referans implementasyon** (Go std, BoringSSL, OpenSSL — bu sırayla)

"Stack Overflow", "ChatGPT öyle demişti", "genellikle böyledir" geçerli kaynak değildir.

### 1.4 RFC - Fetch Zorunluluğu

**Herhangi bir protokol alanı yazmadan önce ilgili RFC'yi https://www.rfc-editor.org/rfc/rfcXXXX.txt adresinden fetch et ilgili bölümü oku, sonra kodu yaz.**

---

## 2. Struct-First Kodlama (Manuel Offset Yasağı)

### 2.1 Kural

Ham byte slice offseti ile protokol alanına erişmek yasaktır.

```zig
// YASAK — derleyici bu tür kodu kabul etmeyecektir (PR reddedilir)
const tcp_payload = buffer[ip_offset + 20 ..]; // 20 byte varsayımı

// ZORUNLU — struct üzerinden dinamik hesaplama
const ip_header_len: usize = @as(usize, header.ihl) * 4;
const tcp_payload = buffer[ip_header_len..];
```

### 2.2 Packed Struct Zorunluluğu

Her protokol katmanı için `packed struct` tanımlanır ve boyutu `comptime` ile doğrulanır:

```zig
const Ipv4Header = packed struct {
    ihl: u4,
    version: u4,
    dscp: u6,
    ecn: u2,
    total_length: u16,
    identification: u16,
    flags: u3,
    fragment_offset: u13,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
};
// SOURCE: RFC 791, Section 3.1
comptime {
    std.debug.assert(@sizeOf(Ipv4Header) == 20);
    std.debug.assert(@bitSizeOf(Ipv4Header) == 160);
}
```

### 2.3 Hizalama (Alignment) Kontrolü

`packed struct` kullanıldığında endianness ve bit sırası platform bağımlıdır.
Her struct için şu kontroller eklenir:

```zig
comptime {
    // Ağ byte sırası (big-endian) ile native sıra eşleşiyor mu?
    std.debug.assert(@import("builtin").cpu.arch.endian() == .big or
        @hasDecl(@This(), "byteSwapOnRead"));
}
```

---

## 3. Assert Katmanı (Runtime Doğrulama)

### 3.1 Paket İnşası

Her paket oluşturma fonksiyonu sonunda şu kontroller zorunludur:

```zig
fn buildPacket(allocator: std.mem.Allocator) ![]u8 {
    var buf = try allocator.alloc(u8, EXPECTED_SIZE);

    // ... inşa kodu ...

    // Boyut doğrulama — RFC'den hesaplanan değere karşı
    std.debug.assert(buf.len == EXPECTED_SIZE); // SOURCE: RFC XXXX, Section Y.Z
    
    // Kritik alan doğrulama
    std.debug.assert(buf[0] == 0x16); // TLS record type: handshake
    std.debug.assert(buf[1] == 0x03 and buf[2] == 0x01); // legacy_record_version

    return buf;
}
```

### 3.2 Struct Boyutu Comptime Assert

Tüm `packed struct` tanımlamalarının hemen altında `comptime` assert bloğu olmalıdır.
Bu assert olmayan bir struct PR'a kabul edilmez.

### 3.3 Allocasyon Sınırları

Dinamik allocation yapan her fonksiyon üst sınırını assert eder:

```zig
std.debug.assert(total_size <= MAX_PACKET_SIZE); // 65535 for IPv4
```

---

## 4. Ağ Yığını Farkındalığı (Network Stack Awareness)

### 4.1 Raw Socket Kodu Yazılmadan Önce Kontrol Listesi

Raw socket veya kernel-level ağ kodu yazılmadan önce aşağıdakiler açıkça analiz edilir ve kod içinde yorum olarak belirtilir:

```zig
// NETWORK STACK ANALYSIS:
// [1] UFW/iptables: Bu soket OUTPUT chain'den geçer mi? INPUT chain'den mi?
//     Cevap: SOCK_RAW + IP_HDRINCL → OUTPUT chain → ACCEPT kuralı gerekli
// [2] conntrack: Bu paket conntrack tarafından takip edilecek mi?
//     Cevap: Hayır — raw socket conntrack'i bypass eder (doğru davranış)
// [3] Routing: Paket hangi interface'den çıkacak?
//     Cevap: SO_BINDTODEVICE ile açıkça belirlenmiş olmalı
// [4] Checksum: Kernel mi hesaplıyor, uygulama mı?
//     Cevap: IP_HDRINCL ile uygulama hesaplar (IP checksum alanı 0 bırakılırsa kernel doldurur)
```

### 4.2 UFW/iptables Kuralı Gerektiren Kod

Kodun çalışması için bir firewall kuralı gerekiyorsa, bu kural kodun hemen yanında yorum olarak bulunur:

```zig
// FIREWALL REQUIREMENT:
// sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
// sudo iptables -A INPUT -p tcp --sport 443 -j ACCEPT
// Bu kurallar olmadan paket kernel tarafından DROP edilir.
```

---

## 5. Round-Trip Test Zorunluluğu

### 5.1 Kural

Her paket oluşturma fonksiyonu için bir parse fonksiyonu ve test bloğu zorunludur.
AI'dan bir `build*` fonksiyonu istediğinde, aynı promptta şunu da iste:

> "Şimdi yazdığın bu fonksiyonun çıktısını giriş olarak alan, her alanı doğrulayan ve RFC'ye uygunluğunu test eden bir `std.testing` bloğu yaz. Test, build fonksiyonu ile aynı dosyada olmalı."

### 5.2 Test Şablonu

```zig
test "buildClientHello: RFC 8446 Section 4.1.2 uyumu" {
    const allocator = std.testing.allocator;
    const hello = try buildClientHello(allocator, .{ ... });
    defer allocator.free(hello);

    // Record katmanı kontrolü (RFC 8446, Section 5.1)
    try std.testing.expectEqual(@as(u8, 0x16), hello[0]); // handshake
    try std.testing.expectEqual(@as(u8, 0x03), hello[1]); // legacy major
    try std.testing.expectEqual(@as(u8, 0x01), hello[2]); // legacy minor

    // HandshakeType kontrolü (RFC 8446, Section 4)
    try std.testing.expectEqual(@as(u8, 0x01), hello[5]); // client_hello

    // ECH extension varlık kontrolü (RFC 9001, IANA ext type 0xfe0d)
    const ech_type_pos = findExtension(hello, 0xfe0d);
    try std.testing.expect(ech_type_pos != null);
}
```

### 5.3 Fuzzing Döngüsü

Kararlı hale gelen her modül için `zig build fuzz` hedefi eklenir.
AI'dan fuzzing hedefi istendiğinde şu direktif kullanılır:

> "Bu fonksiyon için libFuzzer-uyumlu bir Zig fuzz hedefi yaz. Giriş verisi geçersiz/rastgele olduğunda fonksiyonun `error` döndürmesi veya graceful exit yapması gerekir; hiçbir zaman undefined behavior'a düşmemeli."

---

## 6. Hata Üretimi Protokolü (Failure Mode Dokümantasyonu)

### 6.1 Kural

AI'ın önceki oturumda ürettiği ve sonradan yanlış olduğu kanıtlanan her kod parçası için bir kayıt tutulur.

Format: `docs/failure_log.md`

```markdown
## [TARİH] — ECH Payload Offset Hatası

**Ne oldu:** AI, ECH payload'unun TLS record header'ından sonra doğrudan başladığını varsaydı.
**Gerçek:** ECH, ClientHello extension listesinin içinde, kendi length-prefixed bloğundadır.
**Kaynak:** RFC 9001, Section 5 + Wireshark dissector `tls-utils.c`
**Düzeltme:** `packed struct EchClientHello` ile offset elle hesaplanmıyor.
**Tekrar olmaması için:** Bu dosyanın Section 2.2 kuralı.
```

### 6.2 Oturum Başı Zorunlu Kontrol

> "docs/failure_log.md dosyasını oku. Bu dosyadaki hataların hiçbirini tekrarlama. Eğer yazmak üzere olduğun kod bu dosyadaki bir hatayı tekrarlıyorsa, dur ve beni uyar."

---

## 7. Çıktı Kabul Kriterleri (Definition of Done)

üretilen bir kod parçası ancak şu koşulların tamamını karşılıyorsa commit'e alınır:

- [ ] Her protokol yapısı için kaynak (RFC / kernel source) belirtilmiş
- [ ] Ham byte offset kullanılmamış; tüm offsetler `packed struct` veya dinamik hesaplamadan geliyor
- [ ] Her `packed struct` için `comptime assert(@sizeOf(...) == N)` mevcut
- [ ] İlgili `std.testing` bloğu yazılmış ve `zig test` geçiyor
- [ ] Raw socket kullanan kod için network stack analizi yorumu mevcut
- [ ] Firewall kuralı gerektiren kod için kural yorumu mevcut
- [ ] Bilinmeyen değerler için `@compileError` kullanılmış, sessiz varsayım yok

---

## 8. Protokol

```
[PROTOCOL: WIRE-TRUTH ENFORCEMENT]

Sen bu projede Principal Systems Engineer rolündesin.
Aşağıdaki kurallar mutlaktır; istisnası yoktur:

1. KAYNAK: Herhangi bir ağ protokolü alanı, byte offseti veya kernel davranışı yazmadan önce
   kullandığın RFC bölümünü, IANA kayıt değerini veya kernel source dosyasını belirt.
   Kaynak yoksa kodu yazma; @compileError ile işaretle.

2. OFFSET YASAĞI: `buffer[N..]` formundaki sabit offsetler yasaktır.
   Tüm offsetler packed struct veya dinamik IHL/length hesaplamasından türetilir.

3. ASSERT: Her struct boyutu comptime assert ile doğrulanır.
   Her paket boyutu runtime assert ile doğrulanır. Assert olmayan struct kabul edilmez.

4. TEST: Her build fonksiyonu için RFC referanslı std.testing bloğu zorunludur.

5. NETWORK STACK: Raw socket kullanan her fonksiyon, UFW/iptables/conntrack
   etkileşimini açıkça yorum olarak belgelemelidir.

6. HATA > TAHMİN: Eğer bir değerden emin değilsen, sessizce bir değer koyma.
   @compileError veya TODO yorum bırak ve beni uyar.

Daha önce bu projede şu hatalar üretildi — tekrarlama:
[failure_log.md içeriğini buraya yapıştır]
```

---

## 9. Versiyon ve Güncelleme

Bu dosya her yeni hata keşfedildiğinde güncellenir.
Son güncelleme: `[TARIH]`
Güncelleyen: `[AI model adı + kullanıcı]`
Tetikleyen olay: `[Kısa açıklama]`

---

## 10. Hata Kaydı Zorunluluğu

Herhangi bir bug fix tamamlandığında:
1. `docs/failure_log.md` dosyasını aç (yoksa oluştur)
2. Hatayı şu formatta ekle:

## [TARİH] — [Kısa başlık]
**Hata:** Ne yanlış gitti
**Kök sebep:** Neden oldu  
**Kaynak:** Doğru davranışı belgeleyen RFC/source
**Düzeltme:** Ne yapıldı

---
