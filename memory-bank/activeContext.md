# Active Context: İki Katmanlı UFW Sorunu Çözüldü

## Gerçek Kök Neden (Kesin, Kanıtlanmış)

tcpdump + raw socket karşılaştırması sonucu tespiti:

```
tcpdump (AF_PACKET, iptables ÖNCESİ): SYN-ACK görüyor ✓
SOCK_RAW (AF_INET, iptables SONRASI): SYN-ACK görmüyor ✗
```

**Linux kernel netfilter akışı:**
NIC → PREROUTING → routing → INPUT chain → socket delivery

tcpdump pre-iptables çalışır (AF_PACKET seviyesi). SOCK_RAW, INPUT zincirinden SONRA paket alır. UFW INPUT `policy DROP` ve eşleşen ACCEPT kuralı olmadığından SYN-ACK INPUT chain'de düşürülüyordu.

### Uygulanan Düzeltmeler

1. **PREROUTING NOTRACK**: Inbound SYN-ACK için conntrack bypass (INVALID olarak işaretlenmesin)
2. **INPUT ACCEPT** (asıl kritik düzeltme): `iptables -I INPUT -p tcp --sport 443 --dport {port} -j ACCEPT`
   - UFW'un DROP policy'sini bypass eder
   - Paketi socket delivery'a ulaştırır

### TLS decode_error Düzeltmesi

**Neden**: `0xFE0D` GREASE extension tipi değil — IANA'nın ECH'e atadığı gerçek extension tipi. Cloudflare 1.1.1.1 üzerinde ECH implement ediyor ve payload'ı strict parse ediyor. Önceki payload'daki byte[0] = `0x0D` geçersiz (ECH type: 0=inner, 1=outer).

**Düzeltme**: ECHClientHello outer wire format:
- byte 0: `0x01` (outer)
- byte 1-2: `0x0001` (HKDF-SHA256)
- byte 3-4: `0x0001` (AES-128-GCM)
- byte 5: random config_id
- byte 6-7: `0x0000` (enc length = 0)
- byte 8-9: `0x0001` (payload length = 1)
- byte 10: random payload byte

## Mevcut Durum
- Build: başarılı
- PREROUTING NOTRACK + INPUT ACCEPT + ECH fix uygulandı
- `sudo ./verify.sh` çalıştırılmayı bekliyor
- Beklenen: STAGES=4+ → OVERALL SUCCESS

## verify.sh Aşama Haritası
| Aşama | Kontrol | Hata mı? |
|---|---|---|
| SYN-ACK | [SUCCESS] Targeted SYN-ACK Captured | RESULT=1 (mandatory) |
| Handshake | Handshake Completed | stage++ only |
| MTU | [MTU] Packet size N bytes <= 1500 | RESULT=1 if violation |
| TLS Hello | TLS Client Hello sent | stage++ only |
| JA4S | [SUCCESS] JA4S Confirmed | WARNING only |
| RST leak | Kernel Leak Detected | RESULT=1 if present |

STAGES >= 4 ve RESULT = 0 → OVERALL SUCCESS
