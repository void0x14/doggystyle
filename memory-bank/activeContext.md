# Active Context: Keep-Alive Fix v2 — Full Reconnect (deinit+init)

## Root Cause: Stale Keep-Alive Connection

LiteSpeed Keep-Alive timeout 5s. GitHub signup ~11s sürüyor. Bu süre içinde server TCP'yi sessizce kapatıyor.

## Fix Evolution

**v1 (FAILED):** `HttpClient.reconnect()` — partial reconnect (TCP+TLS yenile, aynı struct içinde). TLS handshake sonrası bağlantı stabil olmadı, her poll yine TcpRecvFailed verdi.

**v2 (WORKING):** `deinit()` + `HttpClient.init()` — TAM YENİ bağlantı. Cookie'ler kayboluyor ama bu sorun değil çünkü GET /mailbox sonrası yeni CSRF + session cookie'leri alınıyor.

## ensureConnected() Flow
```
isStale(3000ms)?
  → YES: http.deinit()
  → HttpClient.init() (yeni TCP+TLS)
  → GET /mailbox (yeni CSRF + session)
  → livewire.parseInitialState()
  → http = new_http
  → NO: devam et
```

## Mevcut Durum
- Build: ✅ clean
- Tests: ✅ 33/33 passing
- Reconnect stratejisi: full deinit+init (partial reconnect iptal)
