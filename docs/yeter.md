A. Execution Map
- main src/network_core.zig:1842-1905: arg parsing, interface resolve, dst_ip parse, src_ip ioctl ile alınır, ephemeral src_port üretilir.
- LinuxRawSocket.init src/network_core.zig:268-287: tek AF_INET/SOCK_RAW/IPPROTO_TCP socket açılır; IP_HDRINCL set edilir; yalnızca local IP’ye bind() yapılır; src_port açıkça atılır (269); ifindex tutulur ama sonra hiç kullanılmaz.
- applyRstSuppression src/network_core.zig:1430-1454: sadece OUTPUT RST drop ve raw/OUTPUT NOTRACK eklenir.
- main src/network_core.zig:1927-1953: listener thread spawn edilir, listener_ready.wait() sonrası SYN aynı fd üzerinden gönderilir.
- completeHandshake src/network_core.zig:1562-1599: SO_RCVTIMEO set edilir, ready event set edilir, sonra recvfrom(fd=3) loop başlar.
- filterRawPacket src/network_core.zig:1475-1509: yalnız recvfrom() sonrası IPv4/TCP, dst_ip == local_ip, src_port == 443, dst_port == ephemeral_port kontrol edilir.
- completeHandshake src/network_core.zig:1601-1771: sadece bu filtreden geçen paketler INBOUND PACKET loglar; SYN-ACK ise ACK, jitter, ClientHello ve JA4S yoluna gider.
- verify.sh verify.sh:58-145: başarı tamamen marker loglarına bağlıdır; [SUCCESS] Targeted SYN-ACK Captured yoksa failure verir. Script, [LISTENER READY] veya [LISTENER WAIT] aramaz.
B. Ranked Root Cause Candidates
1. Receive socket target flow’a kernel seviyesinde scope edilmemiş
Dosya: satır src/network_core.zig:268-287, 301-306, 453-465, 1475-1509, 1567-1599
Neden şüpheli: bind(local_ip:0) port bağlamıyor; src_port init içinde atılıyor; ifindex hesaplanıyor ama kullanılmıyor; connect, SO_BINDTODEVICE, SO_ATTACH_FILTER/BPF yok. Kod, hedef akışı ancak recvfrom() sonrasında ayırıyor.
Destekleyen kanıt: raw(7) açıkça “aynı protocol numarasına uyan tüm paketler raw socket’e geçer” ve bind() ile yalnız local address scope edildiğini söylüyor. strace dosyası /tmp/ghost_strace_stderr.txt:31-42 aynı fd=3 üstünde send sonrası recvfrom()’ların 162.159.140.229, 149.154.167.91, 104.244.43.131, 151.101.240.159 gibi bambaşka HTTPS akışlarını aldığını gösteriyor. ss -Htin state established '( sport = :443 or dport = :443 )' çıktısı bu uzak IP’lerle aktif 443 bağlantıları doğruluyor. Aynı anda canlı tcpdump gerçek hedef SYN-ACK’ı görüyor:
192.168.1.2:58093 -> 1.1.1.1:443 [S]
1.1.1.1:443 -> 192.168.1.2:58093 [S.]
ama aynı reproducer’daki strace içinde recvfrom(... inet_addr("1.1.1.1")) hiç yok.
Çürüten kanıt: Yok.
Sonuç: confirmed
2. Packet parser / field compare / byte-order hatası
Dosya: satır src/network_core.zig:1475-1509, 1623-1675
Neden şüpheli: Semptom “paket geldi ama match olmadı” gibi görünüyor.
Destekleyen kanıt: Failure yüzeyde silent discard gibi görünüyor.
Çürüten kanıt: capture.log:7-9 içindeki tarihsel akış mevcut filtreyi birebir karşılıyor: 1.1.1.1.443 > 192.168.1.2.60397 [S.]; filterRawPacket() tam bunu kabul edecek şekilde yazılmış. capture.log:7 SYN seq 10152941, capture.log:9 ack 10152942; bu, completeHandshake() içindeki server_ack == client_seq + 1 kontrolünü de geçirir. Canlı tcpdump da SYN src port ve ACK değerlerinin doğru olduğunu gösterdi. zig test src/network_core.zig içindeki raw packet filter enforces destination IP and TCP port tuple testi de geçti.
Sonuç: rejected
3. Firewall / conntrack / iptables scope sorunu
Dosya: satır src/network_core.zig:1430-1454
Neden şüpheli: Tarihsel capture.log içinde kernel RST görülmüş (capture.log:10-11, 20-23, vb.).
Destekleyen kanıt: Kod sadece OUTPUT ve raw/OUTPUT kuralı koyuyor; inbound PREROUTING tarafını hiç scope etmiyor.
Çürüten kanıt: Güncel canlı capture’da sadece SYN ve iki SYN-ACK retransmit var; outbound RST yok, outbound ACK de yok. sudo -n ./verify.sh ayrıca No kernel RST leak raporladı. Yani mevcut failure, RST sızıntısı olmadan da oluşuyor.
Sonuç: rejected
4. Listener sequencing / ready race
Dosya: satır src/network_core.zig:1571-1573, 1942-1950
Neden şüpheli: Listener ready signal ile SYN send arasında sequencing hassas.
Destekleyen kanıt: Thread ve main ayrık ilerliyor.
Çürüten kanıt: Main, listener_ready.wait() ile bloklanıyor; socket SYN’den önce zaten açılmış durumda; raw socket receive queue recvfrom() çağrısından bağımsız var. Problem 5 saniye boyunca deterministik tekrar ediyor.
Sonuç: rejected
5. Verify script / marker sözleşmesi uyuşmazlığı
Dosya: satır verify.sh:58-145, docs/superpowers/plans/2026-04-06-ghost-engine-raw-listener-recovery.md:52-54
Neden şüpheli: Kullanıcı kanıtında [LISTENER READY], [LISTENER WAIT], [PACKET MATCH] marker’ları var.
Destekleyen kanıt: Bu marker’lar current source’da yok; grep yalnız plan dokümanında buldu. verify.sh bunları hiç kontrol etmiyor. Ayrıca verify.sh:140 ve 144 satırlarındaki grep -c ... || echo 0 kalıbı sıfır eşleşmede 0\n0 üretir; canlı verify çıktısındaki fazladan çıplak 0 bundan geliyor.
Çürüten kanıt: Script’in asıl failure sebebi sahte değil; engine gerçekten "[SUCCESS] Targeted SYN-ACK Captured" basmıyor.
Sonuç: confirmed
Not: Bu gerçek bir script/log sözleşme drift’i, ama handshake root cause’u değil.
C. Actual Root Cause
Tek net kök neden şu:
- Kod, AF_INET/SOCK_RAW/IPPROTO_TCP socket’in bind(local_ip:0) ile hedef akış listener’ı gibi davranacağını varsayıyor.
- Bu varsayım yanlış. src_port raw bind’de yok sayılıyor (src/network_core.zig:269, 278-284), ifindex hiç uygulanmıyor (266-287 ve başka kullanım yok), kernel-side flow filter yok.
- Sonuçta fd=3 tüm host TCP gürültüsünü alıyor; hedef akış sadece recvfrom() sonrasında userspace’de ayıklanmaya çalışılıyor.
- Canlı kanıt: tcpdump gerçek 1.1.1.1:443 -> local_ephemeral SYN-ACK’ı görüyor, fakat aynı anda strace bu SYN-ACK’ın fd=3’ten hiç çıkmadığını; onun yerine diğer aktif HTTPS akışlarının dequeue edildiğini gösteriyor.
- Bu yüzden failure parser’da değil; hedef SYN-ACK filterRawPacket()’a hiç ulaşmıyor.
Kod değiştirmedim.
D. Minimal Fix Set
- Mevcut raw fd’ye, listener başlamadan önce kernel-side receive filter ekle.
Neden gerekli: Bug recvfrom() ile filterRawPacket() arasındaki sınırın öncesinde oluşuyor. Userspace filter geç; hedef dışı TCP trafiği önce socket queue’ya giriyor. Minimum güvenilir çözüm, queue’ya sadece {dst_ip=local_ip, src_port=target_port, dst_port=ephemeral_port} uyan paketleri sokmak.
- Başka mantık/parsing/state değişikliği yapma.
Neden gerekli değil: capture.log ve canlı wire kanıtı mevcut parser/ACK check’in doğru tuple geldiğinde işleyeceğini gösteriyor.
E. Verification Plan
- zig build
Beklenen: build temiz geçmeli.
- zig test src/network_core.zig
Beklenen: mevcut 15 test geçmeli.
- sudo -n ./verify.sh 1.1.1.1 443
Beklenen marker’lar:
[SUCCESS] Targeted SYN-ACK Captured
Handshake Completed
[GHOST JITTER]
[MTU] Packet size ...
[CHECKSUM]
Validated inbound packets logged: 1 veya daha büyük
- Paralel wire capture:
sudo -n tcpdump -tt -ni any "host 1.1.1.1 and tcp port 443"
Beklenen sıra:
S
S.
. ACK
P. TLS ClientHello
Yerel R görülmemeli.
- İsteğe bağlı kesin kanıt:
sudo -n strace -tt -f -e trace=recvfrom,sendto ./zig-out/bin/ghost_engine 1.1.1.1 443
Beklenen: recvfrom() artık hedef tuple’ı göstermeli; unrelated 443 akışları görünmemeli ya da dramatik biçimde azalmalı.
F. If Still Uncertain
- Kök nedeni kanıtlamak için ek veri gerekmiyor.
- Kalan tek belirsizlik alt mekanizma: hedef SYN-ACK kernel tarafından fd=3 queue’suna hiç alınmadı mı, yoksa unrelated trafik arasında düşürüldü mü.
- Bu alt belirsizliği tek hamlede bitirecek veri: fd=3 için kernel-level drop/overflow metriği (SO_RXQ_OVFL benzeri) veya geçici pre-filter tuple logu. Bu veri root cause’u değiştirmez; sadece kernel içi kayıp noktasını adlandırır.
