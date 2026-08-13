# UniProtocol — biblioteka P2P dla .NET 10

> **Ten dokument to plan pierwotny.** Bieżący stan opisuje `README.md`. Poniżej lista
> odstępstw, które zapadły w trakcie realizacji — same milestone'y i uzasadnienia poniżej
> pozostają aktualne.
>
> ### Odstępstwa od planu
>
> | Zmiana | Powód |
> |---|---|
> | **M3 (relay) zrobiony przed M2 (strumienie)** | „Łączy się z dowolnej sieci" to główny wymóg; relay przenosi nieprzezroczyste pakiety, więc nie wymaga strumieni. M2 wraca po M3. |
> | **Relay uwierzytelniany kluczem (`unipr://<nodeid>@host:port`), nie TLS-em** | Zero certyfikatów do wystawiania, odnawiania i wygasania; ten sam model zaufania co reszta systemu. Koszt: brak mimikry HTTPS wobec głębokiej inspekcji. |
> | **Dodane parowanie: `UniTicket` + mDNS (poza planem)** | Bez tego nie dało się prosto połączyć dwóch maszyn. Ticket niesie NodeId, adresy i relay w ~100 znakach. |
> | **`PathEndpoint` zamiast `NetworkAddress` w transporcie** | Pakiet przez relay nie ma sensownego adresu IP — jest adresowany do NodeId. To fundament awansu relay→direct z M4. |
> | **Koordynator na razie zbędny** | Przy jednym relayu to on jest punktem spotkania: wie, kto jest podłączony. Koordynator wraca przy wielu regionach relay. |
> | **STUN przesunięty do M4** | Służy ścieżkom bezpośrednim, nie łączności przez relay. |
> | **Public API Analyzer odłożony do M7** | Ręczne utrzymywanie `PublicAPI.Shipped.txt` przez całe 0.x to koszt bez korzyści. Do tego czasu: „domyślnie `internal`". |
> | **BLAKE2b pominięty** | Nic go nie używa; Noise wymaga tylko BLAKE2s. |

## Context

Repozytorium `D:\work\sources\UniProtocol` jest puste (brak commitów). Cel: biblioteka .NET 10 pozwalająca połączyć **dowolne dwa urządzenia** (Windows↔Windows, Windows↔Android, Android↔Android, Linux↔…) niezależnie od tego, czy są w tej samej podsieci, czy po dwóch stronach świata za NAT-em — z **dwukierunkowym strumieniowaniem danych** i ruchem idącym **najkrótszą, bezpośrednią drogą** (jak Tailscale/iroh), a nie przez serwer centralny.

Docelowe zachowanie: połączenie **zawsze się udaje** (fallback przez relay), a następnie w tle **awansuje do połączenia bezpośredniego** bez przerywania otwartych strumieni. Serwer pomocniczy jest potrzebny tylko do odnalezienia się peerów i jako awaryjny przekaźnik — nigdy nie widzi plaintextu.

### Research — wnioski, które ukształtowały projekt

- **Tailscale**: każde połączenie startuje przez DERP i jest oportunistycznie podnoszone do direct; protokół `disco` po UDP z osobnymi kluczami; STUN w każdym regionie relay; wykrywanie NAT EIM vs EDM; „birthday paradox" (~256 gniazd, 50% sukcesu <2 s) dla twardych NAT-ów; UPnP-IGD/NAT-PMP/PCP; >90–94% połączeń bezpośrednich. ([how-nat-traversal-works](https://tailscale.com/blog/how-nat-traversal-works), [nat-traversal-improvements-pt-1](https://tailscale.com/blog/nat-traversal-improvements-pt-1))
- **ICE**: zbierz wszystkich kandydatów, sonduj równolegle, wybierz najniższe RTT, trzymaj fallback gorący. ([RFC 8445](https://datatracker.ietf.org/doc/rfc8656/history/))
- **iroh**: home relay per endpoint, hole punching koordynowany przez relay, ~90% skuteczności, bezstanowe tanie relaye, „dial keys, not IPs". ([docs.iroh.computer](https://docs.iroh.computer/what-is-iroh), [iroh vs libp2p](https://www.iroh.computer/blog/comparing-iroh-and-libp2p))
- **Odrzucone**: libp2p (~70% hole-punch, przeciążone API), WebRTC/SIPSorcery (ciężki stos ICE+DTLS+SCTP, SCTP wolniejsze niż QUIC, słaba kontrola nad traversal). ([porównanie ARK Builders](https://www.ark-builders.dev/blog/p2p-networking-webrtc-libp2p-iroh/))

### Ograniczenia techniczne (zweryfikowane)

- `System.Net.Quic`/msquic **nie działa na Android/iOS** w .NET 10 (`IsSupported` tylko windows/linux/osx) → własny transport nad UDP. ([QUIC overview](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/quic/quic-overview), [QuicListener.IsSupported](https://learn.microsoft.com/en-us/dotnet/api/system.net.quic.quiclistener.issupported?view=net-10.0))
- .NET 10 **nie ma X25519/Ed25519** w BCL (dodano tylko PQC: MLKem/MLDsa/SlhDsa), a `ChaCha20Poly1305.IsSupported` jest zależne od platformy → kryptografia własna, zarządzana, z opcjonalną ścieżką szybką przez BCL. ([What's new — libraries](https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/libraries), [issue 52482](https://github.com/dotnet/runtime/issues/52482))

### Decyzje użytkownika

1. Własny protokół nad UDP, 100% managed, zero zależności natywnych (Noise_IK jak WireGuard + własna warstwa strumieni).
2. Pełny self-hosted stack w repo: klient + koordynator + STUN + relay, jeden binarny serwer.
3. v1: Windows, Linux, Android. iOS/macOS/przeglądarka później, ale nie mogą być wyprojektowane out.
4. API typu endpoint + strumienie (jak iroh/QUIC), tożsamość = klucz publiczny.
5. **SOLID + clean code** — patrz sekcja „Zasady projektowe", obowiązująca w każdym milestone.

---

## Zasady projektowe (SOLID / clean code) — nienegocjowalne

Te reguły nie są ozdobnikiem: to one czynią ten protokół testowalnym bez sieci.

- **DIP jako fundament testowalności.** Rdzeń nie zna `Socket` ani zegara systemowego. Zależy wyłącznie od `IPacketTransport` (wyślij/odbierz datagram) i `TimeProvider`. Produkcja wstrzykuje `UdpPacketTransport` + `TimeProvider.System`; testy wstrzykują `SimNetwork` + `FakeTimeProvider`. **Zakaz `DateTime.UtcNow`, `Environment.TickCount`, `new Socket()` gdziekolwiek poza warstwą adapterów** — pilnowane analizatorem (Roslyn banned-symbols, `BannedSymbols.txt`).
- **SRP — jedna klasa, jeden powód do zmiany.** Konkretny podział zamiast klas-molochów: `LossDetector` (RFC 9002 detekcja), `RttEstimator`, `AckManager`, `SendQueue`, `ReceiveBuffer`, `FlowController`, `StreamRegistry`, `PathManager`, `CandidateGatherer`, `PathProber`, `PathSelector`. `UniConnection` **koordynuje** te obiekty, nie implementuje ich logiki. Twardy limit: plik > 400 linii albo klasa > 7 pól to sygnał do podziału, nie do wyjątku.
- **OCP przez strategie.** Wymienne polityki za interfejsami: `ICongestionController` (NewReno → CUBIC → BBR bez dotykania recovery), `INodeDiscovery` (koordynator / statyczny / mDNS / DNS), `IAuthorizer`, `IKeyStore`, `IPlatformNetwork`, `IUniTelemetry`. Dodanie CUBIC czy discovery przez DNS = nowa klasa, zero zmian w istniejących.
- **ISP — wąskie interfejsy.** `IPacketTransport` ma dwie metody, nie dwanaście. Zamiast jednego `IPlatformNetwork` z ośmioma odpowiedzialnościami: `INetworkMonitor`, `IWakeGuard`, `IMulticastGuard`, `INetworkBinder` — Android implementuje wszystkie, desktop tylko pierwszy.
- **LSP w kryptografii.** `ManagedChaCha20Poly1305` i `BclChaCha20Poly1305` są w pełni wymienne za `IAeadCipher`; ten sam zestaw wektorów testowych przechodzi obie implementacje (test parametryzowany po implementacjach — jeśli któraś zawiedzie, to jest naruszenie LSP i błąd blokujący).
- **Brak stanu globalnego i statycznych singletonów.** Wszystko schodzi z `UniEndpoint`, który jest korzeniem kompozycji. Umożliwia to uruchomienie 50 endpointów w jednym procesie testowym.
- **Fail fast, jasne błędy.** Własna hierarchia wyjątków (`UniProtocolException` → `HandshakeFailedException`, `PeerUnreachableException`, `StreamResetException`) z kodami błędów protokołu. Zero pustych `catch`. Parsery zwracają `bool TryParse(...)`, nie rzucają na wrogim wejściu.
- **Nazwy z domeny protokołu**, nie z implementacji: `PathProber`, nie `Helper`/`Manager2`/`Utils`. Zero klas `*Utils`/`*Helper` w publicznym API.
- **Immutability domyślnie.** Typy wiadomości i konfiguracja jako `readonly record struct` / `sealed record`. Stan mutowalny wyłącznie wewnątrz pętli aktora połączenia (jeden wątek logiczny — brak locków w hot path).
- **Testy jako dokumentacja.** Nazewnictwo `Metoda_Warunek_OczekiwanyWynik`. Każdy błąd znaleziony przez fuzzing/symulator staje się nazwanym testem regresji z ziarnem (seed).
- **Publiczne API minimalne.** Domyślnie `internal`; `InternalsVisibleTo` dla testów. Każdy typ publiczny to zobowiązanie na lata. `PublicAPI.Shipped.txt` (Roslyn Public API Analyzer) pilnuje przypadkowych rozszerzeń.
- **Komentarze wyjaśniają „dlaczego", nie „co".** Wyjątek: przy każdym odstępstwie od RFC obowiązkowy komentarz z numerem sekcji RFC i uzasadnieniem.

---

## A. Układ rozwiązania

`UniProtocol.slnx` w korzeniu. Central Package Management (`Directory.Packages.props`), wspólny `Directory.Build.props`: `net10.0`, `Nullable enable`, `TreatWarningsAsErrors`, `IsAotCompatible=true`, `EnableTrimAnalyzer`, deterministyczne buildy, `.editorconfig` z regułami stylu jako błędami.

| Projekt | TFM | Odpowiedzialność |
|---|---|---|
| `src/UniProtocol.Crypto` | `net10.0` | X25519, Ed25519, BLAKE2s/2b, ChaCha20-Poly1305, XChaCha20, HKDF, maszyna stanów Noise_IK |
| `src/UniProtocol.Protocol` | `net10.0` | Typy wire dzielone klient+serwer: nagłówki, ramki, varint, disco, ramki relay, STUN, rekordy podpisane |
| `src/UniProtocol` | `net10.0` | Biblioteka klienta: endpoint, połączenia, strumienie, ścieżki, discovery |
| `src/UniProtocol.PortMapping` | `net10.0` | UPnP-IGD / NAT-PMP / PCP (własna impl.; [Mono.Nat](https://www.nuget.org/packages/Mono.Nat) jako referencja) |
| `src/UniProtocol.Platform.Android` | `net10.0-android` | `INetworkMonitor`, `IWakeGuard`, `IMulticastGuard`, `INetworkBinder`, foreground service |
| `src/UniProtocol.Server` | `net10.0` | Koordynator + STUN + relay jako biblioteki |
| `src/UniProtocol.Server.Host` | `net10.0` | `unipd` — jeden binarny serwer (Kestrel), AOT, Docker |
| `src/UniProtocol.Cli` | `net10.0` | `unip` — keygen, netcheck, dial, echo, relay-ping |
| `tests/UniProtocol.TestKit` | `net10.0` | Symulator deterministyczny: `VirtualTimeProvider`, `SimNetwork`, `SimNat` |
| `tests/*.Tests` | `net10.0` | xUnit v3 + testy własnościowe |
| `tests/UniProtocol.Integration.Tests` | `net10.0` | Testcontainers + Linux netns |
| `tests/UniProtocol.Fuzz` | `net10.0` | SharpFuzz per parser |
| `bench/UniProtocol.Benchmarks` | `net10.0` | BenchmarkDotNet |
| `samples/Chat`, `samples/FileSend`, `samples/MauiDemo` | — | Dema |

**Rdzeń jest single-TFM `net10.0`, celowo nie multi-target.** Biblioteka `net10.0` ładuje się na `net10.0-android`; specyfika platformy siedzi za interfejsami rejestrowanymi **jawnie** w `UniEndpointOptions` (zero refleksji → trimming/AOT bezpieczne). Późniejsze `Platform.Apple` i klient `browser` (tylko relay) wchodzą bez dotykania rdzenia — to OCP na poziomie solucji.

## B. Protokół warstwa po warstwie

### B1. Tożsamość
- **NodeId = klucz publiczny Ed25519 (32 B)**, tekstowo base32 bez paddingu (52 znaki).
- **Jeden 32-bajtowy seed, dwa klucze.** Statyk Noise (X25519) wyprowadzony z tego samego seeda; klucz X25519 to biracjonalne odwzorowanie Ed25519 (`u = (1+y)/(1−y)`), więc peer wyprowadza klucz DH z samego NodeId. Walidacja obowiązkowa: odrzucenie niekanonicznego `y`, punktów małego rzędu, zerowego wyniku DH. Podpisy z separacją domen (`"uniprotocol/v1/<ctx>" || msg`).
- **Klucz disco** — efemeryczny X25519 per proces (jak w Tailscale). Sondowanie ścieżek nigdy nie dotyka klucza tożsamości ani sesji.

### B2. Kryptografia — implementacja zarządzana
Powód: brak X25519/Ed25519 w BCL i zmienne `ChaCha20Poly1305.IsSupported`. `UniProtocol.Crypto` dostarcza:
- ChaCha20 z `Vector256/512` (fallback skalarny), Poly1305 na `UInt128`.
- X25519 (styl ref10, drabina Montgomery'ego, `cswap` w stałym czasie), Ed25519 (edwards25519, tablica prekomputowana, SHA-512 z BCL).
- BLAKE2s (hash Noise) + BLAKE2b, HKDF nad BLAKE2s.
- Za `IAeadCipher` opcjonalna ścieżka szybka do BCL gdy `IsSupported` — włączana benchmarkiem, nie domyślnie.

### B3. Płaszczyzna sterowania (koordynator)
- Jedno połączenie HTTPS/WebSocket per endpoint. Auth: nonce serwera → podpis klienta → krótkotrwały ticket HMAC do reconnectów.
- **Podpisany `NodeRecord`** (kanoniczny CBOR): `{ NodeId, DiscoKey, HomeRelayId, Endpoints[], Seq, Expiry, Sig }`, `Endpoint = { Kind: Local|Stun|PortMapped|Manual|Nat64, IP, Port, LastSeen }`. Koordynator **nie może sfałszować** rekordu, może tylko go nie wydać; `Seq` chroni przed rollbackiem.
- Operacje: `Publish`, `Resolve`, `Subscribe` (push), `RelayTicket`, `WakePeer` (hook push dla Androida — API w v1, implementacja później).
- `INodeDiscovery` wymienne: `CoordinatorDiscovery` (domyślne), `StaticDiscovery`, `MdnsDiscovery` (`_uniprotocol._udp.local`), później DNS/pkarr.
- **Sygnalizacja `CallMeMaybe` idzie płaszczyzną danych relaya**, nie koordynatorem — relay i tak jest zawsze podłączony, a koordynator zostaje poza ścieżką latencji.

### B4. Ramkowanie UDP
Jedno gniazdo per rodzina adresów niesie handshake, dane, disco i STUN. Bajt typu tak dobrany, by demux był jednoznaczny: STUN zaczyna się `0x00/0x01`, **nasze typy zajmują `0x20–0x2F`**. Wszystko little-endian przez `BinaryPrimitives`.

```
0x20 HandshakeInit                                    offset  size
  type                                                   0      1
  version (=1)                                           1      1
  reserved                                               2      2
  senderIndex (u32)                                      4      4
  ephemeral X25519 pub                                   8     32
  enc(static pub) + tag                                 40     48
  enc(payload: TAI64N ts + transport params + ticket)   88    var+16
  mac1 = BLAKE2s-128(key=H(LABEL_MAC1||S_pub_r), ...)          16
  mac2 = BLAKE2s-128(key=cookie, ...)                          16

0x21 HandshakeResponse
  type|version|reserved(2)|senderIndex(4)|receiverIndex(4)
  ephemeral(32)|enc(transport params)+tag|mac1(16)|mac2(16)

0x23 CookieReply
  type|reserved(3)|receiverIndex(4)|nonce(24)|enc(cookie 16)+tag(16)

0x22 Data                                             offset  size
  type                                                   0      1
  flags (bit0 = key phase)                               1      1
  reserved                                               2      2
  receiverIndex (u32)  <-- IDENTYFIKATOR SESJI           4      4
  counter (u64) = numer pakietu = nonce                  8      8
  ciphertext                                            16      n
  tag Poly1305                                        16+n     16
  AAD = bajty[0..16). Nonce = 4 zera || counter(LE). Narzut 32 B.
```

`receiverIndex` identyfikuje **sesję, nie ścieżkę** — to jest mechanizm, dzięki któremu migracja relay→direct jest darmowa i niewidoczna dla aplikacji. `counter` to jedna przestrzeń numerów pakietów ciągnąca się przez rekeye (ACK-i pozostają ważne przy zmianie klucza).

**Noise**: `Noise_IK_25519_ChaChaPoly_BLAKE2s`, prolog `"UniProtocol v1" || applicationProtocolId`, `Split()` → klucze send/recv.

### B5. Ramki transportowe (wewnątrz ciphertextu)
Varinty w stylu QUIC (1/2/4/8 B). Payload = sklejone ramki.

| Kod | Ramka |
|---|---|
| `0x00` | PADDING |
| `0x01` | PING |
| `0x02` | ACK `{largestAcked, ackDelay, rangeCount, firstRange, (gap,len)*}` |
| `0x08–0x0F` | STREAM (bity: OFF/LEN/FIN, kodowanie jak QUIC) |
| `0x10/0x11` | RESET_STREAM / STOP_SENDING |
| `0x12–0x14` | MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS |
| `0x15–0x17` | *_BLOCKED |
| `0x18` | DATAGRAM (zawodny, semantyka RFC 9221) |
| `0x19/0x1A` | PATH_CHALLENGE / PATH_RESPONSE |
| `0x1B` | SETTINGS |
| `0x1C` | CLOSE `{errorCode, frameType, reason}` |

**Wykrywanie strat: RFC 9002 dosłownie** — `kPacketThreshold=3`, `kTimeThreshold=9/8`, PTO z backoffem, estymacja RTT (latest/min/smoothed, rttvar 1/4, srtt 1/8). Wybrane, bo to jedyny w pełni wyspecyfikowany, sprawdzony w boju zestaw dla dokładnie tego modelu pakietu, oraz bo reguła „nigdy nie retransmituj numeru pakietu — retransmituj **ramki** w nowym pakiecie" jest twardym warunkiem migracji ścieżek.

**Kontrola przeciążenia: `ICongestionController`; NewReno (RFC 9002 §7) w M2, CUBIC (RFC 9438) w M7.** NewReno najpierw, bo ~150 linii i priorytet to poprawność; CUBIC dla uczciwości wobec TCP; BBRv2 po v1. **Pacing od pierwszego dnia** (token bucket `1.25·cwnd/srtt`, burst max 10 pakietów) — niespacowane serie UDP to przyczyna #1 strat na routerach konsumenckich.

**Flow control**: okna połączenia i strumienia (4 MiB / 1 MiB, auto-tuning: podwojenie gdy >½ okna zużyte w 2·RTT, sufit 16 MiB). Okna sterowane bezpośrednio konsumpcją `PipeReader`, więc backpressure aplikacji staje się backpressure na drucie bez dodatkowej księgowości.

**MTU**: start 1200, **DPLPMTUD (RFC 8899)** sondami PING+PADDING 1200 → 1372 → 1452 → 1492, wykrywanie blackhole tylko po stratach dużych pakietów, ponowne sondowanie co 10 min i przy każdej zmianie ścieżki. `DontFragment=true`; **nigdy fragmentacji IP ani aplikacyjnej**. `conn.MaxDatagramSize` publiczne i zmienne; ścieżka relay przypięta do 1200.

### B6. Disco (sondowanie ścieżek) — pieczętowane osobno
```
0x24 Disco: type(1) | senderDiscoKey(32) | nonce(24) | XChaCha20-Poly1305 box
klucz = HKDF-BLAKE2s(X25519(discoSk, peerDiscoPk))
Ping{txid(12), nodeId(32), padding do 1200}
Pong{txid(12), observedIp(16), observedPort(2)}   <-- darmowy STUN od każdego peera
CallMeMaybe{endpoints[]}                          <-- przez relay
```
Sondy dopełnione do 1200 B: współczynnik amplifikacji <1, a przy okazji dowód MTU.

### B7. Relay (`UniRelay`, odpowiednik DERP)
- TLS/TCP na **443** z `Upgrade: uniprotocol-relay` (przechodzi przez proxy korporacyjne via CONNECT). Opcjonalna szybka ścieżka UDP dla self-hosted/LAN.
- Ramki: `type(1) | len(u24 BE) | payload` — `ServerKey`, `ClientInfo` (zapieczętowane Noise IK do klucza serwera, ten sam kod Noise), `ServerInfo`, `SendPacket{dstNodeId|body}`, `RecvPacket{srcNodeId|body}`, `KeepAlive`, `NotePreferred`, `PeerGone`, `Ping/Pong`, `Health`, `RestartingSoon`.
- Relay jest **bezstanowy per para**: trzyma tylko `NodeId → connection`. Body to nieprzezroczysty payload UDP — relay widzi NodeId i szyfrogram, nigdy plaintext.
- Każdy region relay uruchamia też responder STUN (RFC 8489 BINDING + XOR-MAPPED-ADDRESS). Wybór home relay = najniższa mediana z 5 pingów, publikowana w `NodeRecord`.

## C. Zarządzanie ścieżkami

**Zbieranie kandydatów** (`CandidateGatherer`): (1) wszystkie lokalne adresy unicast × port (v4 + v6 GUA/ULA/link-local); (2) mapowania STUN z ≥2 serwerów na 2 portach — ten sam port z różnych serwerów ⇒ NAT endpoint-independent; (3) UPnP-IGD / NAT-PMP / PCP równolegle, wygrywa pierwszy, dzierżawa 2 h odnawiana w połowie; (4) adresy zaobserwowane przez peera w `Pong` (dokładniejsze niż STUN — to mapowanie dla *tej* ścieżki); (5) synteza NAT64 przez `ipv4only.arpa`; (6) ścieżka relay, zawsze.

**Przebieg połączenia (twarda zasada: nigdy nie czekamy na punching):**
1. `ConnectAsync` rozwiązuje `NodeRecord`, otwiera/reużywa home relay peera, wykonuje Noise IK **przez relay** → połączenie zdatne po ~1 RTT do relaya. Strumienie płyną natychmiast.
2. Obie strony wymieniają `CallMeMaybe` przez relay.
3. Obie strony jednocześnie rozsyłają dopełnione Pingi disco do wszystkich kandydatów ze wszystkich lokalnych gniazd (simultaneous open przebija obie strony).
4. Brak Pongu w 1,5 s **i** wykryty lokalnie NAT typu EDM ⇒ **birthday attack**: współdzielona pula 256 dodatkowych gniazd UDP (limit globalny, nie per peer), sondy w okolice zaobserwowanego portu, peer robi to samo; budżet raz na 30 s na peera.
5. Test hairpin przy starcie; gdy hairpinning nie działa, tłumimy kandydatów WAN wobec peerów dzielących nasz adres WAN i polegamy na LAN.

**Wybór ścieżki** (`PathSelector`): najniższe EWMA RTT wśród **potwierdzonych** ścieżek, histereza 20% i 250 ms dwell timer przeciw migotaniu; relay zawsze gorący jako standby. Kadencja sond: 100 ms w trakcie punchingu, 2 s niepotwierdzone, 5 s aktywna direct (to również keepalive NAT), 30 s standby.

**Migracja bez zrywania strumieni** — sens istnienia `receiverIndex`:
- Nadawca trzyma `PathHandle{Socket, RemoteEndPoint}`; zmiana ścieżki to podmiana uchwytu. Offsety strumieni, numery pakietów i klucze nietknięte, więc awans relay→direct jest niewidoczny dla aplikacji.
- Każdy uwierzytelniony pakiet z nieznanego adresu wyzwala PATH_CHALLENGE/PATH_RESPONSE przed przełączeniem ruchu wychodzącego; do walidacji obowiązuje limit 3× odebranych bajtów (anty-amplifikacja).
- **Stan CC/RTT per ścieżka** (`PathCcState`, cache 30 s) zamiast resetu z RFC 9002 — migotanie relay↔direct nie może restartować slow startu. Każdy wysłany pakiet zapamiętuje swoją ścieżkę, więc próbki RTT aktualizują tylko tę ścieżkę.
- Wykrywanie rebindingu: uwierzytelnione pakiety z nowego adresu, `NetworkChange.NetworkAddressChanged` / `ConnectivityManager` na Androidzie, okresowy STUN własnego mapowania ⇒ ponowne zebranie, publikacja, `CallMeMaybe`.
- Keepalive: 15 s direct (poniżej typowego timeoutu ~30 s mapowania UDP), 5 s po świeżo utraconym mapowaniu, 60 s relay TCP; idle timeout sesji 5 min.

## D. Model współbieżności i wydajności (.NET)

- **Gniazda**: dwa per endpoint (osobno v4 i v6, ten sam numer portu gdy się da — dual-mode ukrywa adres lokalny i komplikuje multicast/Androida). Jedna dedykowana pętla odbioru per gniazdo na `Socket.ReceiveMessageFromAsync(Memory<byte>, …, CancellationToken)` → `ValueTask`. **Nie surowe `SocketAsyncEventArgs`** — API ValueTask *jest* cache'owanym SAEA pod spodem i nie alokuje, o ile w locie jest **dokładnie jedno** odbieranie per gniazdo; równoległość bierze się z wielu gniazd, nie z równoległych odbiorów na jednym.
- **Bufory**: `PacketPool` nad przypiętymi slabami 64 KiB (`GC.AllocateUninitializedArray(pinned: true)`) ciętymi na pakiety 2048 B; `Packet` to struktura-uchwyt z jawnym `Return()`, wykrywanie wycieków i double-free w DEBUG. Unika przypinania z `ArrayPool` w trakcie I/O.
- **Deszyfrowanie w miejscu** w pętli odbioru (ChaCha20 to szyfr strumieniowy: weryfikacja tagu, potem XOR in-place) — zero kopii od bufora gniazda do parsera ramek. Zabezpieczone heurystyką `MaxInlineDecryptBytes`, która przy jednym zachłannym peerze przenosi pracę do pętli połączenia.
- **Aktor per połączenie**: `UniConnection` ma ograniczony `Channel<Packet>` (drop-oldest przy presji datagramów) i jedno zadanie pętli: odbiór → ramki → timery → wysyłka. Brak locków w hot path, naturalna serializacja, i dokładnie ten kształt, którego potrzebuje symulator deterministyczny (pętla sterowana ręcznie). Dispatch = jedno `ConcurrentDictionary<uint, UniConnection>` po `receiverIndex`.
- **Timery**: żadnych `System.Threading.Timer` per połączenie. Jedno hierarchiczne koło czasowe per endpoint (sloty 1 ms, 512 wpisów) napędzane pętlą endpointu. Cały czas przez `TimeProvider`.
- **Strumienie**: `UniStream : Stream` z pełnym API `Memory<T>` **oraz** `PipeReader Input` / `PipeWriter Output`. Odbiór = `Pipe` dla bajtów w kolejności + mały `SortedList<ulong,Packet>` na out-of-order; konsumpcja Pipe napędza MAX_STREAM_DATA. Wysyłka = `Pipe`; `WriteAsync` kończy się na buforze, `FlushAsync` na akceptacji przez CC/flow control.
- **Cele wymuszone testami**: 0 alokacji/pakiet w stanie ustalonym (`GC.GetAllocatedBytesForCurrentThread()` przez 10 k pakietów), ≥2 Gbps single stream na loopbacku x64, p99 dodanej latencji <100 µs.
- **Znany sufit**: brak zarządzanego `sendmmsg`; UDP GSO/GRO tylko przez `Socket.SetRawSocketOption(SOL_UDP, UDP_SEGMENT/UDP_GRO)` na Linuksie — benchmark w M7, bez uzależniania projektu.
- **Serwer**: Kestrel `ConnectionHandler` nad `IConnectionListener`, przekazywanie pipe-to-pipe, ograniczony `Channel` per klient; cel 100 k bezczynnych klientów na węzeł.

## E. Android

Granica abstrakcji: cztery wąskie interfejsy (ISP) wstrzykiwane jawnie przez `UniEndpointOptions.Platform`.
- `INetworkMonitor` — `ConnectivityManager.RegisterNetworkCallback` (uchwyty per-sieć, flagi VPN/metered) zamiast `NetworkInterface.GetAllNetworkInterfaces()`, które na Androidzie bywa niekompletne.
- `IWakeGuard` — `PowerManager.PARTIAL_WAKE_LOCK`, trzymany **wyłącznie** podczas handshake'u i serii punchingu, nigdy ciągle.
- `IMulticastGuard` — `WifiManager.MulticastLock` dla mDNS, `WifiLock(WIFI_MODE_FULL_LOW_LATENCY)` w czasie transferu.
- `INetworkBinder` — przypięcie gniazd do wifi vs komórki. W v1 `ConnectivityManager.BindProcessToNetwork` (zgrubne, ale pewne); `Network.BindSocket(FileDescriptor)` wymaga przejścia po FD z `Socket.Handle` — **spike w M0, to znany trudny punkt**.
- **Doze**: gniazda przeżywają, ale timery są odraczane, a sieć blokowana. Rdzeń nie może zakładać, że timery wystrzeliły: `IdleDetector` porównuje zegar monotoniczny z ściennym i przy skoku natychmiast rewaliduje ścieżki zamiast ufać stanowi timerów. Dla trwałej osiągalności: `UniProtocolForegroundService` (`foregroundServiceType="dataSync"`) + snippety manifestu; alternatywnie `WakePeer` → FCM high-priority.
- Keepalive adaptacyjne: 15 s foreground, 60 s background, tylko relay + TCP keepalive w tle.
- Pakowanie: `net10.0-android`, minSdk 26, deskryptory ILLink; sample MAUI dowodzi historii pakowania.

## F. Bezpieczeństwo

- **Przechowywanie kluczy**: `IKeyStore`; `FileKeyStore` (0600, `ProtectedData` na Windows), Android `EncryptedSharedPreferences` z kluczem AES opakowanym w Keystore (surowych seedów Ed25519 nie da się trzymać w Android Keystore do użycia X25519), Keychain na Apple później.
- **Autoryzacja**: Noise IK daje wzajemne uwierzytelnienie kryptograficzne; polityka ponad tym to `IAuthorizer` (`AllowList`, `AllowAll`, `NetworkTicketAuthorizer`). Wybór: **tokeny zdolności w payloadzie handshake'u** — `{NodeId, NetworkId, Caps, NotAfter}` podpisane kluczem roota sieci, przypiętym u peerów. Skutek: autoryzacja weryfikowana **offline, peer-to-peer**; koordynator jest zaufany tylko w kwestii *admisji*, a wdrożenie o wysokich wymaganiach może podpisywać tickety air-gapped.
- **Replay**: handshake — znacznik TAI64N z regułą największego znacznika per peer (jak WireGuard) + 2-minutowy LRU par `(staticPub, ephemeral)`; dane — przesuwne okno 8192 bitów per sesja per generacja klucza; disco — cache 12-bajtowych txid.
- **DoS**: `mac1` obowiązkowy (tanie odrzucenie obcych bez żadnego DH), `mac2`/cookie pod obciążeniem (cookie = MAC adresu źródłowego zapieczętowany XChaCha20 pod 2-minutowym sekretem, jak WireGuard); odpowiedź handshake ≤ rozmiar żądania, sondy dopełnione do 1200 B, limit 3× przed walidacją. Relay: jedno połączenie per NodeId, limity per IP, token bucket (10 Mbps / 1000 pps), kolejki drop-oldest, max ramka 64 KiB, ticket członkostwa w sieciach zamkniętych. Koordynator: rate limiting ASP.NET, każdy zapis podpisany.
- **Rekey**: nowy handshake po 2^24 pakietach lub 120 s; odrzucenie po 2^32 / 180 s; bit fazy klucza w `flags` przełącza generacje bez psucia pakietów poza kolejnością. **Bez 0-RTT w v1.**
- **Hook PQ**: zarezerwowany bajt wersji + TLV rozszerzenia handshake'u na `IKpsk2` z PSK z ML-KEM (`System.Security.Cryptography.MLKem` jest już w .NET 10). Teraz darmowe, później drogie.
- Krypto zamknięte w jednym projekcie: pomocniki stałoczasowe, `CryptographicOperations.FixedTimeEquals`/`ZeroMemory`, zero rozgałęzień zależnych od sekretu, cel fuzzingu per parser.

## G. Testowanie

1. **Wektory kryptograficzne**: RFC 8439, RFC 8032, RFC 7748 (z wektorami małego rzędu), RFC 7693, wektory Noise (cacophony) dla `Noise_IK_25519_ChaChaPoly_BLAKE2s`, Wycheproof.
2. **Symulacja deterministyczna — budowana *przed* warstwą niezawodności, nie po.** Rdzeń nie dotyka `Socket`, rozmawia z `IPacketTransport`. `SimNetwork` daje łącza z rozkładem latencji, jitterem, token bucketem pasma, stratami, przestawianiem, duplikacją, korupcją, MTU i jednokierunkowymi blackhole'ami — wszystko z zasianego Xoshiro256\*\*, na jednowątkowej pętli zdarzeń z `VirtualTimeProvider`. Scenariusz 60-sekundowy wykonuje się w milisekundach. Asercje własnościowe na 10 k ziaren nocnie: integralność danych, ostateczne dostarczenie, brak zakleszczeń, niezmienniki flow control, brak reużycia numeru pakietu. Każde padające ziarno staje się trwałym testem regresji.
3. **Scenariusze chaosu** w symulatorze: rekey podczas serii strat, migracja w środku transferu 100 MB/s, MTU 1500→1280 w locie, śmierć relaya, restart peera, skok zegara ściennego (doze).
4. **Symulator NAT** (`SimNat`): full-cone / restricted / port-restricted / symmetric-sequential / symmetric-random, hairpin on/off, czas życia mapowania. Macierz 5×5 z **jawną tabelą oczekiwanej skuteczności** per komórka (np. symmetric×symmetric ⇒ tylko relay, albo ≥50% w 3 s z birthday punchingiem). Czyste testy jednostkowe, bez kontenerów.
5. **Integracja**: Linux netns (`ip netns` + `iptables MASQUERADE` = prawdziwa semantyka NAT) na CI Ubuntu; Testcontainers dla `unipd`; smoke test Windows↔Linux↔emulator Androida.
6. **Fuzzing**: SharpFuzz na nagłówku pakietu, parserze ramek, parserze ramek relay, parserze STUN, czytniku Noise; korpus w repo, nocnie.
7. **Złote wektory wire** zapisane szesnastkowo dla każdego typu pakietu i ramki; zmiana któregokolwiek wymaga podbicia wersji protokołu. To jest strażnik interoperacyjności.
8. **Benchmarki i soak**: BenchmarkDotNet (AEAD, kodek ramek, pula pakietów, przepustowość/latencja loopback, `[MemoryDiagnoser]`), godzinny soak 100 połączeń z asercją płaskiej pamięci.

## H. Milestone'y (każdy samodzielnie demonstrowalny)

- **M0 — Szkielet + krypto (1–2 tyg.).** Solucja, CI (build/test/analizatory na Windows+Linux), `.editorconfig` + banned symbols + Public API Analyzer, zarządzane X25519/Ed25519/BLAKE2s/ChaCha20-Poly1305/XChaCha + Noise IK zielone na oficjalnych wektorach. *Równolegle: spike wiązania gniazd na Androidzie.* Demo: `unip keygen`, suita wektorów.
- **M1 — Warstwa pakietowa + sesja loopback (1–2 tyg.).** `IPacketTransport`, pula pakietów, kodek nagłówka, handshake Noise po UDP, szyfrowane echo. Demo: `unip echo` między dwoma procesami. ← M0
- **M2 — Niezawodność + strumienie (3–4 tyg., największy).** **Najpierw** TestKit/`SimNetwork`, potem ramki, recovery RFC 9002, NewReno + pacing, flow control, `UniStream : Stream`, datagramy, zamykanie. Demo: transfer 1 GB przez symulowane łącze 100 ms/1% z wykresem przepustowości. ← M1
- **M3 — Relay + koordynator (2–3 tyg.).** `unipd` jako jeden binarny serwer (koordynator WS/REST + STUN + relay), transport relay w kliencie, wybór home relay, publish/resolve. Demo: **dwie maszyny za prawdziwymi NAT-ami rozmawiają przez relay** — pierwsze demo przez internet; od tego miejsca każdy milestone jest wysyłalny. ← M1, M2
- **M4 — Ścieżki bezpośrednie i hole punching (3–4 tyg.).** Zbieranie kandydatów, disco, klient STUN, sondowanie równoległe, wybór ścieżki, PATH_CHALLENGE + migracja, awans relay→direct w locie, keepalive, wykrywanie typu NAT, testy macierzy NAT. Demo: połączenie startuje przez relay i awansuje do direct w <1 s **bez żadnego zakłócenia strumienia**; `unip netcheck`. ← M3
- **M5 — Twarde NAT-y + port mapping (2 tyg.).** UPnP-IGD/NAT-PMP/PCP, birthday punching, wykrywanie hairpin, NAT64. Demo: symmetric↔symmetric w netns i na prawdziwym telefonie w 4G. ← M4
- **M6 — Android (2–3 tyg.).** Pakiet platformy, sample MAUI, foreground service, callbacki sieciowe, przeżycie doze, hook push-wake. Demo: telefon↔desktop czat + wysyłka pliku, ekran zgaszony 10 min, wznowienie. ← M4
- **M7 — Hardening i wydajność (3 tyg.).** CUBIC, DPLPMTUD, cookie DoS, rate limity, fuzzing, audyt zero-alloc, eksperyment GSO, benchmarki, soak, pakiety NuGet, dokument specyfikacji protokołu. Demo: raport benchmarków + paczki preview.
- **M8 (po v1).** iOS/macOS, klient przeglądarkowy (WebTransport, tylko relay), discovery przez DNS/pkarr, BBR, hybrydowe PQ, multipath.

Realistycznie **4–6 miesięcy skupionej pracy do M7**. Ratunkiem harmonogramu jest niezmiennik „relay zawsze działa": wszystko od M3 wzwyż jest wysyłalne, nawet gdyby łączność bezpośrednia się cofnęła.

## Weryfikacja

Po każdym milestone:
- `dotnet test` — jednostkowe + własnościowe (10 k ziaren nocnie w CI, 100 ziaren w PR).
- `dotnet run --project bench` — brak regresji przepustowości/alokacji względem zapisanej linii bazowej.
- **M1+**: `unip echo` między dwoma lokalnymi procesami.
- **M2+**: scenariusz symulatora „1 GB przez 100 ms RTT / 1% strat" kończy się z integralnością danych i przepustowością w granicach 80% teoretycznego BDP.
- **M3+**: dwie realne maszyny (Windows + Linux VPS) łączą się przez `unipd`; `unip dial <nodeid>` pokazuje typ ścieżki.
- **M4+**: `unip netcheck` raportuje typ NAT i mapowania; test integracyjny netns potwierdza awans relay→direct w trakcie aktywnego transferu **bez utraty ani jednego bajta** (sprawdzane hashem SHA-256 strumienia).
- **M6+**: ręczny test na urządzeniu — telefon (LTE) ↔ desktop (za NAT domowym), transfer pliku, wygaszenie ekranu na 10 min, wznowienie bez ponownego łączenia z poziomu aplikacji.

## Pierwsze pliki do utworzenia (kolejność)

1. `Directory.Build.props`, `Directory.Packages.props`, `.editorconfig`, `BannedSymbols.txt`, `UniProtocol.slnx`
2. `src/UniProtocol.Crypto/Curve25519/X25519.cs`, `Ed25519.cs`, `Aead/IAeadCipher.cs`, `Noise/NoiseIkHandshake.cs`
3. `src/UniProtocol.Protocol/PacketHeader.cs`, `Frames/FrameReader.cs`, `Frames/FrameWriter.cs`
4. `src/UniProtocol/Abstractions/IPacketTransport.cs`, `Transport/UniConnection.cs`, `Streams/UniStream.cs`
5. `tests/UniProtocol.TestKit/SimNetwork.cs`, `VirtualTimeProvider.cs`, `SimNat.cs`
6. `src/UniProtocol/Paths/PathManager.cs`, `CandidateGatherer.cs`, `PathProber.cs`, `PathSelector.cs`

## Największe ryzyka

1. **Poprawność i stałoczasowość zarządzanego X25519/Ed25519** — klasyczna pułapka. Mitygacja: wierny port struktury ref10, wektory wyczerpujące + Wycheproof, izolowany projekt do audytu.
2. **Warstwa niezawodności/CC to prawdziwa implementacja protokołu**; jej błędy ujawniają się tylko przy stratach i przestawieniach. Mitygacja: symulator deterministyczny powstaje *przed* algorytmem i bramkuje milestone.
3. **Migracja przy współbieżności** — ACK-i z porzuconej ścieżki psujące RTT, resety cwnd, okna replay przez ścieżki. Mitygacja: stan CC/RTT per ścieżka, tagowanie pakietu ścieżką, jawne testy chaosu. To najsubtelniejsza część całego projektu.
4. **Sieć w tle na Androidzie i wiązanie gniazd per-sieć.** Spike w M0 — nie odkrywać tego w M6.
5. **Skuteczność NAT traversal jest empiryczna** — żadne laboratorium nie osiągnie 90%. Mitygacja: liczniki `IUniTelemetry` (typ ścieżki w t=1 s/10 s, wynik punchingu wg klasy NAT) od M4 i program beta.
6. **Nadużycia i koszt relaya** — ograniczone kolejki, tickety i rate limity od pierwszego dnia, nie doklejane później.
