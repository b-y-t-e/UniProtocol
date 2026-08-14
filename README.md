# UniProtocol

Biblioteka .NET 10 do łączenia **dowolnych dwóch urządzeń** — Windows, Linux, Android
(docelowo także macOS/iOS) — niezależnie od tego, czy stoją w tej samej podsieci, czy po
przeciwnych stronach świata za NAT-em. Połączenie jest dwukierunkowe, strumieniowe
i szyfrowane end-to-end, a ruch idzie **najkrótszą możliwą drogą**: bezpośrednio między
urządzeniami, a nie przez serwer centralny.

Adresem jest klucz publiczny, nie adres IP.

Tak wygląda API **dzisiaj** — działające, z datagramami:

```csharp
await using var relay = RelayPacketTransport.Create(relayAddress, identity);
await relay.WaitUntilConnectedAsync(ct);

await using var endpoint = UniEndpoint.Create(new UniEndpointOptions
{
    Identity = identity,
    RelayTransport = relay,
});

await using var connection = await endpoint.ConnectAsync(ticket, ct);   // albo ConnectViaRelayAsync(nodeId, ct)
await connection.SendDatagramAsync(payload, ct);
```

Strumienie dochodzą w M2 i **nie zmienią** powyższego — `OpenStreamAsync` stanie obok
`SendDatagramAsync`, bo datagram to osobna usługa, a nie etap przejściowy do strumienia.

## Jak to działa

Wzorzec zapożyczony z Tailscale i iroh, w trzech krokach:

1. **Połączenie zawsze się udaje.** ✅ *działa* — relay podnosi połączenie tam, gdzie
   żadna strona nie ma osiągalnego adresu. Relay widzi wyłącznie NodeId i szyfrogram.
2. **Potem awansuje do bezpośredniego.** ⏳ *M4* — hole punching (STUN, sondowanie
   równoległe kandydatów, UPnP/NAT-PMP/PCP, „birthday paradox" dla twardych NAT-ów).
   U Tailscale i iroh tą drogą idzie >90% połączeń. Dziś działa tylko część: adresy
   bezpośrednie i relay są sondowane równolegle i wygrywa pierwszy, który odpowie.
3. **Awans jest niewidoczny.** ✅ *fundament gotowy* — identyfikator sesji jest niezależny
   od ścieżki, a uwierzytelniony pakiet z innej drogi jest przyjmowany jako nowa ścieżka.
   Przełączanie na żywo pod obciążeniem dochodzi z M4.

Nie jest to VPN: nie ma wirtualnych interfejsów ani uprawnień administratora. Biblioteka
daje aplikacji datagramy (i, od M2, strumienie) do konkretnego peera.

## Status

Wczesny etap. Zaimplementowane i zweryfikowane wektorami testowymi:

| Warstwa | Status |
|---|---|
| Kryptografia (X25519, Ed25519, BLAKE2s, ChaCha20-Poly1305, XChaCha20) | gotowe |
| Handshake `Noise_IK_25519_ChaChaPoly_BLAKE2s` | gotowe |
| Tożsamość (NodeId, keystore, CLI) | gotowe |
| Warstwa pakietowa, sesja UDP, datagramy | gotowe |
| Parowanie: ticket, mDNS | gotowe |
| Autoryzacja („tylko zaproszeni") — pole `PairingToken` istnieje, **nic go nie sprawdza** | w planach (`IAuthorizer`) |
| **Relay — łączność z dowolnej sieci, także za NAT** | **gotowe** |
| Strumienie, niezawodność, kontrola przeciążenia | w planach (M2) |
| Hole punching i ścieżki bezpośrednie | w planach (M4) |
| Android | w planach (M6) |

Pełny plan: `docs/plan.md`.

## Zero zależności natywnych

Cała kryptografia jest zarządzana. Powód jest konkretny: `System.Net.Quic` (msquic) nie
działa na Androidzie ani iOS w .NET 10, a .NET nie ma w BCL ani X25519, ani Ed25519, ani
BLAKE2 — natomiast `ChaCha20Poly1305.IsSupported` zależy od platformy. Jedna zarządzana
implementacja oznacza jedną ścieżkę kodu i identyczne zachowanie wszędzie.

Poprawność nie opiera się na tym, że kod zgadza się sam ze sobą — każdy prymityw jest
sprawdzony oficjalnymi wektorami (RFC 7748, RFC 8032, RFC 8439, RFC 7693,
draft-irtf-cfrg-xchacha), a handshake odtwarza wektor Noise z zestawu Cacophony **co do
bajtu**, łącznie z kluczami transportowymi.

## Budowanie

```bash
dotnet build UniProtocol.slnx
dotnet test UniProtocol.slnx
```

Wymaga .NET SDK 10.

## CLI

```bash
unip keygen                       # utwórz tożsamość, wypisz NodeId
unip show                         # pokaż NodeId zapisanej tożsamości
unip listen [--relay <unipr://…>] # szyfrowane echo; wypisuje ticket i ogłasza się w LAN
unip discover                     # wypisz węzły widoczne w sieci lokalnej
unip dial <ticket>                # połącz się ticketem (relay bierze z ticketu)
unip dial <nodeid> <adres>        # połącz się jawnym adresem
unip dial --discover              # połącz się z jedynym węzłem w LAN

unipd --host <nazwa-publiczna>    # serwer relay; wypisuje swój adres unipr://
     [--advertise-port <n>]       # port, na który pukają klienci, gdy inny niż nasłuchiwany
```

Wyniki trafiają na stdout, komunikaty na stderr, więc `unip listen > ticket.txt` zapisuje
dokładnie ticket.

## Jak połączyć dwa urządzenia

**W tej samej sieci — nic nie przepisujesz:**

```
maszyna A:  unip listen
maszyna B:  unip dial --discover
```

Odkrywanie idzie przez mDNS (`_uniprotocol._udp.local`), więc węzeł widać też w
`dns-sd -B _uniprotocol._udp` czy przeglądarce Avahi.

**Przez internet — jedno wklejenie:**

```
maszyna A:  unip listen
            → unip://n/aeaiuttmsw3z7rftmiejmehfr65emjq4ns4oqndtrjokckd3pevqazadarsf…
maszyna B:  unip dial unip://n/aeaiuttmsw3z7rftmiejmehfr65emjq4ns4oqndtrjokckd3pevqazadarsf…
```

**Ticket** pakuje NodeId, adresy kandydatów i opcjonalny token parowania w ~100 znaków —
mieści się w wiadomości na czacie i w kodzie QR. Ma sumę kontrolną, więc literówka daje
natychmiastowy, czytelny błąd zamiast dziesięciosekundowego timeoutu.

Ticket **nie jest tajny**. Tożsamość w nim to klucz publiczny, więc jego znajomość pozwala
się *skontaktować*, nigdy podszyć: podmiana ticketu w locie nie daje MITM, daje połączenie
z innym, widocznie innym NodeId. Ticket potrzebuje integralności, nie poufności — i od tego
jest suma kontrolna.

Ticket niesie też pole na token parowania, ale **żaden kod go dziś nie sprawdza**: peer bez
tokenu jest przyjmowany dokładnie tak samo jak peer z prawidłowym. Pole jest w formacie od
początku, bo dodanie go później łamie wersję wire, a nieegzekwowane — nie. Kto musi
ograniczyć, kto się połączy, robi to na razie nad biblioteką, porównując `NodeId` z własną
listą.

Wszystkie adresy z ticketu są sondowane **równolegle**, a wygrywa pierwszy, który odpowie.
Maszyna z Wi-Fi, Ethernetem i wirtualną kartą ogłasza kilka adresów i większość jest
nieosiągalna z dowolnego konkretnego miejsca — próbowanie po kolei oznaczałoby czekanie na
timeout przy każdym z nich.

**Za NAT-em, obie strony bez publicznego adresu** — potrzebny jeden serwer relay:

```
serwer:     unipd --host relay.twojadomena.pl
            → unipr://aiu3gmh2hj3c…@relay.twojadomena.pl:443

maszyna A:  unip listen --relay unipr://aiu3gmh2hj3c…@relay.twojadomena.pl:443
            → unip://n/aeca6lkj2wnziazl…      (ticket zawiera już relay)

maszyna B:  unip dial unip://n/aeca6lkj2wnziazl…
            → Connected via relay:b4wutvm3
```

Ticket z takiego `listen` niesie adres relaya, więc `dial` nie wymaga żadnej konfiguracji.
Ustaw `UNIP_RELAY`, żeby nie podawać `--relay` za każdym razem.

Adresy bezpośrednie i relay są sondowane **równolegle**: jeśli droga bezpośrednia działa,
połączenie idzie nią i ma jej opóźnienie; jeśli nie, relay przejmuje bez czekania na
timeout. Obie strony zbiegają się do tej samej ścieżki, bo uwierzytelniony pakiet
przychodzący inną drogą jest przyjmowany jako nowa ścieżka.

### Dlaczego serwer jest konieczny

Dwa urządzenia za NAT-em **nie wymienią ze sobą ani jednego pakietu**, dopóki ktoś trzeci
ich sobie nie przedstawi. Nie ma na to protokołu — Tailscale ma DERP, iroh ma swoje relaye.
Stawiasz jeden serwer, obsługuje wszystkie twoje urządzenia, i po zestawieniu połączenia
(od M4) ruch schodzi z niego na drogę bezpośrednią.

Relay jest celowo głupi: uczy się, który węzeł jest na którym połączeniu, i przenosi
nieprzezroczyste bajty. Nie trzyma kluczy peerów, nie terminuje sesji, widzi wyłącznie
NodeId i szyfrogram. Skompromitowany relay może gubić ruch i widzieć, kto z kim rozmawia —
nie może go odczytać ani sfałszować.

Stoi na porcie 443 wystawiony na świat, więc limity są od pierwszego dnia, nie doklejone
później: 10 000 uwierzytelnionych klientów, 512 połączeń czekających na handshake (to ten
limit spotyka zalew, bo połączenie nieuwierzytelnione nie liczy się do pierwszego),
64 połączenia z jednego adresu, 1000 pakietów na sekundę na klienta, kolejka 256 pakietów
i rozłączenie po 90 s ciszy. Wszystkie są w `RelayServerOptions`.

Limit per adres jest tylko podniesieniem kosztu, nie obroną: za CGNAT-em, firmowym wyjściem
czy proxy tysiące niepowiązanych klientów dzieli jeden adres i limit odetnie uczciwe
urządzenia, a napastnik z własnym /64 IPv6 po prostu zmieni adres. Pod zalewem trzyma limit
globalny (`MaximumPendingHandshakes`). Jeśli twoi klienci siedzą za wspólnym adresem —
podnieś go albo wyłącz, ustawiając `int.MaxValue`.

## Serwer relay

**Uwierzytelniany kluczem, nie certyfikatem.** Adres to `unipr://<nodeid>@host:port`, a
klient wykonuje handshake Noise dokładnie do tego klucza. Nie ma czego wystawiać, odnawiać
ani czemu pozwolić wygasnąć, a przejęty CA czy podmieniony rekord DNS nie podstawi innego
serwera.

**Linux (Docker):**

```bash
cd deploy
RELAY_PUBLIC_HOST=relay.twojadomena.pl docker compose up -d --build
docker compose logs unipd | head -1     # adres relaya
```

**Linux (systemd):**

```bash
dotnet publish src/UniProtocol.Server.Host -c Release -o /usr/local/bin
useradd --system uniprotocol
cp deploy/unipd.service /etc/systemd/system/
systemctl enable --now unipd
```

Unit nadaje `CAP_NET_BIND_SERVICE`, więc port 443 działa bez uruchamiania całości jako root.

**Windows:**

```powershell
.\deploy\install-windows.ps1 -PublicHost relay.twojadomena.pl
```

Rejestruje zadanie startowe działające jako `LOCAL SERVICE` z restartem po awarii. To nie
jest usługa Windows w ścisłym sensie — `unipd` jest zwykłą aplikacją konsolową, a `sc.exe`
skierowane na taką aplikację zostanie po chwili ubite przez menedżera usług. Kto chce
prawdziwego wpisu usługi, niech opakuje binarium w NSSM albo WinSW.

**Klucz relaya musi przetrwać restart.** Klienci go przypinają, więc nowy klucz unieważnia
każdy wydany adres relaya. Docker trzyma go w wolumenie, systemd w `StateDirectory`,
Windows w `ProgramData`.

## Zasady projektowe

Rdzeń nie zna `Socket` ani zegara systemowego — zależy wyłącznie od `IPacketTransport`,
`TimeProvider` i `IRandomSource`. To nie jest ozdobnik: dzięki temu cały protokół, razem
z retransmisjami, kontrolą przeciążenia i hole punchingiem, testuje się deterministycznie
w symulatorze ze wstrzykiwanymi stratami i przestawianiem pakietów, a każdy padający
przebieg da się odtworzyć z ziarna.

Reguła jest egzekwowana analizatorem: `BannedSymbols.txt` czyni `DateTime.UtcNow`,
`System.Random`, `Socket` i pokrewne **błędem kompilacji**. Adaptery na granicy systemu
wyłączają regułę punktowo, z komentarzem — więc każde przejście przez granicę widać
w `grep`.

## Licencja

MIT.
