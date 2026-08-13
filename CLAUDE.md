# UniProtocol — instrukcje dla agenta

Biblioteka .NET 10 do łączenia dowolnych dwóch urządzeń przez dowolną sieć, także gdy obie
strony są za NAT-em. Adresem jest klucz publiczny (`NodeId`), nie adres IP.

Stan i sposób użycia: `README.md`. Plan i odstępstwa: `docs/plan.md`.

## Reguły, które łamie się najłatwiej

**Rdzeń nie dotyka zegara, gniazda ani nieziarnowanego RNG.** `BannedSymbols.txt` czyni
`DateTime.UtcNow`, `System.Random`, `Socket`, `Dns`, `RandomNumberGenerator`,
`Task.Delay` bez `TimeProvider` i pokrewne **błędem kompilacji** (`RS0030`). To nie jest
higiena — to jedyny powód, dla którego cały protokół da się testować deterministycznie bez
sieci. Zależności to `IPacketTransport`, `TimeProvider` i `IRandomSource`.

Adaptery na granicy systemu (`UdpPacketTransport`, `RelayPacketTransport`, `MdnsDiscovery`,
`RelayServer`, `SecureRandomSource`) wyłączają regułę **punktowo, z komentarzem
uzasadniającym**. Każde przejście przez granicę ma być widoczne w `grep RS0030`.

**Kryptografia nie może zgadzać się wyłącznie sama ze sobą.** Każdy prymityw jest
sprawdzony oficjalnymi wektorami (RFC 7748, 8032, 8439, 7693, draft-irtf-cfrg-xchacha),
a handshake odtwarza wektor Cacophony co do bajtu — łącznie z kluczami transportowymi.
Nowy prymityw bez wektora referencyjnego nie wchodzi. Trzy błędy złapane tą drogą
przechodziły wszystkie testy self-consistency.

**Zmiana formatu wire = zmiana wersji protokołu.** Złote wektory bajtowe siedzą
w `tests/UniProtocol.Protocol.Tests/Packets/PacketFormatTests.cs`. Poprawianie oczekiwanego
ciągu, żeby test przeszedł, to zerwanie interoperacyjności.

**Bajty zarezerwowane są odrzucane, nie ignorowane.** Dzięki temu przyszła wersja może im
nadać znaczenie i wiedzieć, że stary peer odmówił, a nie po cichu przyjął.

## Konwencje

- Wejście wrogie (sieć, ticket wklejony przez człowieka) → `bool TryX(...)`. Błąd
  konfiguracji lub użycia API → wyjątek. Nieudana weryfikacja tagu AEAD to zdarzenie
  normalne, nie wyjątkowe.
- Komentarze tłumaczą **dlaczego**, nie co. Przy odstępstwie od RFC — numer sekcji
  i uzasadnienie.
- Logowanie przez `[LoggerMessage]`, nie `ILogger.LogDebug(...)`: na ścieżce odbioru
  argumenty to struktury, które inaczej byłyby pakowane przy każdym pakiecie.
- Nazwy z domeny protokołu (`PathProber`), nigdy `*Helper`/`*Utils`.
- Testy: `Metoda_Warunek_OczekiwanyWynik`.

## Pułapki tej bazy kodu

- **`stackalloc` jest nielegalny w metodach `async`.** Scratch bierz z `PacketPool`.
- **Kolejność inicjalizatorów statycznych ma znaczenie.** `EdwardsPoint.BasePoint` musi być
  zadeklarowany *po* stałych krzywej — inaczej dekompresja liczy z `d = 0` i powstaje
  spójna, ale całkowicie inna grupa.
- **Deszyfrowanie in-place tylko z tym samym offsetem** źródła i celu. To jedyna forma
  nakładania się gwarantowana przez wszystkie implementacje AEAD; stąd `Packet.Offset`.
- **Uwierzytelnienie przed aktualizacją okna anty-replay.** Odwrotnie atakujący przesunie
  okno sfałszowanym licznikiem i prawdziwe pakiety zaczną być odrzucane.
- **Deduplikacja handshake'u po kluczu efemerycznym Noise**, nie po adresie źródłowym.
  Sondowanie równoległe dostarcza tę samą próbę z wielu adresów.
- **Globy w `.editorconfig`: `**.cs`, nie `**/*.cs`** — to drugie pomija pliki leżące
  bezpośrednio w katalogu projektu.

## Budowanie

```bash
dotnet build UniProtocol.slnx      # musi być 0 ostrzeżeń
dotnet test UniProtocol.slnx
```

Testy relaya i mDNS używają prawdziwych gniazd. mDNS pomija się (`Assert.Skip`), gdy
multicast jest niedostępny — kontenery i sieci korporacyjne to normalne środowiska.

## Zakres

Kolejność milestone'ów jest w `docs/plan.md`. Zmiana kolejności jest w porządku, jeśli tego
wymaga cel — ale odnotuj ją w tabeli odstępstw na górze tego planu wraz z powodem.
