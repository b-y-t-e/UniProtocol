# UniProtocol

A .NET 10 library for connecting **any two devices** — Windows, Linux, Android (macOS and
iOS later) — whether they sit on the same subnet or on opposite sides of the world behind
NAT. The connection is bidirectional, streaming and end-to-end encrypted, and traffic takes
the **shortest path available**: straight between the devices rather than through a central
server.

The address is a public key, not an IP address.

This is the API **today** — working, with datagrams:

```csharp
await using var relay = RelayPacketTransport.Create(relayAddress, identity);
await relay.WaitUntilConnectedAsync(ct);

await using var endpoint = UniEndpoint.Create(new UniEndpointOptions
{
    Identity = identity,
    RelayTransport = relay,
});

await using var connection = await endpoint.ConnectAsync(ticket, ct);   // or ConnectViaRelayAsync(nodeId, ct)
await connection.SendDatagramAsync(payload, ct);
```

Streams arrive in M2 and **will not change** the above — `OpenStreamAsync` will sit next to
`SendDatagramAsync`, because a datagram is a service in its own right and not a stepping
stone to a stream.

## How it works

The pattern is borrowed from Tailscale and iroh, in three steps:

1. **The connection always succeeds.** ✅ *working* — the relay carries it where neither
   side has a reachable address. The relay sees nothing but NodeIds and ciphertext.
2. **Then it is upgraded to direct.** ⏳ *M4* — hole punching (STUN, parallel candidate
   probing, UPnP/NAT-PMP/PCP, the "birthday paradox" trick for hard NATs). At Tailscale and
   iroh that path carries >90% of connections. Only part of it works today: direct addresses
   and the relay are probed in parallel and the first to answer wins.
3. **The upgrade is invisible.** ✅ *foundations in place* — the session identifier is
   independent of the path, and an authenticated packet arriving over a different route is
   adopted as the new path. Switching live under load arrives with M4.

This is not a VPN: there are no virtual interfaces and no administrator rights. The library
hands the application datagrams — and, from M2, streams — to a specific peer.

## Status

Early. Implemented and checked against reference vectors:

| Layer | Status |
|---|---|
| Cryptography (X25519, Ed25519, BLAKE2s, ChaCha20-Poly1305, XChaCha20) | done |
| `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake | done |
| Identity (NodeId, key store, CLI) | done |
| Packet layer, UDP session, datagrams | done |
| Pairing: ticket, mDNS | done |
| Authorisation ("invited peers only") — the `PairingToken` field exists, **nothing checks it** | planned (`IAuthorizer`) |
| **Relay — connectivity from any network, including behind NAT** | **done** |
| Streams, reliability, congestion control | planned (M2) |
| Hole punching and direct paths | planned (M4) |
| Android | planned (M6) |

Full plan: `docs/plan.md` (in Polish).

## No native dependencies

All the cryptography is managed. The reason is specific: `System.Net.Quic` (msquic) does not
work on Android or iOS in .NET 10, and the BCL has neither X25519 nor Ed25519 nor BLAKE2 —
while `ChaCha20Poly1305.IsSupported` varies by platform. One managed implementation means one
code path and identical behaviour everywhere.

Correctness does not rest on the code agreeing with itself. Every primitive is checked
against the official vectors (RFC 7748, RFC 8032, RFC 8439, RFC 7693,
draft-irtf-cfrg-xchacha), and the handshake reproduces a Noise vector from the Cacophony
suite **byte for byte**, transport keys included.

## Building

```bash
dotnet build UniProtocol.slnx
dotnet test UniProtocol.slnx
```

Requires the .NET 10 SDK.

## CLI

```bash
unip keygen                       # create an identity, print its NodeId
unip show                         # print the NodeId of the stored identity
unip listen [--relay <unipr://…>] # encrypted echo; prints a ticket and advertises on the LAN
unip discover                     # list nodes visible on the local network
unip dial <ticket>                # connect using a ticket (the relay comes from the ticket)
unip dial <nodeid> <address>      # connect to an explicit address
unip dial --discover              # connect to the only node on the LAN

unipd --host <public-name>        # relay server; prints its own unipr:// address
     [--advertise-port <n>]       # the port clients reach it on, when it differs from the bound one
```

Results go to stdout and messages to stderr, so `unip listen > ticket.txt` writes exactly
the ticket.

## Connecting two devices

**On the same network — nothing to copy:**

```
machine A:  unip listen
machine B:  unip dial --discover
```

Discovery runs over mDNS (`_uniprotocol._udp.local`), so the node also shows up in
`dns-sd -B _uniprotocol._udp` or an Avahi browser.

**Over the internet — one paste:**

```
machine A:  unip listen
            → unip://n/aeaiuttmsw3z7rftmiejmehfr65emjq4ns4oqndtrjokckd3pevqazadarsf…
machine B:  unip dial unip://n/aeaiuttmsw3z7rftmiejmehfr65emjq4ns4oqndtrjokckd3pevqazadarsf…
```

A **ticket** packs the NodeId, candidate addresses and an optional pairing token into about
a hundred characters — small enough for a chat message and for a QR code. It carries a
checksum, so a typo produces an immediate, readable error instead of a ten-second timeout.

A ticket **is not a secret**. The identity in it is a public key, so knowing one lets you
*contact* a node, never impersonate it: swapping a ticket in transit does not give an
attacker a machine-in-the-middle, it gives a connection to a different, visibly different
NodeId. A ticket needs integrity, not confidentiality — which is what the checksum is for.

A ticket also carries a field for a pairing token, but **no code checks it today**: a peer
presenting no token is accepted exactly like one presenting the right token. The field is in
the format from the start because adding it later would break the wire version, whereas
leaving it unenforced does not. Anyone who has to restrict who may connect does it above
this library for now, by comparing `NodeId` against their own list.

Every address in a ticket is probed **in parallel**, and the first to answer wins. A machine
with Wi-Fi, Ethernet and a virtual adapter advertises several addresses and most are
unreachable from any given place — trying them in turn would mean waiting out a timeout on
each.

**Behind NAT, with neither side publicly addressable** — one relay server is needed:

```
server:     unipd --host relay.example.com
            → unipr://aiu3gmh2hj3c…@relay.example.com:443

machine A:  unip listen --relay unipr://aiu3gmh2hj3c…@relay.example.com:443
            → unip://n/aeca6lkj2wnziazl…      (the ticket already carries the relay)

machine B:  unip dial unip://n/aeca6lkj2wnziazl…
            → Connected via relay:b4wutvm3
```

A ticket produced by that `listen` carries the relay's address, so `dial` needs no
configuration at all. Set `UNIP_RELAY` to avoid passing `--relay` every time.

Direct addresses and the relay are probed **in parallel**: if a direct path works the
connection takes it and gets its latency; if not, the relay takes over without waiting out a
timeout. Both sides converge on the same path, because an authenticated packet arriving over
a different route is adopted as the new path.

### Why a server is necessary

Two devices behind NAT **cannot exchange a single packet** until something else introduces
them. No protocol works around that — Tailscale has DERP, iroh has its relays. You run one
server, it serves all your devices, and once a connection is up (from M4) the traffic moves
off it onto a direct path.

The relay is deliberately stupid: it learns which node is on which connection and moves
opaque bytes between them. It holds no peer keys, terminates no sessions, and sees only
NodeIds and ciphertext. A compromised relay can drop traffic and see who talks to whom; it
can neither read that traffic nor forge it.

It sits on port 443 exposed to the internet, so the limits are there from day one rather than
bolted on later: 10,000 authenticated clients, 512 connections waiting to complete a
handshake (that is the limit a flood actually meets, because an unauthenticated connection
does not count towards the first one), 64 connections from one address, 1,000 packets per
second per client, a 256-packet queue, and disconnection after 90 seconds of silence. All of
them live in `RelayServerOptions`.

The per-address limit raises the cost of the easy case; it is not a defence. Behind CGNAT, a
corporate egress or a proxy, thousands of unrelated clients share one address and the limit
will cut off honest devices, while an attacker with their own IPv6 /64 simply moves. Under a
flood the limit that holds is the global one (`MaximumPendingHandshakes`). If your clients
sit behind a shared address, raise the per-address limit or switch it off with
`int.MaxValue`.

## The relay server

**Authenticated by key, not by certificate.** The address is `unipr://<nodeid>@host:port`,
and the client performs a Noise handshake to exactly that key. There is nothing to issue,
renew or let expire, and a compromised CA or a hijacked DNS record cannot substitute a
different server.

**Linux (Docker):**

```bash
cd deploy
RELAY_PUBLIC_HOST=relay.example.com docker compose up -d --build
docker compose logs unipd | head -1     # the relay address
```

**Linux (systemd):**

```bash
dotnet publish src/UniProtocol.Server.Host -c Release -o /usr/local/bin
useradd --system uniprotocol
cp deploy/unipd.service /etc/systemd/system/
systemctl enable --now unipd
```

The unit grants `CAP_NET_BIND_SERVICE`, so port 443 works without running the whole thing as
root.

**Windows:**

```powershell
.\deploy\install-windows.ps1 -PublicHost relay.example.com
```

This registers a scheduled task running as `LOCAL SERVICE` with restart on failure. It is
not a Windows service in the strict sense — `unipd` is a plain console application, and
`sc.exe` pointed at one gets killed by the service control manager shortly after start.
Anyone who wants a genuine service entry should wrap the binary with NSSM or WinSW.

**The relay's key must survive restarts.** Clients pin it, so a new key invalidates every
relay address you have handed out. Docker keeps it in a volume, systemd in `StateDirectory`,
Windows in `ProgramData`.

## Design rules

The core knows nothing about `Socket` or the system clock — it depends only on
`IPacketTransport`, `TimeProvider` and `IRandomSource`. This is not decoration: it is what
lets the whole protocol, retransmission and congestion control and hole punching included,
be tested deterministically in a simulator with injected loss and reordering, with every
failing run reproducible from a seed.

The rule is enforced by an analyser: `BannedSymbols.txt` makes `DateTime.UtcNow`,
`System.Random`, `Socket` and their relatives a **compile error**. Adapters at the system
boundary disable it locally, with a comment — so every crossing of that boundary is visible
to `grep`.

## Licence

MIT.
