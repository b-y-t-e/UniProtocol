# UniProtocol — instructions for the agent

A .NET 10 library for connecting any two devices over any network, including when both sides
are behind NAT. The address is a public key (`NodeId`), not an IP address.

Current state and usage: `README.md`. Plan and deviations from it: `docs/plan.md` (Polish).

## The rules that are easiest to break

**The core never touches the clock, a socket, or an unseeded RNG.** `BannedSymbols.txt`
makes `DateTime.UtcNow`, `System.Random`, `Socket`, `Dns`, `RandomNumberGenerator`,
`Task.Delay` without a `TimeProvider` and their relatives a **compile error** (`RS0030`).
This is not hygiene — it is the only reason the whole protocol can be tested
deterministically without a network. The dependencies are `IPacketTransport`, `TimeProvider`
and `IRandomSource`.

Adapters at the system boundary (`UdpPacketTransport`, `RelayPacketTransport`,
`MdnsDiscovery`, `RelayServer`, `SecureRandomSource`) disable the rule **locally, with a
comment giving the reason**. Every crossing of that boundary must be visible to
`grep RS0030`.

**Cryptography must not agree only with itself.** Every primitive is checked against the
official vectors (RFC 7748, 8032, 8439, 7693, draft-irtf-cfrg-xchacha), and the handshake
reproduces the Cacophony vector byte for byte, transport keys included. A new primitive
without a reference vector does not go in. Three bugs caught this way passed every
self-consistency test.

**A change to the wire format is a change to the protocol version.** The golden byte vectors
live in `tests/UniProtocol.Protocol.Tests/Packets/PacketFormatTests.cs`. Editing an expected
string to make a test pass is breaking interoperability.

**Reserved bytes are rejected, not ignored.** That way a future version can give them
meaning and know that an old peer refused rather than quietly accepted.

## Conventions

- Hostile input (the network, a ticket pasted by a human) → `bool TryX(...)`. A configuration
  or API misuse → an exception. A failed AEAD tag check is an ordinary event, not an
  exceptional one.
- Comments explain **why**, not what. Where the code departs from an RFC, give the section
  number and the reason.
- Log through `[LoggerMessage]`, not `ILogger.LogDebug(...)`: on the receive path the
  arguments are structs that would otherwise be boxed for every packet.
- Names from the protocol domain (`PathProber`), never `*Helper`/`*Utils`.
- Tests: `Method_Condition_ExpectedResult`.

## Traps in this codebase

- **`stackalloc` is illegal in `async` methods.** Take scratch space from `PacketPool`.
- **The order of static initialisers matters.** `EdwardsPoint.BasePoint` must be declared
  *after* the curve constants — otherwise decompression runs with `d = 0` and produces a
  consistent but entirely different group.
- **In-place decryption only at the same offset** for source and destination. That is the
  only form of overlap every AEAD implementation guarantees, and it is why `Packet.Offset`
  exists.
- **Authenticate before updating the replay window.** The other way round, an attacker
  advances the window with a forged counter and genuine packets start being rejected.
- **Deduplicate handshakes by the Noise ephemeral key**, not by source address. Parallel
  probing delivers the same attempt from several addresses.
- **There are as many receive loops as there are transports — not one.** A session carrying
  traffic over both a relay and a direct address is decrypted from two threads at once. Hence
  the locks in `UniSession` and the `ConcurrentDictionary` for handshake attempts. Every "it
  only runs on one thread anyway" at this layer is false.
- **A failed Noise message read must have no effect.** `TryReadMessage` mixes the ephemeral
  key and the DH results before it can tell the message is forged, and a handshake packet is
  authenticated only by `mac1`, which is keyed by a *public* key. Without a state snapshot,
  one packet from an on-path observer permanently kills a connection that would otherwise
  have succeeded.
- **The identity key is written through a temporary file and `File.Move`.** This is the one
  place in the codebase where an interrupted write destroys something irrecoverably: a
  truncated `node.key` invalidates every ticket ever issued, and `relay.key` invalidates
  every client that pinned it. The staging file gets a random name and an owner-only access
  list at creation — permissions are applied when a file is created, never when an existing
  one is opened, and `File.Move` carries the source's permissions onto the destination.
- **Data from the network or from a human never reaches a `stackalloc` without a length
  bound.** A ticket arrives on the command line; a `stackalloc` proportional to its length is
  a stack overflow no `catch` will save you from.
- **Globs in `.editorconfig`: `**.cs`, not `**/*.cs`** — the latter skips files sitting
  directly in a project directory.

## Building

```bash
dotnet build UniProtocol.slnx      # must be 0 warnings
dotnet test UniProtocol.slnx
```

The relay and mDNS tests use real sockets. mDNS is skipped (`Assert.Skip`) when multicast is
unavailable — containers and corporate networks are normal environments.

## Scope

The milestone order is in `docs/plan.md`. Reordering is fine when the goal demands it — but
record it in the deviations table at the top of that plan, with the reason.
