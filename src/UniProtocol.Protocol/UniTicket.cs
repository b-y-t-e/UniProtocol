using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using UniProtocol.Crypto.Hashing;
using UniProtocol.Protocol.Identity;
using UniProtocol.Protocol.Relay;

namespace UniProtocol.Protocol;

/// <summary>
/// Everything one device needs in order to reach another: an identity and where it might
/// currently be found.
/// </summary>
/// <remarks>
/// <para>
/// A ticket is the unit of pairing. It fits in a QR code, a chat message or a
/// double-click-to-select string, and it is what turns "connect these two machines" into a
/// single copy and paste.
/// </para>
/// <para>
/// <strong>A ticket is not a secret.</strong> The identity in it is a public key, so
/// knowing a ticket lets you <em>contact</em> a node, never impersonate it: an attacker who
/// swaps the ticket in transit does not get a machine-in-the-middle, they get a connection
/// to a different, visibly different, NodeId. What a ticket does need is integrity, and the
/// checksum catches the accidental corruption that transcription introduces. Where
/// contacting a node should itself require an invitation, the ticket carries a pairing
/// token, and <em>that</em> is secret — but see <see cref="PairingToken"/>: the field is
/// carried, not yet enforced.
/// </para>
/// <para>
/// The addresses are hints that only work when the peer happens to be directly reachable.
/// A ticket that also names a relay is sufficient on its own, from anywhere: the relay
/// knows where the node is, so connectivity stops depending on either side having a public
/// address.
/// </para>
/// <para>
/// Wire format, following the <c>unip://n/</c> prefix as base32:
/// </para>
/// <code>
///   offset  size  field
///        0     1  version (1)
///        1     1  flags: bit 0 expiry, bit 1 pairing token, bit 2 relay
///        2    32  NodeId
///       34     1  address count
///       35     n  addresses: kind (4 or 6), 4 or 16 address bytes, 2 port bytes
///      ...     4  expiry, Unix seconds       (only when flagged)
///      ...    16  pairing token              (only when flagged)
///      ...    35+ relay: NodeId(32), port(2), host length(1), host  (only when flagged)
///      ...     2  checksum over everything above
/// </code>
/// </remarks>
public sealed record UniTicket
{
    /// <summary>The URI scheme and path prefix a ticket is written with.</summary>
    public const string UriPrefix = "unip://n/";

    /// <summary>Size of a pairing token in bytes.</summary>
    public const int PairingTokenSizeInBytes = 16;

    private const byte CurrentVersion = 1;
    private const byte ExpiryFlag = 0x01;
    private const byte PairingTokenFlag = 0x02;
    private const byte RelayFlag = 0x04;
    /// <summary>
    /// The most addresses a ticket can carry.
    /// </summary>
    /// <remarks>
    /// Public because anyone assembling a ticket has to respect it. A machine with several
    /// adapters — Wi-Fi, Ethernet, a hypervisor bridge, a VPN, IPv6 privacy addresses that
    /// come and go — can easily hold more addresses than this, and a builder that hands them
    /// all over would produce a ticket that <see cref="Encode"/> refuses. Past a handful the
    /// extra candidates cost more to probe than they are worth anyway.
    /// </remarks>
    public const int MaximumAddressCount = 16;

    private const int ChecksumSizeInBytes = 2;
    private const int MaximumRelayHostLength = 255;

    /// <summary>
    /// The largest a ticket can be: every optional field present, every address in its
    /// 19-byte IPv6 form, and the longest host name the one-byte length prefix can express.
    /// </summary>
    private const int MaximumEncodedSizeInBytes =
        35                                                    // version, flags, NodeId, address count
        + (MaximumAddressCount * 19)                          // addresses
        + 4                                                   // expiry
        + PairingTokenSizeInBytes
        + NodeId.SizeInBytes + 3 + MaximumRelayHostLength     // relay
        + ChecksumSizeInBytes;

    /// <summary>
    /// The longest text that can encode a ticket. Anything longer is rejected before it is
    /// decoded, because <see cref="TryParse"/> decodes onto the stack and the text comes
    /// from a command line, a chat message or a QR code — that is, from anywhere.
    /// </summary>
    private static readonly int MaximumTextLength = Base32.GetEncodedLength(MaximumEncodedSizeInBytes);

    /// <summary>The identity to connect to.</summary>
    public required NodeId NodeId { get; init; }

    /// <summary>Addresses the node may be reachable at, best first.</summary>
    public IReadOnlyList<NetworkAddress> Addresses { get; init; } = [];

    /// <summary>When the ticket stops being offered, if it is time-limited.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// A secret carried for a node that will accept invited peers only.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Nothing enforces this yet.</strong> The field is carried across the wire and
    /// round-trips through <see cref="Encode"/> and <see cref="TryParse"/>, but no code
    /// reads it when deciding whether to accept a handshake — a peer that presents no token,
    /// or the wrong one, is accepted exactly like a peer that presents the right one. Setting
    /// it today buys no access control whatsoever.
    /// </para>
    /// <para>
    /// It exists now because the wire format is versioned and adding a field later is a
    /// breaking change, whereas leaving a documented, unenforced one is not. Enforcement
    /// arrives with <c>IAuthorizer</c>, which checks it during the handshake; until that
    /// exists, a node that must restrict who may connect has to do it above this library, by
    /// checking <see cref="Identity.NodeId"/> against its own list.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> PairingToken { get; init; }

    /// <summary>
    /// The relay this node can be reached through when none of its addresses work.
    /// </summary>
    /// <remarks>
    /// This is what makes a ticket sufficient on its own. The addresses are hints that fail
    /// whenever the peer is behind NAT — which is nearly always — and the relay is the
    /// fallback that does not.
    /// </remarks>
    public RelayAddress? Relay { get; init; }

    /// <summary>Indicates whether <paramref name="now"/> is past <see cref="ExpiresAt"/>.</summary>
    public bool IsExpired(DateTimeOffset now) => ExpiresAt is { } expiry && now > expiry;

    /// <summary>Renders the ticket as a <c>unip://n/…</c> URI.</summary>
    public override string ToString() => UriPrefix + Base32.Encode(Encode());

    /// <summary>Encodes the ticket to its binary form.</summary>
    public byte[] Encode()
    {
        if (Addresses.Count > MaximumAddressCount)
        {
            throw new InvalidOperationException(
                $"A ticket may carry at most {MaximumAddressCount} addresses; this one has {Addresses.Count}.");
        }

        byte flags = 0;
        if (ExpiresAt is not null)
        {
            flags |= ExpiryFlag;
        }

        if (Relay is not null)
        {
            // The host length is written as a single byte, so a longer name would be
            // truncated into a ticket that parses cleanly and names the wrong server.
            if (Encoding.UTF8.GetByteCount(Relay.Host) is 0 or > MaximumRelayHostLength)
            {
                throw new InvalidOperationException(
                    $"A relay host name must be between 1 and {MaximumRelayHostLength} bytes in UTF-8.");
            }

            flags |= RelayFlag;
        }

        if (!PairingToken.IsEmpty)
        {
            if (PairingToken.Length != PairingTokenSizeInBytes)
            {
                throw new InvalidOperationException(
                    $"A pairing token must be exactly {PairingTokenSizeInBytes} bytes.");
            }

            flags |= PairingTokenFlag;
        }

        byte[] buffer = new byte[MeasureEncodedSize(flags)];
        Span<byte> destination = buffer;

        destination[0] = CurrentVersion;
        destination[1] = flags;
        NodeId.CopyTo(destination[2..]);
        destination[34] = (byte)Addresses.Count;

        int offset = 35;
        foreach (NetworkAddress address in Addresses)
        {
            offset += WriteAddress(address, destination[offset..]);
        }

        if ((flags & ExpiryFlag) != 0)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                destination[offset..],
                (uint)ExpiresAt!.Value.ToUnixTimeSeconds());
            offset += 4;
        }

        if ((flags & PairingTokenFlag) != 0)
        {
            PairingToken.Span.CopyTo(destination[offset..]);
            offset += PairingTokenSizeInBytes;
        }

        if ((flags & RelayFlag) != 0)
        {
            Relay!.NodeId.CopyTo(destination[offset..]);
            offset += NodeId.SizeInBytes;

            BinaryPrimitives.WriteUInt16BigEndian(destination[offset..], (ushort)Relay.Port);
            offset += 2;

            int hostLength = Encoding.UTF8.GetByteCount(Relay.Host);
            destination[offset++] = (byte)hostLength;
            offset += Encoding.UTF8.GetBytes(Relay.Host, destination[offset..]);
        }

        WriteChecksum(destination[..offset], destination[offset..]);

        return buffer;
    }

    /// <summary>
    /// Parses a ticket from a <c>unip://n/…</c> URI, a bare base32 ticket, or a bare NodeId.
    /// </summary>
    /// <remarks>
    /// A bare NodeId is accepted because it is a complete ticket with no address hints, and
    /// because people will paste one. It parses to a ticket whose <see cref="Addresses"/>
    /// is empty.
    /// </remarks>
    public static bool TryParse(ReadOnlySpan<char> text, [NotNullWhen(true)] out UniTicket? ticket)
    {
        ticket = null;
        text = text.Trim();

        if (text.StartsWith(UriPrefix, StringComparison.OrdinalIgnoreCase))
        {
            text = text[UriPrefix.Length..];
        }

        if (text.IsEmpty || text.Length > MaximumTextLength)
        {
            return false;
        }

        if (NodeId.TryParse(text, out NodeId bareNodeId))
        {
            ticket = new UniTicket { NodeId = bareNodeId };
            return true;
        }

        Span<byte> decoded = stackalloc byte[MaximumEncodedSizeInBytes];

        return Base32.TryDecode(text, decoded, out int written) && TryDecode(decoded[..written], out ticket);
    }

    /// <summary>Parses a ticket, throwing on malformed input.</summary>
    public static UniTicket Parse(ReadOnlySpan<char> text)
        => TryParse(text, out UniTicket? ticket)
            ? ticket
            : throw new FormatException("The text is not a valid UniProtocol ticket.");

    /// <summary>Decodes a ticket from its binary form.</summary>
    public static bool TryDecode(ReadOnlySpan<byte> source, [NotNullWhen(true)] out UniTicket? ticket)
    {
        ticket = null;

        if (source.Length < 35 + ChecksumSizeInBytes
            || source[0] != CurrentVersion)
        {
            return false;
        }

        byte flags = source[1];
        if ((flags & ~(ExpiryFlag | PairingTokenFlag | RelayFlag)) != 0)
        {
            return false;
        }

        int bodyLength = source.Length - ChecksumSizeInBytes;

        Span<byte> expectedChecksum = stackalloc byte[ChecksumSizeInBytes];
        WriteChecksum(source[..bodyLength], expectedChecksum);

        if (!expectedChecksum.SequenceEqual(source[bodyLength..]))
        {
            return false;
        }

        NodeId nodeId = NodeId.FromPublicKey(source.Slice(2, NodeId.SizeInBytes));
        int addressCount = source[34];

        if (addressCount > MaximumAddressCount)
        {
            return false;
        }

        List<NetworkAddress> addresses = new(addressCount);
        int offset = 35;

        for (int i = 0; i < addressCount; i++)
        {
            if (!TryReadAddress(source[..bodyLength], ref offset, out NetworkAddress address))
            {
                return false;
            }

            addresses.Add(address);
        }

        DateTimeOffset? expiresAt = null;
        if ((flags & ExpiryFlag) != 0)
        {
            if (bodyLength - offset < 4)
            {
                return false;
            }

            expiresAt = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(source[offset..]));
            offset += 4;
        }

        byte[] pairingToken = [];
        if ((flags & PairingTokenFlag) != 0)
        {
            if (bodyLength - offset < PairingTokenSizeInBytes)
            {
                return false;
            }

            pairingToken = source.Slice(offset, PairingTokenSizeInBytes).ToArray();
            offset += PairingTokenSizeInBytes;
        }

        RelayAddress? relay = null;
        if ((flags & RelayFlag) != 0)
        {
            if (bodyLength - offset < NodeId.SizeInBytes + 3)
            {
                return false;
            }

            NodeId relayNodeId = NodeId.FromPublicKey(source.Slice(offset, NodeId.SizeInBytes));
            offset += NodeId.SizeInBytes;

            int relayPort = BinaryPrimitives.ReadUInt16BigEndian(source[offset..]);
            offset += 2;

            int hostLength = source[offset++];

            if (hostLength == 0 || bodyLength - offset < hostLength)
            {
                return false;
            }

            relay = new RelayAddress
            {
                NodeId = relayNodeId,
                Host = Encoding.UTF8.GetString(source.Slice(offset, hostLength)),
                Port = relayPort,
            };

            offset += hostLength;
        }

        if (offset != bodyLength)
        {
            // Trailing bytes mean the encoding is not canonical, and a ticket with two
            // spellings is a ticket an allow-list cannot reliably compare.
            return false;
        }

        ticket = new UniTicket
        {
            NodeId = nodeId,
            Addresses = addresses,
            ExpiresAt = expiresAt,
            PairingToken = pairingToken,
            Relay = relay,
        };

        return true;
    }

    private int MeasureEncodedSize(byte flags)
    {
        int size = 35 + ChecksumSizeInBytes;

        foreach (NetworkAddress address in Addresses)
        {
            size += address.IsIPv4 ? 7 : 19;
        }

        if ((flags & ExpiryFlag) != 0)
        {
            size += 4;
        }

        if ((flags & PairingTokenFlag) != 0)
        {
            size += PairingTokenSizeInBytes;
        }

        if ((flags & RelayFlag) != 0)
        {
            size += NodeId.SizeInBytes + 3 + Encoding.UTF8.GetByteCount(Relay!.Host);
        }

        return size;
    }

    private static int WriteAddress(NetworkAddress address, Span<byte> destination)
    {
        ReadOnlySpan<byte> bytes = address.AddressSpan;

        if (address.IsIPv4)
        {
            destination[0] = 4;
            bytes[12..].CopyTo(destination[1..]);
            BinaryPrimitives.WriteUInt16BigEndian(destination[5..], address.Port);
            return 7;
        }

        destination[0] = 6;
        bytes.CopyTo(destination[1..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[17..], address.Port);
        return 19;
    }

    private static bool TryReadAddress(ReadOnlySpan<byte> source, ref int offset, out NetworkAddress address)
    {
        address = default;

        if (offset >= source.Length)
        {
            return false;
        }

        byte kind = source[offset];

        if (kind == 4)
        {
            if (source.Length - offset < 7)
            {
                return false;
            }

            Span<byte> mapped = stackalloc byte[NetworkAddress.AddressSizeInBytes];
            mapped[..10].Clear();
            mapped[10] = 0xFF;
            mapped[11] = 0xFF;
            source.Slice(offset + 1, 4).CopyTo(mapped[12..]);

            address = NetworkAddress.FromIPv6Bytes(
                mapped,
                BinaryPrimitives.ReadUInt16BigEndian(source[(offset + 5)..]));

            offset += 7;
            return true;
        }

        if (kind == 6)
        {
            if (source.Length - offset < 19)
            {
                return false;
            }

            address = NetworkAddress.FromIPv6Bytes(
                source.Slice(offset + 1, 16),
                BinaryPrimitives.ReadUInt16BigEndian(source[(offset + 17)..]));

            offset += 19;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Writes a two-byte checksum over <paramref name="body"/>.
    /// </summary>
    /// <remarks>
    /// Not a security measure — the ticket is already tied to a public key, and an attacker
    /// who can rewrite it can recompute this. Its job is to turn a mistyped character into
    /// "that ticket is corrupted" instead of a ten-second connection timeout against an
    /// identity that never existed.
    /// </remarks>
    private static void WriteChecksum(ReadOnlySpan<byte> body, Span<byte> destination)
    {
        Span<byte> digest = stackalloc byte[Blake2s.HashSizeInBytes];
        Blake2s.HashData(body, digest);

        digest[..ChecksumSizeInBytes].CopyTo(destination);
    }
}
