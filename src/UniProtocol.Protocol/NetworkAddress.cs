using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace UniProtocol.Protocol;

/// <summary>
/// An IP address and port, as a value type.
/// </summary>
/// <remarks>
/// <para>
/// This exists instead of <see cref="IPEndPoint"/> because an endpoint is compared and
/// looked up on every received packet, and <see cref="IPEndPoint"/> is a class: using it
/// on the receive path allocates per datagram and puts pressure on the GC precisely where
/// the protocol is most latency-sensitive.
/// </para>
/// <para>
/// IPv4 addresses are held in IPv4-mapped form, so one representation covers both families
/// and a dual-stack socket needs no special cases.
/// </para>
/// </remarks>
public readonly struct NetworkAddress : IEquatable<NetworkAddress>
{
    /// <summary>Size of the address portion in bytes.</summary>
    public const int AddressSizeInBytes = 16;

    private static ReadOnlySpan<byte> IPv4MappedPrefix => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF];

    private readonly AddressBytes _address;
    private readonly uint _scopeId;
    private readonly ushort _port;

    private NetworkAddress(ReadOnlySpan<byte> address, ushort port, uint scopeId)
    {
        address.CopyTo(_address);
        _port = port;
        _scopeId = scopeId;
    }

    /// <summary>The port number.</summary>
    public ushort Port => _port;

    /// <summary>The IPv6 scope identifier, used by link-local addresses.</summary>
    public uint ScopeId => _scopeId;

    /// <summary>Indicates whether this is an IPv4 address held in IPv4-mapped form.</summary>
    public bool IsIPv4 => ((ReadOnlySpan<byte>)_address)[..12].SequenceEqual(IPv4MappedPrefix);

    /// <summary>Indicates whether this is the default, unset value.</summary>
    public bool IsUnspecified => _port == 0 && ((ReadOnlySpan<byte>)_address).IndexOfAnyExcept((byte)0) < 0;

    /// <summary>
    /// Indicates whether the address part is the wildcard — <c>0.0.0.0</c> or <c>::</c>.
    /// </summary>
    /// <remarks>
    /// A socket bound to the wildcard accepts traffic on every interface, so its local
    /// address says nothing about where a peer should send. One bound to a specific address
    /// says exactly that, and nothing else will reach it.
    /// </remarks>
    public bool IsAnyAddress
    {
        get
        {
            ReadOnlySpan<byte> bytes = _address;
            return (IsIPv4 ? bytes[12..] : bytes).IndexOfAnyExcept((byte)0) < 0;
        }
    }

    /// <summary>Creates an address from 16 raw bytes in IPv6 form.</summary>
    public static NetworkAddress FromIPv6Bytes(ReadOnlySpan<byte> address, ushort port, uint scopeId = 0)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(address.Length, AddressSizeInBytes);

        return new NetworkAddress(address, port, scopeId);
    }

    /// <summary>Converts from the BCL representation.</summary>
    public static NetworkAddress FromIPEndPoint(IPEndPoint endPoint)
    {
        ArgumentNullException.ThrowIfNull(endPoint);

        Span<byte> bytes = stackalloc byte[AddressSizeInBytes];
        IPAddress address = endPoint.Address;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            address = address.MapToIPv6();
        }

        if (!address.TryWriteBytes(bytes, out int written) || written != AddressSizeInBytes)
        {
            throw new ArgumentException("Only IPv4 and IPv6 addresses are supported.", nameof(endPoint));
        }

        uint scopeId = address.AddressFamily == AddressFamily.InterNetworkV6 ? (uint)address.ScopeId : 0;

        return new NetworkAddress(bytes, (ushort)endPoint.Port, scopeId);
    }

    /// <summary>Parses text of the form <c>host:port</c> or <c>[v6]:port</c>.</summary>
    public static bool TryParse(ReadOnlySpan<char> text, out NetworkAddress address)
    {
        if (IPEndPoint.TryParse(text, out IPEndPoint? endPoint))
        {
            address = FromIPEndPoint(endPoint);
            return true;
        }

        address = default;
        return false;
    }

    /// <summary>Converts to the BCL representation, allocating.</summary>
    /// <remarks>
    /// Only for the socket boundary and for diagnostics — never on the receive path.
    /// </remarks>
    public IPEndPoint ToIPEndPoint()
    {
        ReadOnlySpan<byte> bytes = _address;

        IPAddress address = IsIPv4
            ? new IPAddress(bytes[12..])
            : new IPAddress(bytes, _scopeId);

        return new IPEndPoint(address, _port);
    }

    /// <summary>The raw 16-byte address, as a view over this instance.</summary>
    [UnscopedRef]
    public ReadOnlySpan<byte> AddressSpan => _address;

    /// <inheritdoc />
    public bool Equals(NetworkAddress other)
        => _port == other._port
        && _scopeId == other._scopeId
        && ((ReadOnlySpan<byte>)_address).SequenceEqual(other._address);

    /// <inheritdoc />
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is NetworkAddress other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        ReadOnlySpan<byte> bytes = _address;

        HashCode hash = default;
        hash.AddBytes(bytes);
        hash.Add(_port);
        hash.Add(_scopeId);

        return hash.ToHashCode();
    }

    /// <summary>Compares two addresses.</summary>
    public static bool operator ==(NetworkAddress left, NetworkAddress right) => left.Equals(right);

    /// <summary>Compares two addresses.</summary>
    public static bool operator !=(NetworkAddress left, NetworkAddress right) => !left.Equals(right);

    /// <inheritdoc />
    /// <remarks>
    /// Goes through <see cref="IPEndPoint"/> so the canonical formatting rules — IPv6
    /// zero-group compression, bracketing, scope suffixes — come from the BCL rather than
    /// being reimplemented here. This is diagnostics only, so the allocation is fine.
    /// </remarks>
    public override string ToString() => ToIPEndPoint().ToString();

    [InlineArray(AddressSizeInBytes)]
    private struct AddressBytes
    {
        private byte _element0;
    }
}
