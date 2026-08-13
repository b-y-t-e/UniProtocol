using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using UniProtocol.Abstractions;
using UniProtocol.Protocol;

namespace UniProtocol.Transport;

/// <summary>
/// An <see cref="IPacketTransport"/> backed by a real UDP socket.
/// </summary>
/// <remarks>
/// <para>
/// This is an adapter at the system boundary and the only type in the library permitted to
/// touch <c>Socket</c> — hence the suppressions below. Everything above it is written
/// against <see cref="IPacketTransport"/> and can therefore run against the simulator.
/// </para>
/// <para>
/// One socket serves one address family. Dual-mode sockets are avoided deliberately: they
/// obscure which local address a packet actually left from, which is exactly the
/// information path selection needs on a multi-homed machine, and they behave
/// inconsistently around multicast on Android.
/// </para>
/// </remarks>
#pragma warning disable RS0030 // Adapter boundary: the sanctioned use of Socket.
public sealed class UdpPacketTransport : IPacketTransport
{
    private const int SioUdpConnectionReset = -1744830452; // _WSAIOW(IOC_VENDOR, 12)

    private readonly Socket _socket;
    private readonly ConcurrentDictionary<NetworkAddress, SocketAddress> _destinationCache = new();
    private readonly SocketAddress _receivedAddress;

    private UdpPacketTransport(Socket socket)
    {
        _socket = socket;
        _receivedAddress = new SocketAddress(socket.AddressFamily);
        LocalAddress = NetworkAddress.FromIPEndPoint((IPEndPoint)socket.LocalEndPoint!);
    }

    /// <inheritdoc />
    public NetworkAddress LocalAddress { get; }

    /// <inheritdoc />
    public PathKind SupportedPathKind => PathKind.Direct;

    /// <summary>Binds a UDP socket to <paramref name="localEndPoint"/>.</summary>
    /// <remarks>
    /// Pass port 0 to let the operating system choose; <see cref="LocalAddress"/> then
    /// reports the port that was actually assigned.
    /// </remarks>
    public static UdpPacketTransport Bind(IPEndPoint localEndPoint)
    {
        ArgumentNullException.ThrowIfNull(localEndPoint);

        Socket socket = new(localEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

        try
        {
            if (localEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = false;
            }

            DisableConnectionResetReporting(socket);

            // Path MTU discovery depends on packets not being silently fragmented; a
            // fragmented probe would be reported as success and the real limit never found.
            if (localEndPoint.AddressFamily == AddressFamily.InterNetwork)
            {
                socket.DontFragment = true;
            }

            socket.Bind(localEndPoint);

            return new UdpPacketTransport(socket);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public async ValueTask SendAsync(
        ReadOnlyMemory<byte> payload,
        PathEndpoint destination,
        CancellationToken cancellationToken)
    {
        if (destination.Kind != PathKind.Direct)
        {
            throw new ArgumentException(
                $"A UDP transport cannot reach a {destination.Kind} destination.",
                nameof(destination));
        }

        SocketAddress socketAddress = _destinationCache.GetOrAdd(
            destination.Address,
            static address => address.ToIPEndPoint().Serialize());

        try
        {
            await _socket.SendToAsync(payload, SocketFlags.None, socketAddress, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SocketException)
        {
            // A datagram that the local stack refuses — an unreachable host, a full send
            // buffer, a route that just disappeared — is indistinguishable from one lost in
            // the network, and the protocol already recovers from loss. Failing the caller
            // here would turn a transient routing hiccup into a broken connection.
        }
    }

    /// <inheritdoc />
    public async ValueTask<PacketReceiveResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        while (true)
        {
            try
            {
                int received = await _socket
                    .ReceiveFromAsync(buffer, SocketFlags.None, _receivedAddress, cancellationToken)
                    .ConfigureAwait(false);

                return new PacketReceiveResult(received, PathEndpoint.ToAddress(ToNetworkAddress(_receivedAddress)));
            }
            catch (SocketException exception) when (IsRecoverable(exception.SocketErrorCode))
            {
                // An ICMP error from an earlier send surfaces on the *receive* call. It says
                // nothing about the next packet, so the loop continues rather than tearing
                // down a socket that serves every peer.
            }
        }
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        _socket.Dispose();
        return ValueTask.CompletedTask;
    }

    private static bool IsRecoverable(SocketError error) => error
        is SocketError.ConnectionReset
        or SocketError.MessageSize
        or SocketError.NetworkReset
        or SocketError.HostUnreachable
        or SocketError.NetworkUnreachable;

    /// <summary>
    /// Stops Windows from turning an ICMP "port unreachable" into an exception on the next
    /// receive.
    /// </summary>
    /// <remarks>
    /// Without this, a single peer that is not listening yet — the normal case while both
    /// sides are still starting up, and the normal case during hole punching — breaks
    /// receiving for every other peer on the socket.
    /// </remarks>
    private static void DisableConnectionResetReporting(Socket socket)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        socket.IOControl(SioUdpConnectionReset, [0, 0, 0, 0], null);
    }

    /// <summary>
    /// Reads a <c>sockaddr_in</c> or <c>sockaddr_in6</c> directly, avoiding the
    /// <see cref="IPEndPoint"/> allocation that a per-datagram conversion would cost.
    /// </summary>
    private static NetworkAddress ToNetworkAddress(SocketAddress socketAddress)
    {
        ReadOnlySpan<byte> raw = socketAddress.Buffer.Span;

        if (socketAddress.Family == AddressFamily.InterNetwork)
        {
            // sockaddr_in: family(2) port(2, network order) address(4)
            ushort port = BinaryPrimitives.ReadUInt16BigEndian(raw[2..]);

            Span<byte> mapped = stackalloc byte[NetworkAddress.AddressSizeInBytes];
            mapped[..10].Clear();
            mapped[10] = 0xFF;
            mapped[11] = 0xFF;
            raw.Slice(4, 4).CopyTo(mapped[12..]);

            return NetworkAddress.FromIPv6Bytes(mapped, port);
        }

        // sockaddr_in6: family(2) port(2, network order) flowinfo(4) address(16) scope(4)
        ushort port6 = BinaryPrimitives.ReadUInt16BigEndian(raw[2..]);
        uint scopeId = BinaryPrimitives.ReadUInt32LittleEndian(raw[24..]);

        return NetworkAddress.FromIPv6Bytes(raw.Slice(8, 16), port6, scopeId);
    }
}
#pragma warning restore RS0030
