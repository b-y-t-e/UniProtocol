using UniProtocol.Protocol;

namespace UniProtocol.Abstractions;

/// <summary>
/// Sends and receives datagrams. The only way the protocol core reaches the network.
/// </summary>
/// <remarks>
/// <para>
/// Two methods, deliberately. Everything above this interface — the handshake, loss
/// recovery, congestion control, path probing, hole punching — is written against these
/// two operations and a <see cref="TimeProvider"/>, so the entire protocol can be driven
/// by a simulated network with injected loss, reordering and latency, at simulated speed,
/// and a failing run can be replayed exactly from its seed.
/// </para>
/// <para>
/// That is why <c>Socket</c> is a banned symbol outside the adapters: the moment the core
/// opens a socket of its own, deterministic testing stops being possible.
/// </para>
/// </remarks>
public interface IPacketTransport : IAsyncDisposable
{
    /// <summary>The address this transport receives on.</summary>
    NetworkAddress LocalAddress { get; }

    /// <summary>Which kinds of destination this transport can reach.</summary>
    PathKind SupportedPathKind { get; }

    /// <summary>
    /// Sends a single datagram. Delivery is not guaranteed and no error is reported for a
    /// packet that is dropped in the network.
    /// </summary>
    ValueTask SendAsync(ReadOnlyMemory<byte> payload, PathEndpoint destination, CancellationToken cancellationToken);

    /// <summary>Waits for the next datagram and copies it into <paramref name="buffer"/>.</summary>
    /// <remarks>
    /// At most one receive may be in flight at a time. The .NET socket receive path is
    /// allocation-free only under that condition, and the protocol gains nothing from
    /// concurrent receives on one socket — parallelism comes from having several sockets.
    /// </remarks>
    ValueTask<PacketReceiveResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken);
}
