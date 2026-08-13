using UniProtocol.Protocol;

namespace UniProtocol.Abstractions;

/// <summary>The outcome of <see cref="IPacketTransport.ReceiveAsync"/>.</summary>
/// <param name="BytesReceived">Number of bytes written into the caller's buffer.</param>
/// <param name="Source">Where the datagram came from, and by which kind of path.</param>
public readonly record struct PacketReceiveResult(int BytesReceived, PathEndpoint Source);
