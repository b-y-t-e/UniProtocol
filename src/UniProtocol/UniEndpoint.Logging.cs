using Microsoft.Extensions.Logging;
using UniProtocol.Protocol;
using UniProtocol.Protocol.Identity;

namespace UniProtocol;

/// <content>
/// Source-generated log methods.
/// </content>
/// <remarks>
/// Written with <see cref="LoggerMessageAttribute"/> rather than
/// <c>ILogger.LogDebug(...)</c> so that formatting a <see cref="NodeId"/> or a
/// <see cref="PathEndpoint"/> costs nothing when the level is disabled. These sit on the
/// receive path, where the arguments are structs that would otherwise be boxed for every
/// packet regardless of whether anyone is listening.
/// </remarks>
public sealed partial class UniEndpoint
{
    [LoggerMessage(
        EventId = 1000,
        Level = LogLevel.Debug,
        Message = "Accepted a connection from {NodeId} over {Path}.")]
    private partial void LogConnectionAccepted(NodeId nodeId, PathEndpoint path);

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Debug,
        Message = "Rejected a handshake over {Path}: {Reason}.")]
    private partial void LogHandshakeRejected(PathEndpoint path, string reason);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Error,
        Message = "Dropping a packet that could not be processed.")]
    private partial void LogPacketProcessingFailed(Exception exception);
}
