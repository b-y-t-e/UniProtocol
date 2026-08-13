using UniProtocol.Protocol;

namespace UniProtocol.Discovery;

/// <summary>Publishes this node's ticket so others can find it.</summary>
/// <remarks>
/// Separate from <see cref="INodeBrowser"/> because the two are genuinely independent: a
/// server advertises without ever browsing, and a client that dials a pasted ticket browses
/// without ever advertising. One interface would force both to depend on the whole thing.
/// </remarks>
public interface INodeAdvertiser : IAsyncDisposable
{
    /// <summary>Starts advertising <paramref name="ticket"/>, replacing any previous one.</summary>
    ValueTask AdvertiseAsync(UniTicket ticket, CancellationToken cancellationToken = default);
}
