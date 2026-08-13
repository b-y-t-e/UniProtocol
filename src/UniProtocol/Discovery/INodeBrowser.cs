namespace UniProtocol.Discovery;

/// <summary>Finds nodes that are advertising themselves.</summary>
public interface INodeBrowser : IAsyncDisposable
{
    /// <summary>
    /// Yields nodes as they are discovered, until <paramref name="cancellationToken"/> is
    /// cancelled.
    /// </summary>
    /// <remarks>
    /// The same node may be yielded more than once: advertisements repeat, and a node that
    /// changes address advertises again. Callers that want a set should key it on
    /// <see cref="DiscoveredNode.NodeId"/>.
    /// </remarks>
    IAsyncEnumerable<DiscoveredNode> BrowseAsync(CancellationToken cancellationToken = default);
}
