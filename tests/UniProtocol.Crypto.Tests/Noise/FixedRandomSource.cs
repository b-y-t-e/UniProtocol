using UniProtocol.Crypto.Randomness;

namespace UniProtocol.Crypto.Tests.Noise;

/// <summary>
/// An <see cref="IRandomSource"/> that replays a fixed sequence of byte blocks.
/// </summary>
/// <remarks>
/// Handshake test vectors pin the ephemeral key, which is the whole reason randomness is
/// an injected dependency rather than a direct call into the OS generator.
/// </remarks>
internal sealed class FixedRandomSource : IRandomSource
{
    private readonly Queue<byte[]> _blocks;

    public FixedRandomSource(params byte[][] blocks)
    {
        _blocks = new Queue<byte[]>(blocks);
    }

    public void Fill(Span<byte> destination)
    {
        if (!_blocks.TryDequeue(out byte[]? block))
        {
            throw new InvalidOperationException("The test requested more randomness than the vector supplies.");
        }

        if (block.Length != destination.Length)
        {
            throw new InvalidOperationException(
                $"The test vector supplies {block.Length} bytes but {destination.Length} were requested.");
        }

        block.CopyTo(destination);
    }
}
