using System.Security.Cryptography;

namespace UniProtocol.Crypto.Randomness;

/// <summary>
/// The production <see cref="IRandomSource"/>, backed by the operating system CSPRNG.
/// </summary>
/// <remarks>
/// This is the single sanctioned crossing point from UniProtocol into the platform
/// entropy source. Everything else takes an <see cref="IRandomSource"/>.
/// </remarks>
public sealed class SecureRandomSource : IRandomSource
{
    /// <summary>The shared instance; the OS generator is thread-safe and stateless here.</summary>
    public static SecureRandomSource Instance { get; } = new();

    private SecureRandomSource()
    {
    }

    /// <inheritdoc />
    public void Fill(Span<byte> destination)
    {
#pragma warning disable RS0030 // Adapter boundary: the sanctioned use of the OS CSPRNG.
        RandomNumberGenerator.Fill(destination);
#pragma warning restore RS0030
    }
}
