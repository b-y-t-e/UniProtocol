namespace UniProtocol.Crypto.Randomness;

/// <summary>
/// Supplies random bytes to code that must remain reproducible under test.
/// </summary>
/// <remarks>
/// Randomness is injected rather than taken from the platform CSPRNG
/// (<c>System.Security.Cryptography.RandomNumberGenerator</c>) directly for two
/// reasons. Handshake test vectors pin the ephemeral keys, so they can only be reproduced
/// if the source is substitutable; and the network simulator must replay a failing run
/// exactly from its seed, which is impossible if any component reaches for entropy on its
/// own. Production always uses <see cref="SecureRandomSource"/>.
/// </remarks>
public interface IRandomSource
{
    /// <summary>Fills <paramref name="destination"/> with random bytes.</summary>
    void Fill(Span<byte> destination);
}
