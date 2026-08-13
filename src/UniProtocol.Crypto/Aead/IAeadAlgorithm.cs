namespace UniProtocol.Crypto.Aead;

/// <summary>
/// Describes an AEAD algorithm and creates keyed cipher instances from it.
/// </summary>
/// <remarks>
/// Split from <see cref="IAeadCipher"/> on purpose: the sizes and the factory are
/// needed to lay out a packet before any key exists, while encryption needs a key that
/// is expensive to install and is reused for the lifetime of a session.
/// </remarks>
public interface IAeadAlgorithm
{
    /// <summary>Key size in bytes.</summary>
    int KeySizeInBytes { get; }

    /// <summary>Nonce size in bytes.</summary>
    int NonceSizeInBytes { get; }

    /// <summary>Authentication tag size in bytes.</summary>
    int TagSizeInBytes { get; }

    /// <summary>Human-readable algorithm name, used in diagnostics and telemetry.</summary>
    string Name { get; }

    /// <summary>Installs <paramref name="key"/> and returns a cipher bound to it.</summary>
    IAeadCipher CreateCipher(ReadOnlySpan<byte> key);
}
