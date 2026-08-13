namespace UniProtocol.Crypto.Aead;

/// <summary>
/// An AEAD cipher bound to a single key, with a detached authentication tag.
/// </summary>
/// <remarks>
/// <para>
/// The tag is detached rather than appended so callers can place it wherever the wire
/// format puts it, and so the receive path can verify a packet before touching the
/// buffer it will decrypt in place.
/// </para>
/// <para>
/// Implementations must permit <c>plaintext</c> and <c>ciphertext</c> to refer to the
/// same memory. In-place transformation is what lets a datagram be decrypted without
/// being copied out of the socket buffer.
/// </para>
/// </remarks>
public interface IAeadCipher : IDisposable
{
    /// <summary>The algorithm this cipher implements.</summary>
    IAeadAlgorithm Algorithm { get; }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and writes the authentication tag to
    /// <paramref name="tag"/>.
    /// </summary>
    void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        Span<byte> ciphertext,
        Span<byte> tag);

    /// <summary>
    /// Verifies <paramref name="tag"/> and, only if it is valid, decrypts
    /// <paramref name="ciphertext"/> into <paramref name="plaintext"/>.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> if the tag was valid; otherwise <see langword="false"/>,
    /// leaving <paramref name="plaintext"/> unmodified.
    /// </returns>
    /// <remarks>
    /// A failed tag check is an ordinary event on a public UDP socket — anyone can send
    /// us bytes — so it is reported as a return value rather than an exception. Throwing
    /// here would turn a trivial spoofed packet into a denial-of-service vector.
    /// </remarks>
    bool TryDecrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> plaintext);
}
