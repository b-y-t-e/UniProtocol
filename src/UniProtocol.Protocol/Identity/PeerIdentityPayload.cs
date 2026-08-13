using UniProtocol.Crypto.Curve25519;

namespace UniProtocol.Protocol.Identity;

/// <summary>
/// The identity claim carried inside a Noise handshake payload.
/// </summary>
/// <remarks>
/// <para>
/// Layout: a 32-byte NodeId followed by an optional application payload. Used by both the
/// peer-to-peer handshake and the relay handshake, which face the same problem.
/// </para>
/// <para>
/// The NodeId has to be transmitted because Noise authenticates the peer's <em>X25519</em>
/// static key, and a UniProtocol identity is an <em>Ed25519</em> key. The conversion runs
/// one way only, so the responder cannot recover the identity from what Noise gives it.
/// </para>
/// <para>
/// The claim is verified by converting the asserted NodeId to X25519 and requiring it to
/// equal the key Noise authenticated. Since both keys come from one seed, and Noise has
/// already proved the peer holds the corresponding X25519 private key, an attacker cannot
/// assert an identity that is not theirs. The payload is encrypted, so the identity is not
/// exposed to observers.
/// </para>
/// </remarks>
public static class PeerIdentityPayload
{
    /// <summary>Size of the fixed portion of the payload.</summary>
    public const int HeaderSizeInBytes = NodeId.SizeInBytes;

    /// <summary>Writes the payload and returns its length.</summary>
    public static int Write(NodeId nodeId, ReadOnlySpan<byte> applicationPayload, Span<byte> destination)
    {
        int total = HeaderSizeInBytes + applicationPayload.Length;
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, total);

        nodeId.CopyTo(destination);
        applicationPayload.CopyTo(destination[HeaderSizeInBytes..]);

        return total;
    }

    /// <summary>
    /// Parses the payload and checks that the asserted identity matches the key Noise
    /// authenticated.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when the payload is too short, the identity is not a valid
    /// curve point, or it does not correspond to <paramref name="authenticatedStaticKey"/>.
    /// </returns>
    public static bool TryParse(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> authenticatedStaticKey,
        out NodeId nodeId,
        out ReadOnlySpan<byte> applicationPayload)
    {
        nodeId = default;
        applicationPayload = default;

        if (payload.Length < HeaderSizeInBytes)
        {
            return false;
        }

        NodeId claimed = NodeId.FromPublicKey(payload[..NodeId.SizeInBytes]);

        Span<byte> derivedStaticKey = stackalloc byte[X25519.KeySizeInBytes];
        if (!claimed.TryGetNoiseStaticKey(derivedStaticKey))
        {
            return false;
        }

        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                derivedStaticKey,
                authenticatedStaticKey))
        {
            return false;
        }

        nodeId = claimed;
        applicationPayload = payload[HeaderSizeInBytes..];

        return true;
    }
}
