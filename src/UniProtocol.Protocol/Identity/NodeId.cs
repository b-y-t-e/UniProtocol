using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using UniProtocol.Crypto.Curve25519;

namespace UniProtocol.Protocol.Identity;

/// <summary>
/// The identity of a UniProtocol node: an Ed25519 public key.
/// </summary>
/// <remarks>
/// <para>
/// A NodeId is the only address a caller needs. It is not tied to an IP address, a port,
/// a network or a relay, so a device keeps the same identity as it moves between Wi-Fi,
/// cellular and a different continent — "dial keys, not IPs".
/// </para>
/// <para>
/// The same key also yields the X25519 static key used by the Noise handshake (see
/// <see cref="TryGetNoiseStaticKey"/>), so knowing a NodeId is sufficient to start an
/// authenticated connection to it. There is no second key to publish and nothing to keep
/// in sync.
/// </para>
/// </remarks>
public readonly struct NodeId : IEquatable<NodeId>, ISpanFormattable
{
    /// <summary>Size of a node identity in bytes.</summary>
    public const int SizeInBytes = Ed25519.PublicKeySizeInBytes;

    /// <summary>Number of characters in the base32 text form.</summary>
    public const int TextLength = 52;

    private readonly KeyBytes _value;

    private NodeId(ReadOnlySpan<byte> publicKey)
    {
        publicKey.CopyTo(_value);
    }

    /// <summary>Wraps a 32-byte Ed25519 public key.</summary>
    public static NodeId FromPublicKey(ReadOnlySpan<byte> publicKey)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(publicKey.Length, SizeInBytes);

        return new NodeId(publicKey);
    }

    /// <summary>Parses the base32 text form, case-insensitively.</summary>
    public static bool TryParse(ReadOnlySpan<char> text, out NodeId nodeId)
    {
        Span<byte> publicKey = stackalloc byte[SizeInBytes];

        if (!Base32.TryDecode(text, publicKey))
        {
            nodeId = default;
            return false;
        }

        nodeId = new NodeId(publicKey);
        return true;
    }

    /// <summary>Parses the base32 text form, throwing on malformed input.</summary>
    public static NodeId Parse(ReadOnlySpan<char> text)
        => TryParse(text, out NodeId nodeId)
            ? nodeId
            : throw new FormatException($"'{new string(text)}' is not a valid NodeId.");

    /// <summary>
    /// The raw Ed25519 public key, as a view over this instance.
    /// </summary>
    /// <remarks>
    /// The returned span borrows this value's storage, so it must not outlive the
    /// <see cref="NodeId"/> it came from. Use <see cref="CopyTo"/> when the bytes need to
    /// be kept.
    /// </remarks>
    [UnscopedRef]
    public ReadOnlySpan<byte> AsSpan() => _value;

    /// <summary>Copies the raw public key to <paramref name="destination"/>.</summary>
    public void CopyTo(Span<byte> destination) => ((ReadOnlySpan<byte>)_value).CopyTo(destination);

    /// <summary>
    /// Derives the X25519 static public key that this identity uses for Noise.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when the identity is not a valid curve point, which can
    /// happen for any 32 bytes someone hands us.
    /// </returns>
    public bool TryGetNoiseStaticKey(Span<byte> x25519PublicKey)
        => Ed25519.TryConvertPublicKeyToX25519(_value, x25519PublicKey);

    /// <summary>Verifies an Ed25519 signature made by this identity.</summary>
    public bool VerifySignature(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        => Ed25519.Verify(_value, message, signature);

    /// <inheritdoc />
    public bool Equals(NodeId other) => CryptographicOperations.FixedTimeEquals(_value, other._value);

    /// <inheritdoc />
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is NodeId other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        // All 32 bytes, not just the first four. An honest peer's key is uniformly
        // distributed and any four bytes of it would do — but a relay keys its client table
        // by identities that its clients choose, and generating keys that agree in four
        // given bytes costs an attacker nothing worth counting. Mixing the whole key makes
        // the table's worst case something nobody can arrange.
        HashCode hash = default;
        hash.AddBytes(_value);
        return hash.ToHashCode();
    }

    /// <summary>Compares two identities.</summary>
    public static bool operator ==(NodeId left, NodeId right) => left.Equals(right);

    /// <summary>Compares two identities.</summary>
    public static bool operator !=(NodeId left, NodeId right) => !left.Equals(right);

    /// <inheritdoc />
    public override string ToString()
    {
        Span<char> text = stackalloc char[TextLength];
        Base32.Encode(_value, text);
        return new string(text);
    }

    /// <inheritdoc />
    public string ToString(string? format, IFormatProvider? formatProvider) => ToString();

    /// <inheritdoc />
    public bool TryFormat(Span<char> destination, out int charsWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
    {
        if (destination.Length < TextLength)
        {
            charsWritten = 0;
            return false;
        }

        charsWritten = Base32.Encode(_value, destination);
        return true;
    }

    /// <summary>
    /// A short prefix for logs. Never use it to make a security decision — eight
    /// characters is 40 bits and trivially collidable on purpose.
    /// </summary>
    public string ToShortString() => ToString()[..8];

    [InlineArray(SizeInBytes)]
    private struct KeyBytes
    {
        private byte _element0;
    }
}
