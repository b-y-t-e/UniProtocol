using UniProtocol.Crypto.Aead;

namespace UniProtocol.Crypto.Tests.Aead;

/// <summary>
/// The contract every <see cref="IAeadCipher"/> owes its callers, run against every
/// implementation.
/// </summary>
/// <remarks>
/// <para>
/// The managed and platform ciphers are offered as interchangeable — one is selected over
/// the other by benchmark, not by behaviour — so a difference between them is a defect
/// whichever one you call "right". The interesting differences do not show up on the RFC
/// vectors, which only exercise the path where everything succeeds; they show up on
/// tampering, which is the path a public UDP socket spends most of its time on.
/// </para>
/// <para>
/// The platform implementation is skipped where the OS does not provide ChaCha20-Poly1305,
/// which is the same reason it is not the default.
/// </para>
/// </remarks>
public sealed class AeadCipherContractTests
{
    public static TheoryData<string> Implementations
    {
        get
        {
            TheoryData<string> data = new()
            {
                nameof(ChaCha20Poly1305Algorithm),
                nameof(XChaCha20Poly1305Algorithm),
            };

            if (BclChaCha20Poly1305Algorithm.IsSupported)
            {
                data.Add(nameof(BclChaCha20Poly1305Algorithm));
            }

            return data;
        }
    }

    [Theory]
    [MemberData(nameof(Implementations))]
    public void TryDecrypt_TamperedTag_ReturnsFalseAndZeroesTheDestination(string implementation)
        => AssertRejects(implementation, TamperTarget.Tag);

    [Theory]
    [MemberData(nameof(Implementations))]
    public void TryDecrypt_TamperedCiphertext_ReturnsFalseAndZeroesTheDestination(string implementation)
        => AssertRejects(implementation, TamperTarget.Ciphertext);

    [Theory]
    [MemberData(nameof(Implementations))]
    public void TryDecrypt_TamperedAssociatedData_ReturnsFalseAndZeroesTheDestination(string implementation)
        => AssertRejects(implementation, TamperTarget.AssociatedData);

    [Theory]
    [MemberData(nameof(Implementations))]
    public void TryDecrypt_WrongNonce_ReturnsFalseAndZeroesTheDestination(string implementation)
        => AssertRejects(implementation, TamperTarget.Nonce);

    [Theory]
    [MemberData(nameof(Implementations))]
    public void TryDecrypt_ShortTag_ReturnsFalseRatherThanThrowing(string implementation)
    {
        IAeadAlgorithm algorithm = Resolve(implementation);
        using IAeadCipher cipher = algorithm.CreateCipher(Key(algorithm));

        byte[] plaintext = "a message worth forging"u8.ToArray();
        (byte[] ciphertext, byte[] tag) = Seal(cipher, algorithm, plaintext);

        byte[] destination = new byte[ciphertext.Length];
        destination.AsSpan().Fill(0xEE);

        Assert.False(cipher.TryDecrypt(Nonce(algorithm), ciphertext, tag.AsSpan(0, tag.Length - 1), [], destination));
        Assert.All(destination, b => Assert.Equal(0, b));
    }

    [Theory]
    [MemberData(nameof(Implementations))]
    public void TryDecrypt_WrongLengthNonce_ReturnsFalseAndZeroesTheDestination(string implementation)
    {
        // Three implementations once answered this three different ways: one returned false,
        // one threw ArgumentOutOfRangeException, one threw whatever the platform threw. A
        // caller that has to know which it is talking to has no contract at all.
        IAeadAlgorithm algorithm = Resolve(implementation);
        using IAeadCipher cipher = algorithm.CreateCipher(Key(algorithm));

        byte[] plaintext = "a message worth forging"u8.ToArray();
        (byte[] ciphertext, byte[] tag) = Seal(cipher, algorithm, plaintext);

        byte[] shortNonce = new byte[algorithm.NonceSizeInBytes - 1];

        byte[] destination = new byte[ciphertext.Length];
        destination.AsSpan().Fill(0xEE);

        Assert.False(cipher.TryDecrypt(shortNonce, ciphertext, tag, [], destination));
        Assert.All(destination, b => Assert.Equal(0, b));
    }

    [Theory]
    [MemberData(nameof(Implementations))]
    public void Encrypt_WrongLengthNonce_Throws(string implementation)
    {
        // The other half of the rule. Encrypting builds the nonce locally, so a wrong length
        // is a bug in this library rather than something a peer did, and it should stop the
        // caller rather than be reported through a value nobody checks.
        IAeadAlgorithm algorithm = Resolve(implementation);
        using IAeadCipher cipher = algorithm.CreateCipher(Key(algorithm));

        byte[] shortNonce = new byte[algorithm.NonceSizeInBytes - 1];

        Assert.ThrowsAny<ArgumentException>(() =>
            cipher.Encrypt(shortNonce, "probe"u8, [], new byte[5], new byte[algorithm.TagSizeInBytes]));
    }

    [Theory]
    [MemberData(nameof(Implementations))]
    public void TryDecrypt_AfterARejectedPacket_StillAcceptsAGenuineOne(string implementation)
    {
        // A forged packet must leave the cipher usable. Anyone can send one, so a cipher that
        // could be poisoned by one would be a one-packet denial of service.
        IAeadAlgorithm algorithm = Resolve(implementation);
        using IAeadCipher cipher = algorithm.CreateCipher(Key(algorithm));

        byte[] plaintext = "a message worth forging"u8.ToArray();
        (byte[] ciphertext, byte[] tag) = Seal(cipher, algorithm, plaintext);

        byte[] forgedTag = tag.ToArray();
        forgedTag[0] ^= 0xFF;

        Assert.False(cipher.TryDecrypt(Nonce(algorithm), ciphertext, forgedTag, [], new byte[ciphertext.Length]));

        byte[] recovered = new byte[ciphertext.Length];
        Assert.True(cipher.TryDecrypt(Nonce(algorithm), ciphertext, tag, [], recovered));
        Assert.Equal(plaintext, recovered);
    }

    [Theory]
    [MemberData(nameof(Implementations))]
    public void TryDecrypt_InPlaceOverTheCiphertext_RecoversThePlaintext(string implementation)
    {
        // The receive path decrypts a datagram over itself rather than copying it out of the
        // socket buffer, so overlapping source and destination is a supported case, not an
        // accident.
        IAeadAlgorithm algorithm = Resolve(implementation);
        using IAeadCipher cipher = algorithm.CreateCipher(Key(algorithm));

        byte[] plaintext = "decrypted where it landed"u8.ToArray();
        (byte[] buffer, byte[] tag) = Seal(cipher, algorithm, plaintext);

        Assert.True(cipher.TryDecrypt(Nonce(algorithm), buffer, tag, [], buffer));
        Assert.Equal(plaintext, buffer);
    }

    private static void AssertRejects(string implementation, TamperTarget target)
    {
        IAeadAlgorithm algorithm = Resolve(implementation);
        using IAeadCipher cipher = algorithm.CreateCipher(Key(algorithm));

        byte[] associatedData = "header"u8.ToArray();
        byte[] plaintext = "a message worth forging"u8.ToArray();

        byte[] nonce = Nonce(algorithm);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[algorithm.TagSizeInBytes];
        cipher.Encrypt(nonce, plaintext, associatedData, ciphertext, tag);

        switch (target)
        {
            case TamperTarget.Tag:
                tag[^1] ^= 0x01;
                break;

            case TamperTarget.Ciphertext:
                ciphertext[0] ^= 0x01;
                break;

            case TamperTarget.AssociatedData:
                associatedData[0] ^= 0x01;
                break;

            case TamperTarget.Nonce:
                nonce[^1] ^= 0x01;
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(target));
        }

        // Pre-filled, so "zeroed" is distinguishable from "never written".
        byte[] destination = new byte[ciphertext.Length];
        destination.AsSpan().Fill(0xEE);

        Assert.False(cipher.TryDecrypt(nonce, ciphertext, tag, associatedData, destination));
        Assert.All(destination, b => Assert.Equal(0, b));
    }

    private static (byte[] Ciphertext, byte[] Tag) Seal(
        IAeadCipher cipher,
        IAeadAlgorithm algorithm,
        ReadOnlySpan<byte> plaintext)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[algorithm.TagSizeInBytes];

        cipher.Encrypt(Nonce(algorithm), plaintext, [], ciphertext, tag);

        return (ciphertext, tag);
    }

    private static byte[] Key(IAeadAlgorithm algorithm)
    {
        byte[] key = new byte[algorithm.KeySizeInBytes];

        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }

        return key;
    }

    private static byte[] Nonce(IAeadAlgorithm algorithm)
    {
        byte[] nonce = new byte[algorithm.NonceSizeInBytes];

        for (int i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(0x40 + i);
        }

        return nonce;
    }

    private static IAeadAlgorithm Resolve(string implementation) => implementation switch
    {
        nameof(ChaCha20Poly1305Algorithm) => ChaCha20Poly1305Algorithm.Instance,
        nameof(XChaCha20Poly1305Algorithm) => XChaCha20Poly1305Algorithm.Instance,
        nameof(BclChaCha20Poly1305Algorithm) => BclChaCha20Poly1305Algorithm.Instance,
        _ => throw new ArgumentOutOfRangeException(nameof(implementation), implementation, "Unknown implementation."),
    };

    private enum TamperTarget
    {
        Tag,
        Ciphertext,
        AssociatedData,
        Nonce,
    }
}
