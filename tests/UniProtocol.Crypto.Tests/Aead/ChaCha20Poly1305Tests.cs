using System.Security.Cryptography;
using UniProtocol.Crypto.Aead;

namespace UniProtocol.Crypto.Tests.Aead;

public sealed class ChaCha20Poly1305Tests
{
    private const string RfcKeyHex = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    private const string RfcNonceHex = "070000004041424344454647";
    private const string RfcAssociatedDataHex = "50515253c0c1c2c3c4c5c6c7";

    private const string RfcPlaintextHex =
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
        "637265656e20776f756c642062652069742e";

    private const string RfcCiphertextHex =
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
        "3ff4def08e4b7a9de576d26586cec64b6116";

    private const string RfcTagHex = "1ae10b594f09e26a7e902ecbd0600691";

    /// <summary>
    /// Both implementations must be interchangeable, so every behavioural test runs
    /// against both. A divergence here is a substitutability bug, not a performance note.
    /// </summary>
    public static TheoryData<IAeadAlgorithm> Algorithms
    {
        get
        {
            TheoryData<IAeadAlgorithm> data = [ChaCha20Poly1305Algorithm.Instance];

            if (BclChaCha20Poly1305Algorithm.IsSupported)
            {
                data.Add(BclChaCha20Poly1305Algorithm.Instance);
            }

            return data;
        }
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void Encrypt_Rfc8439Vector_ProducesExpectedCiphertextAndTag(IAeadAlgorithm algorithm)
    {
        byte[] plaintext = Convert.FromHexString(RfcPlaintextHex);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[algorithm.TagSizeInBytes];

        using IAeadCipher cipher = algorithm.CreateCipher(Convert.FromHexString(RfcKeyHex));
        cipher.Encrypt(
            Convert.FromHexString(RfcNonceHex),
            plaintext,
            Convert.FromHexString(RfcAssociatedDataHex),
            ciphertext,
            tag);

        Assert.Equal(RfcCiphertextHex, Convert.ToHexStringLower(ciphertext));
        Assert.Equal(RfcTagHex, Convert.ToHexStringLower(tag));
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void TryDecrypt_Rfc8439Vector_RecoversPlaintext(IAeadAlgorithm algorithm)
    {
        byte[] ciphertext = Convert.FromHexString(RfcCiphertextHex);
        byte[] plaintext = new byte[ciphertext.Length];

        using IAeadCipher cipher = algorithm.CreateCipher(Convert.FromHexString(RfcKeyHex));
        bool isAuthentic = cipher.TryDecrypt(
            Convert.FromHexString(RfcNonceHex),
            ciphertext,
            Convert.FromHexString(RfcTagHex),
            Convert.FromHexString(RfcAssociatedDataHex),
            plaintext);

        Assert.True(isAuthentic);
        Assert.Equal(RfcPlaintextHex, Convert.ToHexStringLower(plaintext));
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void TryDecrypt_TamperedCiphertext_ReturnsFalseWithoutThrowing(IAeadAlgorithm algorithm)
    {
        byte[] ciphertext = Convert.FromHexString(RfcCiphertextHex);
        ciphertext[0] ^= 0x01;

        byte[] plaintext = new byte[ciphertext.Length];

        using IAeadCipher cipher = algorithm.CreateCipher(Convert.FromHexString(RfcKeyHex));
        bool isAuthentic = cipher.TryDecrypt(
            Convert.FromHexString(RfcNonceHex),
            ciphertext,
            Convert.FromHexString(RfcTagHex),
            Convert.FromHexString(RfcAssociatedDataHex),
            plaintext);

        Assert.False(isAuthentic);
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void TryDecrypt_TamperedAssociatedData_ReturnsFalse(IAeadAlgorithm algorithm)
    {
        byte[] associatedData = Convert.FromHexString(RfcAssociatedDataHex);
        associatedData[^1] ^= 0x80;

        byte[] plaintext = new byte[Convert.FromHexString(RfcCiphertextHex).Length];

        using IAeadCipher cipher = algorithm.CreateCipher(Convert.FromHexString(RfcKeyHex));
        bool isAuthentic = cipher.TryDecrypt(
            Convert.FromHexString(RfcNonceHex),
            Convert.FromHexString(RfcCiphertextHex),
            Convert.FromHexString(RfcTagHex),
            associatedData,
            plaintext);

        Assert.False(isAuthentic);
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void EncryptThenTryDecrypt_InPlaceOnTheSameBuffer_RoundTrips(IAeadAlgorithm algorithm)
    {
        // The receive path decrypts inside the socket buffer; aliasing must be safe.
        byte[] original = Convert.FromHexString(RfcPlaintextHex);
        byte[] buffer = (byte[])original.Clone();
        byte[] tag = new byte[algorithm.TagSizeInBytes];
        byte[] nonce = Convert.FromHexString(RfcNonceHex);

        using IAeadCipher cipher = algorithm.CreateCipher(Convert.FromHexString(RfcKeyHex));
        cipher.Encrypt(nonce, buffer, [], buffer, tag);

        Assert.NotEqual(original, buffer);
        Assert.True(cipher.TryDecrypt(nonce, buffer, tag, [], buffer));
        Assert.Equal(original, buffer);
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void EncryptThenTryDecrypt_EmptyPlaintextAndAssociatedData_RoundTrips(IAeadAlgorithm algorithm)
    {
        byte[] tag = new byte[algorithm.TagSizeInBytes];
        byte[] nonce = Convert.FromHexString(RfcNonceHex);

        using IAeadCipher cipher = algorithm.CreateCipher(Convert.FromHexString(RfcKeyHex));
        cipher.Encrypt(nonce, [], [], [], tag);

        Assert.True(cipher.TryDecrypt(nonce, [], tag, [], []));
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void Encrypt_LengthsAroundBlockBoundaries_AgreesAcrossImplementations(IAeadAlgorithm algorithm)
    {
        // Poly1305 padding and the ChaCha20 block loop both have edge cases at multiples
        // of 16 and 64 bytes; compare every such length against the managed reference.
        byte[] key = Convert.FromHexString(RfcKeyHex);
        byte[] nonce = Convert.FromHexString(RfcNonceHex);

        using IAeadCipher reference = ChaCha20Poly1305Algorithm.Instance.CreateCipher(key);
        using IAeadCipher subject = algorithm.CreateCipher(key);

        foreach (int length in new[] { 0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 129 })
        {
            byte[] plaintext = new byte[length];
            for (int i = 0; i < length; i++)
            {
                plaintext[i] = (byte)(i * 31 + 7);
            }

            byte[] associatedData = new byte[length % 17];

            byte[] expectedCiphertext = new byte[length];
            byte[] expectedTag = new byte[16];
            reference.Encrypt(nonce, plaintext, associatedData, expectedCiphertext, expectedTag);

            byte[] actualCiphertext = new byte[length];
            byte[] actualTag = new byte[16];
            subject.Encrypt(nonce, plaintext, associatedData, actualCiphertext, actualTag);

            Assert.Equal(expectedCiphertext, actualCiphertext);
            Assert.Equal(expectedTag, actualTag);
        }
    }

    [Fact]
    public void Dispose_ThenEncrypt_Throws()
    {
        IAeadCipher cipher = ChaCha20Poly1305Algorithm.Instance.CreateCipher(Convert.FromHexString(RfcKeyHex));
        cipher.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            cipher.Encrypt(Convert.FromHexString(RfcNonceHex), [], [], [], new byte[16]));
    }

    [Fact]
    public void CreateCipher_WrongKeySize_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ChaCha20Poly1305Algorithm.Instance.CreateCipher(new byte[31]));
    }
}
