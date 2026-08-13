using UniProtocol.Crypto.Aead;

namespace UniProtocol.Crypto.Tests.Aead;

public sealed class XChaCha20Poly1305Tests
{
    [Fact]
    public void DeriveSubkey_XChaChaDraftVector_MatchesReference()
    {
        // draft-irtf-cfrg-xchacha section 2.2.1.
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Convert.FromHexString("000000090000004a0000000031415927");

        Span<byte> subkey = stackalloc byte[HChaCha20.SubkeySizeInBytes];
        HChaCha20.DeriveSubkey(key, nonce, subkey);

        Assert.Equal(
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
            Convert.ToHexStringLower(subkey));
    }

    [Fact]
    public void EncryptThenTryDecrypt_RoundTripsWithAssociatedData()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[XChaCha20Poly1305Algorithm.ExtendedNonceSizeInBytes];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }

        for (int i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(0x40 + i);
        }

        byte[] plaintext = "disco ping payload"u8.ToArray();
        byte[] associatedData = "uniprotocol/v1/disco"u8.ToArray();
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using IAeadCipher cipher = XChaCha20Poly1305Algorithm.Instance.CreateCipher(key);
        cipher.Encrypt(nonce, plaintext, associatedData, ciphertext, tag);

        byte[] recovered = new byte[plaintext.Length];
        Assert.True(cipher.TryDecrypt(nonce, ciphertext, tag, associatedData, recovered));
        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void TryDecrypt_DifferentNonce_ReturnsFalse()
    {
        byte[] key = new byte[32];
        byte[] nonce = new byte[XChaCha20Poly1305Algorithm.ExtendedNonceSizeInBytes];
        byte[] plaintext = "probe"u8.ToArray();
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using IAeadCipher cipher = XChaCha20Poly1305Algorithm.Instance.CreateCipher(key);
        cipher.Encrypt(nonce, plaintext, [], ciphertext, tag);

        // Flipping a byte in the first 16 nonce bytes changes the HChaCha20 subkey, which
        // must invalidate the tag just as surely as changing the inner nonce does.
        nonce[3] ^= 0x01;

        Assert.False(cipher.TryDecrypt(nonce, ciphertext, tag, [], new byte[plaintext.Length]));
    }

    [Fact]
    public void TryDecrypt_WrongNonceLength_ReturnsFalse()
    {
        using IAeadCipher cipher = XChaCha20Poly1305Algorithm.Instance.CreateCipher(new byte[32]);

        Assert.False(cipher.TryDecrypt(new byte[12], [], new byte[16], [], []));
    }
}
