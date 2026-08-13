using UniProtocol.Crypto.Aead;

namespace UniProtocol.Crypto.Tests.Aead;

public sealed class ChaCha20Tests
{
    [Fact]
    public void GenerateKeyStreamBlock_Rfc8439BlockVector_MatchesReference()
    {
        // RFC 8439 section 2.3.2.
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Convert.FromHexString("000000090000004a00000000");

        Span<byte> block = stackalloc byte[ChaCha20.BlockSizeInBytes];
        ChaCha20.GenerateKeyStreamBlock(key, nonce, counter: 1, block);

        Assert.Equal(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
            Convert.ToHexStringLower(block));
    }

    [Fact]
    public void Transform_Rfc8439EncryptionVector_MatchesReference()
    {
        // RFC 8439 section 2.4.2.
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Convert.FromHexString("000000000000004a00000000");
        byte[] plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."u8.ToArray();

        byte[] ciphertext = new byte[plaintext.Length];
        ChaCha20.Transform(key, nonce, initialCounter: 1, plaintext, ciphertext);

        Assert.Equal(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
            "5af90bbf74a35be6b40b8eedf2785e42874d",
            Convert.ToHexStringLower(ciphertext));
    }

    [Fact]
    public void Transform_AppliedTwice_ReturnsOriginalPlaintext()
    {
        byte[] key = new byte[ChaCha20.KeySizeInBytes];
        byte[] nonce = new byte[ChaCha20.NonceSizeInBytes];
        byte[] original = new byte[200];
        for (int i = 0; i < original.Length; i++)
        {
            original[i] = (byte)(i * 3 + 11);
        }

        byte[] buffer = (byte[])original.Clone();

        ChaCha20.Transform(key, nonce, initialCounter: 1, buffer, buffer);
        Assert.NotEqual(original, buffer);

        ChaCha20.Transform(key, nonce, initialCounter: 1, buffer, buffer);
        Assert.Equal(original, buffer);
    }
}
