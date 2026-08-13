using UniProtocol.Crypto.Curve25519;
using UniProtocol.Crypto.Noise;
using UniProtocol.Protocol.Identity;

namespace UniProtocol.Protocol.Tests.Identity;

public sealed class UniIdentityTests
{
    [Fact]
    public void FromSeed_SameSeed_ProducesTheSameIdentity()
    {
        byte[] seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

        using UniIdentity first = UniIdentity.FromSeed(seed);
        using UniIdentity second = UniIdentity.FromSeed(seed);

        Assert.Equal(first.NodeId, second.NodeId);
        Assert.Equal(
            Convert.ToHexStringLower(first.NoiseStaticPrivateKey),
            Convert.ToHexStringLower(second.NoiseStaticPrivateKey));
    }

    [Fact]
    public void Generate_ProducesDistinctIdentities()
    {
        using UniIdentity first = UniIdentity.Generate();
        using UniIdentity second = UniIdentity.Generate();

        Assert.NotEqual(first.NodeId, second.NodeId);
    }

    [Fact]
    public void Sign_ProducesASignatureTheNodeIdVerifies()
    {
        using UniIdentity identity = UniIdentity.Generate();

        byte[] message = "signed node record"u8.ToArray();
        byte[] signature = new byte[Ed25519.SignatureSizeInBytes];
        identity.Sign(message, signature);

        Assert.True(identity.NodeId.VerifySignature(message, signature));
        Assert.False(identity.NodeId.VerifySignature("different record"u8, signature));
    }

    [Fact]
    public void NoiseStaticPrivateKey_MatchesTheKeyDerivedFromTheNodeId()
    {
        // This is the property the whole "dial a NodeId" design rests on: the key a peer
        // derives from the published identity must be the public half of the key this node
        // holds privately.
        using UniIdentity identity = UniIdentity.Generate();

        byte[] fromPrivate = new byte[X25519.KeySizeInBytes];
        X25519.GetPublicKey(identity.NoiseStaticPrivateKey, fromPrivate);

        byte[] fromNodeId = new byte[X25519.KeySizeInBytes];
        Assert.True(identity.NodeId.TryGetNoiseStaticKey(fromNodeId));

        Assert.Equal(fromPrivate, fromNodeId);
    }

    [Fact]
    public void Identities_CompleteANoiseHandshakeDialledByNodeIdAlone()
    {
        // End-to-end: the initiator knows nothing about the responder except its NodeId.
        using UniIdentity initiatorIdentity = UniIdentity.Generate();
        using UniIdentity responderIdentity = UniIdentity.Generate();

        byte[] responderNoiseKey = new byte[X25519.KeySizeInBytes];
        Assert.True(responderIdentity.NodeId.TryGetNoiseStaticKey(responderNoiseKey));

        Assert.True(NoiseIkHandshake.TryCreateInitiator(
            new NoiseHandshakeOptions { StaticPrivateKey = initiatorIdentity.NoiseStaticPrivateKey.ToArray() },
            responderNoiseKey,
            out NoiseIkHandshake initiator));

        using (initiator)
        using (NoiseIkHandshake responder = NoiseIkHandshake.CreateResponder(
            new NoiseHandshakeOptions { StaticPrivateKey = responderIdentity.NoiseStaticPrivateKey.ToArray() }))
        {
            byte[] message1 = new byte[initiator.GetMessageSize(0)];
            int written1 = initiator.WriteMessage([], message1);
            Assert.True(responder.TryReadMessage(message1.AsSpan(0, written1), new byte[written1], out _));

            byte[] message2 = new byte[responder.GetMessageSize(0)];
            int written2 = responder.WriteMessage([], message2);
            Assert.True(initiator.TryReadMessage(message2.AsSpan(0, written2), new byte[written2], out _));

            // The responder learned the initiator's Noise key; it must match the identity
            // the initiator would publish.
            byte[] expectedInitiatorKey = new byte[X25519.KeySizeInBytes];
            X25519.GetPublicKey(initiatorIdentity.NoiseStaticPrivateKey, expectedInitiatorKey);

            Assert.Equal(
                Convert.ToHexStringLower(expectedInitiatorKey),
                Convert.ToHexStringLower(responder.RemoteStaticPublicKey));
        }
    }

    [Fact]
    public void Dispose_ThenSign_Throws()
    {
        UniIdentity identity = UniIdentity.Generate();
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.Sign("x"u8, new byte[Ed25519.SignatureSizeInBytes]));
    }
}
