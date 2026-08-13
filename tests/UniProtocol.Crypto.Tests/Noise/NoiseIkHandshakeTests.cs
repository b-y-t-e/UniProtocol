using System.Text.Json;
using UniProtocol.Crypto.Aead;
using UniProtocol.Crypto.Curve25519;
using UniProtocol.Crypto.Noise;
using UniProtocol.Crypto.Randomness;

namespace UniProtocol.Crypto.Tests.Noise;

/// <summary>
/// Verifies the handshake against the official Noise test vector for
/// <c>Noise_IK_25519_ChaChaPoly_BLAKE2s</c>, taken verbatim from the Cacophony suite.
/// </summary>
/// <remarks>
/// Interoperability is the point of these tests. A handshake that only agrees with itself
/// is worthless, and every self-consistency test in the world will pass on an
/// implementation that has, say, the wrong HKDF chaining or a swapped DH order.
/// </remarks>
public sealed class NoiseIkHandshakeTests
{
    private static readonly NoiseVector Vector = LoadVector();

    [Fact]
    public void Handshake_CacophonyVector_ProducesTheExactWireBytes()
    {
        (NoiseIkHandshake initiator, NoiseIkHandshake responder) = CreateBothSides();

        using (initiator)
        using (responder)
        {
            byte[] payload1 = Convert.FromHexString(Vector.Messages[0].Payload);
            byte[] message1 = new byte[initiator.GetMessageSize(payload1.Length)];
            int written1 = initiator.WriteMessage(payload1, message1);

            Assert.Equal(Vector.Messages[0].Ciphertext, Convert.ToHexStringLower(message1.AsSpan(0, written1)));

            byte[] received1 = new byte[written1];
            Assert.True(responder.TryReadMessage(message1.AsSpan(0, written1), received1, out int receivedLength1));
            Assert.Equal(Vector.Messages[0].Payload, Convert.ToHexStringLower(received1.AsSpan(0, receivedLength1)));

            byte[] payload2 = Convert.FromHexString(Vector.Messages[1].Payload);
            byte[] message2 = new byte[responder.GetMessageSize(payload2.Length)];
            int written2 = responder.WriteMessage(payload2, message2);

            Assert.Equal(Vector.Messages[1].Ciphertext, Convert.ToHexStringLower(message2.AsSpan(0, written2)));

            byte[] received2 = new byte[written2];
            Assert.True(initiator.TryReadMessage(message2.AsSpan(0, written2), received2, out int receivedLength2));
            Assert.Equal(Vector.Messages[1].Payload, Convert.ToHexStringLower(received2.AsSpan(0, receivedLength2)));

            Assert.True(initiator.IsComplete);
            Assert.True(responder.IsComplete);

            using NoiseSplitKeys initiatorKeys = initiator.Split();
            using NoiseSplitKeys responderKeys = responder.Split();

            Assert.Equal(Vector.HandshakeHash, Convert.ToHexStringLower(initiatorKeys.HandshakeHash));
            Assert.Equal(Vector.HandshakeHash, Convert.ToHexStringLower(responderKeys.HandshakeHash));

            Assert.Equal(
                Convert.ToHexStringLower(initiatorKeys.InitiatorToResponder),
                Convert.ToHexStringLower(responderKeys.InitiatorToResponder));
            Assert.Equal(
                Convert.ToHexStringLower(initiatorKeys.ResponderToInitiator),
                Convert.ToHexStringLower(responderKeys.ResponderToInitiator));
        }
    }

    [Fact]
    public void Split_TransportKeys_MatchTheVectorsPostHandshakeMessages()
    {
        // Messages 2 onwards in the vector are transport messages. Reproducing them proves
        // Split() derived the right keys in the right direction — a swap would leave the
        // handshake itself passing while every subsequent packet failed to decrypt.
        using NoiseSplitKeys keys = CompleteHandshakeAndSplit();

        using IAeadCipher initiatorToResponder = ChaCha20Poly1305Algorithm.Instance.CreateCipher(keys.InitiatorToResponder);
        using IAeadCipher responderToInitiator = ChaCha20Poly1305Algorithm.Instance.CreateCipher(keys.ResponderToInitiator);

        ulong initiatorNonce = 0;
        ulong responderNonce = 0;

        for (int index = 2; index < Vector.Messages.Count; index++)
        {
            bool isFromInitiator = index % 2 == 0;
            IAeadCipher cipher = isFromInitiator ? initiatorToResponder : responderToInitiator;
            ulong nonce = isFromInitiator ? initiatorNonce++ : responderNonce++;

            byte[] payload = Convert.FromHexString(Vector.Messages[index].Payload);
            byte[] ciphertext = new byte[payload.Length];
            byte[] tag = new byte[16];

            cipher.Encrypt(EncodeNonce(nonce), payload, [], ciphertext, tag);

            Assert.Equal(
                Vector.Messages[index].Ciphertext,
                Convert.ToHexStringLower(ciphertext) + Convert.ToHexStringLower(tag));
        }
    }

    [Fact]
    public void TryReadMessage_ResponderLearnsTheInitiatorsStaticKey()
    {
        (NoiseIkHandshake initiator, NoiseIkHandshake responder) = CreateBothSides();

        using (initiator)
        using (responder)
        {
            byte[] message = new byte[initiator.GetMessageSize(0)];
            int written = initiator.WriteMessage([], message);

            Assert.True(responder.TryReadMessage(message.AsSpan(0, written), new byte[written], out _));

            byte[] expected = new byte[X25519.KeySizeInBytes];
            X25519.GetPublicKey(Convert.FromHexString(Vector.InitiatorStatic), expected);

            Assert.Equal(Convert.ToHexStringLower(expected), Convert.ToHexStringLower(responder.RemoteStaticPublicKey));
        }
    }

    [Fact]
    public void TryReadMessage_TamperedCiphertext_ReturnsFalse()
    {
        (NoiseIkHandshake initiator, NoiseIkHandshake responder) = CreateBothSides();

        using (initiator)
        using (responder)
        {
            byte[] message = new byte[initiator.GetMessageSize(8)];
            int written = initiator.WriteMessage(new byte[8], message);
            message[written - 1] ^= 0x01;

            Assert.False(responder.TryReadMessage(message.AsSpan(0, written), new byte[written], out _));
        }
    }

    [Fact]
    public void TryReadMessage_DifferentPrologue_ReturnsFalse()
    {
        // The prologue carries the protocol version. A mismatch must fail the handshake
        // rather than produce a session where the peers disagree about the rules.
        using NoiseIkHandshake initiator = CreateInitiator(prologue: "version-1"u8.ToArray());
        using NoiseIkHandshake responder = CreateResponder(prologue: "version-2"u8.ToArray());

        byte[] message = new byte[initiator.GetMessageSize(0)];
        int written = initiator.WriteMessage([], message);

        Assert.False(responder.TryReadMessage(message.AsSpan(0, written), new byte[written], out _));
    }

    [Fact]
    public void TryReadMessage_TruncatedMessage_ReturnsFalseWithoutThrowing()
    {
        (NoiseIkHandshake initiator, NoiseIkHandshake responder) = CreateBothSides();

        using (initiator)
        using (responder)
        {
            byte[] message = new byte[initiator.GetMessageSize(0)];
            int written = initiator.WriteMessage([], message);

            for (int length = 0; length < written; length++)
            {
                using NoiseIkHandshake freshResponder = CreateResponder(Convert.FromHexString(Vector.ResponderPrologue));
                Assert.False(freshResponder.TryReadMessage(message.AsSpan(0, length), new byte[written], out _));
            }
        }
    }

    [Fact]
    public void TryCreateInitiator_LowOrderRemoteStaticKey_ReturnsFalse()
    {
        NoiseHandshakeOptions options = new()
        {
            StaticPrivateKey = Convert.FromHexString(Vector.InitiatorStatic),
        };

        Assert.False(NoiseIkHandshake.TryCreateInitiator(options, new byte[X25519.KeySizeInBytes], out _));
    }

    [Fact]
    public void WriteMessage_CalledTwiceByTheInitiator_Throws()
    {
        using NoiseIkHandshake initiator = CreateInitiator(Convert.FromHexString(Vector.InitiatorPrologue));

        byte[] message = new byte[initiator.GetMessageSize(0)];
        initiator.WriteMessage([], message);

        Assert.Throws<InvalidOperationException>(() => initiator.WriteMessage([], message));
    }

    [Fact]
    public void Split_BeforeCompletion_Throws()
    {
        using NoiseIkHandshake initiator = CreateInitiator(Convert.FromHexString(Vector.InitiatorPrologue));

        Assert.Throws<InvalidOperationException>(() => initiator.Split());
    }

    [Fact]
    public void Handshake_WithRealRandomness_RoundTripsAnArbitraryPayload()
    {
        byte[] responderPrivate = Convert.FromHexString(Vector.ResponderStatic);
        byte[] responderPublic = new byte[X25519.KeySizeInBytes];
        X25519.GetPublicKey(responderPrivate, responderPublic);

        NoiseHandshakeOptions initiatorOptions = new()
        {
            StaticPrivateKey = Convert.FromHexString(Vector.InitiatorStatic),
            RandomSource = SecureRandomSource.Instance,
        };

        Assert.True(NoiseIkHandshake.TryCreateInitiator(initiatorOptions, responderPublic, out NoiseIkHandshake initiator));

        using (initiator)
        using (NoiseIkHandshake responder = NoiseIkHandshake.CreateResponder(new NoiseHandshakeOptions
        {
            StaticPrivateKey = responderPrivate,
        }))
        {
            byte[] request = "hello from the initiator"u8.ToArray();
            byte[] message1 = new byte[initiator.GetMessageSize(request.Length)];
            int written1 = initiator.WriteMessage(request, message1);

            byte[] received1 = new byte[written1];
            Assert.True(responder.TryReadMessage(message1.AsSpan(0, written1), received1, out int length1));
            Assert.Equal(request, received1.AsSpan(0, length1).ToArray());

            byte[] response = "and hello back"u8.ToArray();
            byte[] message2 = new byte[responder.GetMessageSize(response.Length)];
            int written2 = responder.WriteMessage(response, message2);

            byte[] received2 = new byte[written2];
            Assert.True(initiator.TryReadMessage(message2.AsSpan(0, written2), received2, out int length2));
            Assert.Equal(response, received2.AsSpan(0, length2).ToArray());

            using NoiseSplitKeys initiatorKeys = initiator.Split();
            using NoiseSplitKeys responderKeys = responder.Split();
            Assert.Equal(
                Convert.ToHexStringLower(initiatorKeys.HandshakeHash),
                Convert.ToHexStringLower(responderKeys.HandshakeHash));
        }
    }

    private static byte[] EncodeNonce(ulong counter)
    {
        byte[] nonce = new byte[12];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan(4), counter);
        return nonce;
    }

    private static NoiseSplitKeys CompleteHandshakeAndSplit()
    {
        (NoiseIkHandshake initiator, NoiseIkHandshake responder) = CreateBothSides();

        using (initiator)
        using (responder)
        {
            byte[] payload1 = Convert.FromHexString(Vector.Messages[0].Payload);
            byte[] message1 = new byte[initiator.GetMessageSize(payload1.Length)];
            int written1 = initiator.WriteMessage(payload1, message1);
            Assert.True(responder.TryReadMessage(message1.AsSpan(0, written1), new byte[written1], out _));

            byte[] payload2 = Convert.FromHexString(Vector.Messages[1].Payload);
            byte[] message2 = new byte[responder.GetMessageSize(payload2.Length)];
            int written2 = responder.WriteMessage(payload2, message2);
            Assert.True(initiator.TryReadMessage(message2.AsSpan(0, written2), new byte[written2], out _));

            return initiator.Split();
        }
    }

    private static (NoiseIkHandshake Initiator, NoiseIkHandshake Responder) CreateBothSides()
        => (CreateInitiator(Convert.FromHexString(Vector.InitiatorPrologue)),
            CreateResponder(Convert.FromHexString(Vector.ResponderPrologue)));

    private static NoiseIkHandshake CreateInitiator(byte[] prologue)
    {
        NoiseHandshakeOptions options = new()
        {
            StaticPrivateKey = Convert.FromHexString(Vector.InitiatorStatic),
            Prologue = prologue,
            RandomSource = new FixedRandomSource(Convert.FromHexString(Vector.InitiatorEphemeral)),
        };

        Assert.True(NoiseIkHandshake.TryCreateInitiator(
            options,
            Convert.FromHexString(Vector.InitiatorRemoteStatic),
            out NoiseIkHandshake handshake));

        return handshake;
    }

    private static NoiseIkHandshake CreateResponder(byte[] prologue) => NoiseIkHandshake.CreateResponder(
        new NoiseHandshakeOptions
        {
            StaticPrivateKey = Convert.FromHexString(Vector.ResponderStatic),
            Prologue = prologue,
            RandomSource = new FixedRandomSource(Convert.FromHexString(Vector.ResponderEphemeral)),
        });

    private static NoiseVector LoadVector()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Vectors", "noise-ik-25519-chachapoly-blake2s.json");
        using FileStream stream = File.OpenRead(path);

        return JsonSerializer.Deserialize<NoiseVector>(stream, JsonSerializerOptions.Web)
            ?? throw new InvalidOperationException("The Noise test vector could not be read.");
    }

    internal sealed record NoiseVector
    {
        [System.Text.Json.Serialization.JsonPropertyName("init_prologue")]
        public required string InitiatorPrologue { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("init_static")]
        public required string InitiatorStatic { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("init_ephemeral")]
        public required string InitiatorEphemeral { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("init_remote_static")]
        public required string InitiatorRemoteStatic { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("resp_prologue")]
        public required string ResponderPrologue { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("resp_static")]
        public required string ResponderStatic { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("resp_ephemeral")]
        public required string ResponderEphemeral { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("handshake_hash")]
        public required string HandshakeHash { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("messages")]
        public required IReadOnlyList<NoiseVectorMessage> Messages { get; init; }
    }

    internal sealed record NoiseVectorMessage
    {
        [System.Text.Json.Serialization.JsonPropertyName("payload")]
        public required string Payload { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("ciphertext")]
        public required string Ciphertext { get; init; }
    }

    [Fact]
    public void TryReadMessage_ForgedReply_LeavesTheHandshakeAbleToAcceptTheGenuineOne()
    {
        // A handshake reply travels in a packet authenticated only by mac1, whose key comes
        // from a public key — so any observer on the path, a relay included, can produce a
        // well-formed forgery. If reading one destroyed the initiator's state, a single
        // packet would permanently deny a connection that was about to succeed.
        (NoiseIkHandshake initiator, NoiseIkHandshake responder) = CreateBothSides();

        using (initiator)
        using (responder)
        {
            byte[] message1 = new byte[initiator.GetMessageSize(0)];
            int written1 = initiator.WriteMessage([], message1);
            Assert.True(responder.TryReadMessage(message1.AsSpan(0, written1), new byte[written1], out _));

            byte[] message2 = new byte[responder.GetMessageSize(0)];
            int written2 = responder.WriteMessage([], message2);

            byte[] forged = message2.AsSpan(0, written2).ToArray();
            forged[^1] ^= 0xFF;

            Assert.False(initiator.TryReadMessage(forged, new byte[written2], out _));
            Assert.False(initiator.IsComplete);

            // The genuine reply still works, and produces the keys it would have produced
            // had the forgery never arrived.
            Assert.True(initiator.TryReadMessage(message2.AsSpan(0, written2), new byte[written2], out _));
            Assert.True(initiator.IsComplete);

            using NoiseSplitKeys initiatorKeys = initiator.Split();
            using NoiseSplitKeys responderKeys = responder.Split();

            Assert.Equal(
                Convert.ToHexStringLower(responderKeys.InitiatorToResponder),
                Convert.ToHexStringLower(initiatorKeys.InitiatorToResponder));
        }
    }

    [Fact]
    public void TryReadMessage_ForgedFirstMessage_LeavesTheResponderAbleToAcceptTheGenuineOne()
    {
        (NoiseIkHandshake initiator, NoiseIkHandshake responder) = CreateBothSides();

        using (initiator)
        using (responder)
        {
            byte[] message1 = new byte[initiator.GetMessageSize(0)];
            int written1 = initiator.WriteMessage([], message1);

            byte[] forged = message1.AsSpan(0, written1).ToArray();
            forged[^1] ^= 0xFF;

            Assert.False(responder.TryReadMessage(forged, new byte[written1], out _));
            Assert.True(responder.RemoteStaticPublicKey.IsEmpty);

            Assert.True(responder.TryReadMessage(message1.AsSpan(0, written1), new byte[written1], out _));
            Assert.False(responder.RemoteStaticPublicKey.IsEmpty);
        }
    }
}
