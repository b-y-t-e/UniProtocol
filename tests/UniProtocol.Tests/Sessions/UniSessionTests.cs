using UniProtocol.Crypto.Aead;
using UniProtocol.Crypto.Curve25519;
using UniProtocol.Crypto.Noise;
using UniProtocol.Protocol.Packets;
using UniProtocol.Sessions;

namespace UniProtocol.Tests.Sessions;

public sealed class UniSessionTests
{
    [Fact]
    public void EncryptThenDecrypt_AcrossAPair_RoundTrips()
    {
        (UniSession initiator, UniSession responder) = CreateSessionPair();

        using (initiator)
        using (responder)
        {
            byte[] payload = "session payload"u8.ToArray();
            byte[] packet = new byte[UniSession.GetPacketSize(payload.Length)];

            int length = initiator.Encrypt(payload, packet);
            Assert.Equal(packet.Length, length);

            byte[] recovered = new byte[payload.Length];
            Assert.True(responder.TryDecrypt(packet.AsSpan(0, length), recovered, out int recoveredLength));

            Assert.Equal(payload, recovered.AsSpan(0, recoveredLength).ToArray());
        }
    }

    [Fact]
    public void TryDecrypt_ReplayedPacket_RejectsTheSecondCopy()
    {
        (UniSession initiator, UniSession responder) = CreateSessionPair();

        using (initiator)
        using (responder)
        {
            byte[] packet = new byte[UniSession.GetPacketSize(4)];
            int length = initiator.Encrypt([1, 2, 3, 4], packet);

            byte[] recovered = new byte[4];
            Assert.True(responder.TryDecrypt(packet.AsSpan(0, length), recovered, out _));
            Assert.False(responder.TryDecrypt(packet.AsSpan(0, length), recovered, out _));
        }
    }

    [Fact]
    public void TryDecrypt_PacketForAnotherSession_ReturnsFalse()
    {
        (UniSession initiator, UniSession responder) = CreateSessionPair();

        using (initiator)
        using (responder)
        {
            byte[] packet = new byte[UniSession.GetPacketSize(4)];
            int length = initiator.Encrypt([1, 2, 3, 4], packet);

            // Point the packet at a different session identifier.
            packet[4] ^= 0xFF;

            Assert.False(responder.TryDecrypt(packet.AsSpan(0, length), new byte[4], out _));
        }
    }

    [Fact]
    public void TryDecrypt_TamperedHeader_ReturnsFalse()
    {
        // The header is the AEAD associated data, so altering the counter must break
        // authentication rather than silently decrypting under a different nonce.
        (UniSession initiator, UniSession responder) = CreateSessionPair();

        using (initiator)
        using (responder)
        {
            byte[] packet = new byte[UniSession.GetPacketSize(4)];
            int length = initiator.Encrypt([1, 2, 3, 4], packet);

            packet[8] ^= 0x01;

            Assert.False(responder.TryDecrypt(packet.AsSpan(0, length), new byte[4], out _));
        }
    }

    [Fact]
    public void TryDecrypt_TamperedCiphertext_ReturnsFalse()
    {
        (UniSession initiator, UniSession responder) = CreateSessionPair();

        using (initiator)
        using (responder)
        {
            byte[] packet = new byte[UniSession.GetPacketSize(4)];
            int length = initiator.Encrypt([1, 2, 3, 4], packet);

            packet[DataPacketHeader.SizeInBytes] ^= 0x01;

            Assert.False(responder.TryDecrypt(packet.AsSpan(0, length), new byte[4], out _));
        }
    }

    [Fact]
    public void TryDecrypt_OutOfOrderPackets_AllAccepted()
    {
        // UDP reorders. A session that only accepted increasing counters would drop good
        // packets on any path with more than one route.
        (UniSession initiator, UniSession responder) = CreateSessionPair();

        using (initiator)
        using (responder)
        {
            List<byte[]> packets = [];

            for (int i = 0; i < 32; i++)
            {
                byte[] packet = new byte[UniSession.GetPacketSize(1)];
                initiator.Encrypt([(byte)i], packet);
                packets.Add(packet);
            }

            packets.Reverse();

            byte[] recovered = new byte[1];
            foreach (byte[] packet in packets)
            {
                Assert.True(responder.TryDecrypt(packet, recovered, out _));
            }
        }
    }

    [Fact]
    public void Decrypt_InPlace_ProducesThePlaintextOverTheCiphertext()
    {
        // The receive path relies on this: the plaintext replaces the ciphertext in the
        // socket buffer, so a datagram is never copied.
        (UniSession initiator, UniSession responder) = CreateSessionPair();

        using (initiator)
        using (responder)
        {
            byte[] payload = "in place"u8.ToArray();
            byte[] packet = new byte[UniSession.GetPacketSize(payload.Length)];
            int length = initiator.Encrypt(payload, packet);

            Assert.True(responder.TryDecrypt(
                packet.AsSpan(0, length),
                packet.AsSpan(DataPacketHeader.SizeInBytes),
                out int recoveredLength));

            Assert.Equal(payload, packet.AsSpan(DataPacketHeader.SizeInBytes, recoveredLength).ToArray());
        }
    }

    [Fact]
    public void Encrypt_IncrementsTheCounterPerPacket()
    {
        (UniSession initiator, UniSession responder) = CreateSessionPair();

        using (initiator)
        using (responder)
        {
            byte[] packet = new byte[UniSession.GetPacketSize(0)];

            initiator.Encrypt([], packet);
            Assert.True(DataPacketHeader.TryRead(packet, out DataPacketHeader first));

            initiator.Encrypt([], packet);
            Assert.True(DataPacketHeader.TryRead(packet, out DataPacketHeader second));

            Assert.Equal(first.Counter + 1, second.Counter);
            Assert.Equal(2ul, initiator.PacketsSent);
        }
    }

    [Fact]
    public void Encrypt_FromManyThreadsAtOnce_NeverReusesAPacketCounter()
    {
        // A repeated counter is a repeated nonce, and for ChaCha20-Poly1305 that discloses
        // the XOR of the two payloads and lets the Poly1305 key be recovered. The send side
        // is reachable from every caller of SendDatagramAsync, so it has to hold under
        // concurrency rather than by convention.
        const int ThreadCount = 8;
        const int PacketsPerThread = 500;

        (UniSession initiator, UniSession responder) = CreateSessionPair();

        using (initiator)
        using (responder)
        {
            System.Collections.Concurrent.ConcurrentBag<ulong> counters = [];

            Parallel.For(0, ThreadCount, _ =>
            {
                byte[] packet = new byte[UniSession.GetPacketSize(8)];

                for (int i = 0; i < PacketsPerThread; i++)
                {
                    initiator.Encrypt("payload!"u8, packet);

                    Assert.True(DataPacketHeader.TryRead(packet, out DataPacketHeader header));
                    counters.Add(header.Counter);
                }
            });

            Assert.Equal(ThreadCount * PacketsPerThread, counters.Count);
            Assert.Equal(counters.Count, counters.Distinct().Count());
        }
    }

    [Fact]
    public void TryDecrypt_TheSamePacketFromTwoThreads_AcceptsItExactlyOnce()
    {
        // One receive loop per transport means a session carried over both a relay and a
        // direct path is decrypted concurrently. An unsynchronised replay window would
        // admit both copies of a duplicate — exactly what it exists to prevent.
        const int Attempts = 200;

        (UniSession initiator, UniSession responder) = CreateSessionPair();

        using (initiator)
        using (responder)
        {
            for (int attempt = 0; attempt < Attempts; attempt++)
            {
                byte[] packet = new byte[UniSession.GetPacketSize(8)];
                int length = initiator.Encrypt("payload!"u8, packet);

                int accepted = 0;

                Parallel.For(0, 2, _ =>
                {
                    byte[] copy = packet.AsSpan(0, length).ToArray();

                    if (responder.TryDecrypt(copy, new byte[length], out _))
                    {
                        Interlocked.Increment(ref accepted);
                    }
                });

                Assert.Equal(1, accepted);
            }
        }
    }

    /// <summary>
    /// Runs a real Noise handshake and builds both sides' sessions from its output.
    /// </summary>
    /// <remarks>
    /// Deliberately not built from two arbitrary keys: the point worth testing is that the
    /// two sides pick opposite directional keys, and only a real split can get that wrong.
    /// </remarks>
    private static (UniSession Initiator, UniSession Responder) CreateSessionPair()
    {
        byte[] initiatorPrivate = new byte[X25519.KeySizeInBytes];
        byte[] responderPrivate = new byte[X25519.KeySizeInBytes];
        initiatorPrivate[0] = 1;
        responderPrivate[0] = 2;

        byte[] responderPublic = new byte[X25519.KeySizeInBytes];
        X25519.GetPublicKey(responderPrivate, responderPublic);

        Assert.True(NoiseIkHandshake.TryCreateInitiator(
            new NoiseHandshakeOptions { StaticPrivateKey = initiatorPrivate },
            responderPublic,
            out NoiseIkHandshake initiatorHandshake));

        using (initiatorHandshake)
        using (NoiseIkHandshake responderHandshake = NoiseIkHandshake.CreateResponder(
            new NoiseHandshakeOptions { StaticPrivateKey = responderPrivate }))
        {
            byte[] message1 = new byte[initiatorHandshake.GetMessageSize(0)];
            int written1 = initiatorHandshake.WriteMessage([], message1);
            Assert.True(responderHandshake.TryReadMessage(message1.AsSpan(0, written1), new byte[written1], out _));

            byte[] message2 = new byte[responderHandshake.GetMessageSize(0)];
            int written2 = responderHandshake.WriteMessage([], message2);
            Assert.True(initiatorHandshake.TryReadMessage(message2.AsSpan(0, written2), new byte[written2], out _));

            using NoiseSplitKeys initiatorKeys = initiatorHandshake.Split();
            using NoiseSplitKeys responderKeys = responderHandshake.Split();

            const uint InitiatorIndex = 111;
            const uint ResponderIndex = 222;

            return (
                UniSession.Create(ChaCha20Poly1305Algorithm.Instance, initiatorKeys, isInitiator: true, InitiatorIndex, ResponderIndex),
                UniSession.Create(ChaCha20Poly1305Algorithm.Instance, responderKeys, isInitiator: false, ResponderIndex, InitiatorIndex));
        }
    }
}
