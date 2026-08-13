using System.Buffers.Binary;
using System.Text;

namespace UniProtocol.Discovery.Mdns;

/// <summary>
/// Reads and writes the small subset of DNS needed to advertise and find one service type.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not a general DNS library. UniProtocol advertises exactly one service,
/// <c>_uniprotocol._udp.local</c>, and the whole payload it needs to publish is a ticket in
/// a TXT record. Writing only that costs a couple of hundred lines; a general
/// implementation would be an order of magnitude more code to maintain for no benefit.
/// </para>
/// <para>
/// The writer emits uncompressed names, which is legal and keeps it simple. The reader
/// <em>must</em> handle compression pointers, because other implementations — Avahi,
/// Bonjour, every printer on the network — do use them.
/// </para>
/// </remarks>
internal static class MdnsMessage
{
    /// <summary>The DNS-SD service type UniProtocol nodes advertise.</summary>
    public const string ServiceName = "_uniprotocol._udp.local";

    /// <summary>The TXT key whose value is a connection ticket.</summary>
    public const string TicketKey = "t=";

    private const ushort ResponseFlags = 0x8400; // QR = response, AA = authoritative
    private const ushort ClassInternet = 1;
    private const ushort CacheFlushBit = 0x8000;
    private const uint DefaultTimeToLiveInSeconds = 120;

    private const ushort TypePointer = 12;
    private const ushort TypeText = 16;
    private const ushort TypeService = 33;

    /// <summary>Writes a query for the UniProtocol service type.</summary>
    public static int WriteQuery(Span<byte> destination, ushort transactionId)
    {
        int position = 0;

        WriteHeader(destination, ref position, transactionId, flags: 0, questionCount: 1, answerCount: 0, additionalCount: 0);
        WriteName(destination, ref position, ServiceName);
        WriteUInt16(destination, ref position, TypePointer);
        WriteUInt16(destination, ref position, ClassInternet);

        return position;
    }

    /// <summary>
    /// Writes a response advertising one node: a PTR to the instance, an SRV giving its
    /// port, and a TXT carrying its ticket.
    /// </summary>
    public static int WriteResponse(Span<byte> destination, string instanceLabel, ushort port, string ticket)
    {
        string instanceName = $"{instanceLabel}.{ServiceName}";
        string hostName = $"{instanceLabel}.local";

        int position = 0;
        WriteHeader(destination, ref position, transactionId: 0, ResponseFlags, questionCount: 0, answerCount: 3, additionalCount: 0);

        // PTR: service type -> instance
        WriteRecordHeader(destination, ref position, ServiceName, TypePointer, ClassInternet, out int pointerLength);
        WriteName(destination, ref position, instanceName);
        FillLength(destination, pointerLength, position);

        // SRV: instance -> host and port
        WriteRecordHeader(destination, ref position, instanceName, TypeService, ClassInternet | CacheFlushBit, out int serviceLength);
        WriteUInt16(destination, ref position, 0); // priority
        WriteUInt16(destination, ref position, 0); // weight
        WriteUInt16(destination, ref position, port);
        WriteName(destination, ref position, hostName);
        FillLength(destination, serviceLength, position);

        // TXT: instance -> the ticket, which already carries the identity and addresses
        WriteRecordHeader(destination, ref position, instanceName, TypeText, ClassInternet | CacheFlushBit, out int textLength);
        WriteCharacterString(destination, ref position, TicketKey + ticket);
        FillLength(destination, textLength, position);

        return position;
    }

    /// <summary>
    /// Extracts every ticket advertised in <paramref name="message"/>.
    /// </summary>
    /// <remarks>
    /// Only TXT records are read. The ticket in one already names the identity and the
    /// addresses, so the SRV and A records add nothing we would trust more — an address
    /// learned from a record we did not authenticate is a hint either way, and the identity
    /// is verified by the handshake regardless.
    /// </remarks>
    public static void ReadTickets(ReadOnlySpan<byte> message, List<string> tickets)
    {
        ArgumentNullException.ThrowIfNull(tickets);

        if (message.Length < 12)
        {
            return;
        }

        int questionCount = BinaryPrimitives.ReadUInt16BigEndian(message[4..]);
        int recordCount = BinaryPrimitives.ReadUInt16BigEndian(message[6..])
            + BinaryPrimitives.ReadUInt16BigEndian(message[8..])
            + BinaryPrimitives.ReadUInt16BigEndian(message[10..]);

        int position = 12;

        for (int i = 0; i < questionCount; i++)
        {
            if (!TrySkipName(message, ref position) || message.Length - position < 4)
            {
                return;
            }

            position += 4;
        }

        for (int i = 0; i < recordCount; i++)
        {
            if (!TrySkipName(message, ref position) || message.Length - position < 10)
            {
                return;
            }

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(message[position..]);
            int dataLength = BinaryPrimitives.ReadUInt16BigEndian(message[(position + 8)..]);
            position += 10;

            if (message.Length - position < dataLength)
            {
                return;
            }

            if (type == TypeText)
            {
                ReadTicketsFromTextRecord(message.Slice(position, dataLength), tickets);
            }

            position += dataLength;
        }
    }

    private static void ReadTicketsFromTextRecord(ReadOnlySpan<byte> data, List<string> tickets)
    {
        int position = 0;

        while (position < data.Length)
        {
            int length = data[position++];

            if (length == 0 || data.Length - position < length)
            {
                return;
            }

            ReadOnlySpan<byte> entry = data.Slice(position, length);
            position += length;

            if (entry.Length > TicketKey.Length
                && entry[0] == (byte)'t'
                && entry[1] == (byte)'=')
            {
                tickets.Add(Encoding.ASCII.GetString(entry[TicketKey.Length..]));
            }
        }
    }

    private static void WriteHeader(
        Span<byte> destination,
        ref int position,
        ushort transactionId,
        ushort flags,
        ushort questionCount,
        ushort answerCount,
        ushort additionalCount)
    {
        WriteUInt16(destination, ref position, transactionId);
        WriteUInt16(destination, ref position, flags);
        WriteUInt16(destination, ref position, questionCount);
        WriteUInt16(destination, ref position, answerCount);
        WriteUInt16(destination, ref position, 0);
        WriteUInt16(destination, ref position, additionalCount);
    }

    private static void WriteRecordHeader(
        Span<byte> destination,
        ref int position,
        string name,
        ushort type,
        ushort recordClass,
        out int lengthPosition)
    {
        WriteName(destination, ref position, name);
        WriteUInt16(destination, ref position, type);
        WriteUInt16(destination, ref position, recordClass);
        WriteUInt32(destination, ref position, DefaultTimeToLiveInSeconds);

        lengthPosition = position;
        WriteUInt16(destination, ref position, 0);
    }

    private static void FillLength(Span<byte> destination, int lengthPosition, int endPosition)
        => BinaryPrimitives.WriteUInt16BigEndian(destination[lengthPosition..], (ushort)(endPosition - lengthPosition - 2));

    private static void WriteName(Span<byte> destination, ref int position, string name)
    {
        foreach (Range labelRange in name.AsSpan().Split('.'))
        {
            ReadOnlySpan<char> label = name.AsSpan()[labelRange];

            if (label.IsEmpty)
            {
                continue;
            }

            destination[position++] = (byte)label.Length;
            position += Encoding.ASCII.GetBytes(label, destination[position..]);
        }

        destination[position++] = 0;
    }

    private static void WriteCharacterString(Span<byte> destination, ref int position, string value)
    {
        int length = Encoding.ASCII.GetByteCount(value);

        // A DNS character string is length-prefixed with a single byte, so it cannot exceed
        // 255 bytes. A ticket is far shorter, but the limit is checked rather than assumed.
        if (length > 255)
        {
            throw new InvalidOperationException("A TXT entry may not exceed 255 bytes.");
        }

        destination[position++] = (byte)length;
        position += Encoding.ASCII.GetBytes(value, destination[position..]);
    }

    private static void WriteUInt16(Span<byte> destination, ref int position, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination[position..], value);
        position += 2;
    }

    private static void WriteUInt32(Span<byte> destination, ref int position, uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination[position..], value);
        position += 4;
    }

    /// <summary>
    /// Advances past a name, following compression pointers.
    /// </summary>
    /// <remarks>
    /// A pointer ends the name, so the position only ever needs to move past the two
    /// pointer bytes — there is no need to follow it to read the labels, and not following
    /// it also removes any chance of a pointer loop stalling the reader.
    /// </remarks>
    private static bool TrySkipName(ReadOnlySpan<byte> message, ref int position)
    {
        while (true)
        {
            if (position >= message.Length)
            {
                return false;
            }

            byte length = message[position];

            if (length == 0)
            {
                position++;
                return true;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (message.Length - position < 2)
                {
                    return false;
                }

                position += 2;
                return true;
            }

            if (length > 63 || message.Length - position < length + 1)
            {
                return false;
            }

            position += length + 1;
        }
    }
}
