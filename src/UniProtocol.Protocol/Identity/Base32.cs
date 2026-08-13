namespace UniProtocol.Protocol.Identity;

/// <summary>
/// Lowercase RFC 4648 base32 without padding.
/// </summary>
/// <remarks>
/// Node identities and connection tickets get typed, read aloud, pasted into chat and put
/// in QR codes, so the encoding matters. Base32 avoids the case ambiguity of base64 and,
/// unlike hex, keeps a 32-byte key to 52 characters. Decoding is case-insensitive so a key
/// copied from a shouty log still works.
/// </remarks>
public static class Base32
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    private const int BitsPerCharacter = 5;
    private const int BitsPerByte = 8;

    /// <summary>Returns the number of characters <paramref name="byteCount"/> bytes encode to.</summary>
    public static int GetEncodedLength(int byteCount) => ((byteCount * BitsPerByte) + BitsPerCharacter - 1) / BitsPerCharacter;

    /// <summary>Returns the number of bytes <paramref name="characterCount"/> characters decode to.</summary>
    public static int GetDecodedLength(int characterCount) => characterCount * BitsPerCharacter / BitsPerByte;

    /// <summary>Encodes <paramref name="source"/> into <paramref name="destination"/>.</summary>
    public static int Encode(ReadOnlySpan<byte> source, Span<char> destination)
    {
        int required = GetEncodedLength(source.Length);
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, required);

        int accumulator = 0;
        int bitsHeld = 0;
        int written = 0;

        foreach (byte value in source)
        {
            accumulator = (accumulator << BitsPerByte) | value;
            bitsHeld += BitsPerByte;

            while (bitsHeld >= BitsPerCharacter)
            {
                bitsHeld -= BitsPerCharacter;
                destination[written++] = Alphabet[(accumulator >> bitsHeld) & 0x1F];
            }
        }

        if (bitsHeld > 0)
        {
            destination[written++] = Alphabet[(accumulator << (BitsPerCharacter - bitsHeld)) & 0x1F];
        }

        return written;
    }

    /// <summary>Encodes <paramref name="source"/> as a new string.</summary>
    public static string Encode(ReadOnlySpan<byte> source)
    {
        Span<char> destination = stackalloc char[GetEncodedLength(source.Length)];
        int written = Encode(source, destination);

        return new string(destination[..written]);
    }

    /// <summary>
    /// Decodes <paramref name="source"/>, which must encode exactly
    /// <paramref name="destination"/> bytes.
    /// </summary>
    /// <returns><see langword="false"/> for any input that is not a canonical encoding.</returns>
    public static bool TryDecode(ReadOnlySpan<char> source, Span<byte> destination)
        => TryDecode(source, destination, out int written) && written == destination.Length;

    /// <summary>
    /// Decodes <paramref name="source"/> into <paramref name="destination"/>.
    /// </summary>
    /// <returns><see langword="false"/> for any input that is not a canonical encoding.</returns>
    public static bool TryDecode(ReadOnlySpan<char> source, Span<byte> destination, out int written)
    {
        written = 0;

        if (source.Length != GetEncodedLength(GetDecodedLength(source.Length)))
        {
            // A character count that no byte count produces cannot be a canonical encoding.
            return false;
        }

        if (destination.Length < GetDecodedLength(source.Length))
        {
            return false;
        }

        int accumulator = 0;
        int bitsHeld = 0;

        foreach (char character in source)
        {
            int value = DecodeCharacter(character);
            if (value < 0)
            {
                return false;
            }

            accumulator = (accumulator << BitsPerCharacter) | value;
            bitsHeld += BitsPerCharacter;

            if (bitsHeld >= BitsPerByte)
            {
                bitsHeld -= BitsPerByte;
                destination[written++] = (byte)((accumulator >> bitsHeld) & 0xFF);
            }
        }

        // Reject encodings whose trailing bits are non-zero: they would decode to the same
        // bytes as the canonical form, giving one value two spellings.
        int trailingBitsMask = (1 << bitsHeld) - 1;
        return (accumulator & trailingBitsMask) == 0;
    }

    private static int DecodeCharacter(char character) => character switch
    {
        >= 'a' and <= 'z' => character - 'a',
        >= 'A' and <= 'Z' => character - 'A',
        >= '2' and <= '7' => character - '2' + 26,
        _ => -1,
    };
}
