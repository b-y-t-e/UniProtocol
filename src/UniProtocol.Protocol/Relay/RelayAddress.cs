using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using UniProtocol.Protocol.Identity;

namespace UniProtocol.Protocol.Relay;

/// <summary>
/// Where a relay server is and which key it must prove it holds:
/// <c>unipr://&lt;nodeid&gt;@host:port</c>.
/// </summary>
/// <remarks>
/// The identity is part of the address. A relay is therefore authenticated the same way
/// every other peer is — by key, not by name — so operating one needs no certificate, and
/// neither a hijacked DNS record nor an intercepted connection can substitute a different
/// server. The host and port say where to look; the key says who must answer.
/// </remarks>
public sealed record RelayAddress
{
    /// <summary>The relay's identity.</summary>
    public required NodeId NodeId { get; init; }

    /// <summary>The host name or IP address to connect to.</summary>
    public required string Host { get; init; }

    /// <summary>The TCP port.</summary>
    public int Port { get; init; } = RelayProtocol.DefaultPort;

    /// <summary>Parses <c>unipr://&lt;nodeid&gt;@host[:port]</c>.</summary>
    public static bool TryParse(ReadOnlySpan<char> text, [NotNullWhen(true)] out RelayAddress? address)
    {
        address = null;
        text = text.Trim();

        ReadOnlySpan<char> prefix = $"{RelayProtocol.UriScheme}://";
        if (!text.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        text = text[prefix.Length..];

        int at = text.IndexOf('@');
        if (at <= 0 || at == text.Length - 1)
        {
            return false;
        }

        if (!NodeId.TryParse(text[..at], out NodeId nodeId))
        {
            return false;
        }

        ReadOnlySpan<char> authority = text[(at + 1)..];
        int port = RelayProtocol.DefaultPort;

        // A bracketed IPv6 literal contains colons of its own, so the port separator is the
        // last colon and only counts when it follows the closing bracket.
        int colon = authority[^1] == ']' ? -1 : authority.LastIndexOf(':');

        if (colon >= 0 && authority[..colon].LastIndexOf(']') < colon)
        {
            if (!int.TryParse(authority[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port)
                || port is < 1 or > 65535)
            {
                return false;
            }

            authority = authority[..colon];
        }

        if (authority.IsEmpty)
        {
            return false;
        }

        address = new RelayAddress
        {
            NodeId = nodeId,
            Host = authority.ToString(),
            Port = port,
        };

        return true;
    }

    /// <summary>Parses a relay address, throwing on malformed input.</summary>
    public static RelayAddress Parse(ReadOnlySpan<char> text)
        => TryParse(text, out RelayAddress? address)
            ? address
            : throw new FormatException($"'{new string(text)}' is not a valid relay address.");

    /// <inheritdoc />
    public override string ToString()
        => string.Create(
            CultureInfo.InvariantCulture,
            $"{RelayProtocol.UriScheme}://{NodeId}@{Host}:{Port}");
}
