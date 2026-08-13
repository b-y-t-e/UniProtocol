namespace UniProtocol.Sessions;

/// <summary>
/// A sliding window that accepts each packet counter exactly once.
/// </summary>
/// <remarks>
/// <para>
/// The AEAD guarantees a packet was produced by the peer; it says nothing about whether
/// the peer sent it once. Without this, anyone who can copy a datagram can replay it, and
/// the transport above would count it as newly delivered data.
/// </para>
/// <para>
/// The window has to be wide because UniProtocol runs over UDP: packets legitimately
/// arrive out of order, and a window narrower than the reordering the path produces would
/// discard valid traffic. 8192 counters is far beyond any reordering seen in practice
/// while costing one kilobyte per session.
/// </para>
/// <para>
/// The bitmap is indexed circularly by counter, so advancing the window is a matter of
/// clearing the newly exposed bits rather than shifting a kilobyte of state.
/// </para>
/// <para>
/// Not thread-safe: it is owned by a single connection loop.
/// </para>
/// </remarks>
internal sealed class ReplayWindow
{
    /// <summary>Number of counters the window covers.</summary>
    public const int WindowSizeInCounters = 8192;

    private const int WordCount = WindowSizeInCounters / 64;

    private readonly ulong[] _seen = new ulong[WordCount];

    private ulong _highestAccepted;
    private bool _hasAccepted;

    /// <summary>The highest counter accepted so far.</summary>
    public ulong HighestAccepted => _highestAccepted;

    /// <summary>
    /// Records <paramref name="counter"/> as seen.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> if the counter was already seen or has fallen out of the
    /// window, in which case the packet must be discarded.
    /// </returns>
    /// <remarks>
    /// Call this only <em>after</em> the packet has been authenticated. Updating the window
    /// from an unauthenticated header would let an attacker advance it with a forged
    /// counter and cause genuine packets to be rejected as replays.
    /// </remarks>
    public bool TryAccept(ulong counter)
    {
        if (!_hasAccepted)
        {
            _hasAccepted = true;
            _highestAccepted = counter;
            Set(counter);
            return true;
        }

        if (counter > _highestAccepted)
        {
            ulong advance = counter - _highestAccepted;

            if (advance >= WindowSizeInCounters)
            {
                Array.Clear(_seen);
            }
            else
            {
                // Clear only the counters the window has just moved over; everything else
                // keeps its recorded state.
                for (ulong intermediate = _highestAccepted + 1; intermediate <= counter; intermediate++)
                {
                    Clear(intermediate);
                }
            }

            _highestAccepted = counter;
            Set(counter);
            return true;
        }

        if (_highestAccepted - counter >= WindowSizeInCounters)
        {
            return false;
        }

        if (IsSet(counter))
        {
            return false;
        }

        Set(counter);
        return true;
    }

    private static (int Word, ulong Mask) Locate(ulong counter)
    {
        ulong index = counter % WindowSizeInCounters;
        return ((int)(index >> 6), 1UL << (int)(index & 63));
    }

    private bool IsSet(ulong counter)
    {
        (int word, ulong mask) = Locate(counter);
        return (_seen[word] & mask) != 0;
    }

    private void Set(ulong counter)
    {
        (int word, ulong mask) = Locate(counter);
        _seen[word] |= mask;
    }

    private void Clear(ulong counter)
    {
        (int word, ulong mask) = Locate(counter);
        _seen[word] &= ~mask;
    }
}
