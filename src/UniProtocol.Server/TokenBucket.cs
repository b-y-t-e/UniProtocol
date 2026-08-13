namespace UniProtocol.Server;

/// <summary>A simple token bucket, refilled continuously at a fixed rate.</summary>
/// <remarks>
/// A relay forwards on behalf of clients it has authenticated but has no reason to trust,
/// and the bandwidth is the operator's to pay for. The bucket allows a short burst — real
/// traffic is bursty and a strict per-second cap would clip normal use — while bounding the
/// sustained rate.
/// </remarks>
internal sealed class TokenBucket
{
    private readonly double _tokensPerSecond;
    private readonly double _capacity;
    private readonly TimeProvider _timeProvider;
    private readonly Lock _gate = new();

    private double _available;
    private long _lastRefillTimestamp;

    public TokenBucket(int tokensPerSecond, TimeProvider timeProvider)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(tokensPerSecond, 1);

        _tokensPerSecond = tokensPerSecond;
        _capacity = tokensPerSecond;
        _timeProvider = timeProvider;
        _available = tokensPerSecond;
        _lastRefillTimestamp = timeProvider.GetTimestamp();
    }

    /// <summary>Takes one token if any are available.</summary>
    public bool TryConsume()
    {
        lock (_gate)
        {
            long now = _timeProvider.GetTimestamp();
            double elapsedSeconds = _timeProvider.GetElapsedTime(_lastRefillTimestamp, now).TotalSeconds;
            _lastRefillTimestamp = now;

            _available = Math.Min(_capacity, _available + (elapsedSeconds * _tokensPerSecond));

            if (_available < 1)
            {
                return false;
            }

            _available -= 1;
            return true;
        }
    }
}
