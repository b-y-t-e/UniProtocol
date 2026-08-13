using UniProtocol.Sessions;

namespace UniProtocol.Tests.Sessions;

public sealed class ReplayWindowTests
{
    [Fact]
    public void TryAccept_InOrderCounters_AllAccepted()
    {
        ReplayWindow window = new();

        for (ulong counter = 0; counter < 10_000; counter++)
        {
            Assert.True(window.TryAccept(counter), $"counter {counter} was rejected");
        }
    }

    [Fact]
    public void TryAccept_SameCounterTwice_RejectsTheSecond()
    {
        ReplayWindow window = new();

        Assert.True(window.TryAccept(7));
        Assert.False(window.TryAccept(7));
    }

    [Fact]
    public void TryAccept_ReorderedWithinTheWindow_AllAccepted()
    {
        // Reordering is normal on a UDP path, so a window that only accepted increasing
        // counters would discard perfectly good packets.
        ReplayWindow window = new();

        Assert.True(window.TryAccept(100));
        Assert.True(window.TryAccept(97));
        Assert.True(window.TryAccept(99));
        Assert.True(window.TryAccept(98));

        Assert.False(window.TryAccept(99));
        Assert.Equal(100u, window.HighestAccepted);
    }

    [Fact]
    public void TryAccept_CounterOlderThanTheWindow_Rejected()
    {
        ReplayWindow window = new();

        Assert.True(window.TryAccept(ReplayWindow.WindowSizeInCounters + 500));
        Assert.False(window.TryAccept(499));
        Assert.True(window.TryAccept(501));
    }

    [Fact]
    public void TryAccept_LargeJumpForward_ClearsTheWindowSoOldCountersCannotReplay()
    {
        // After a jump larger than the window, every slot in the circular bitmap has been
        // reused. If the jump did not clear it, an old counter would collide with a stale
        // bit and be misreported — in one direction as a replay, in the other as fresh.
        ReplayWindow window = new();

        Assert.True(window.TryAccept(5));
        Assert.True(window.TryAccept(1_000_000));

        // Counter 5 is far outside the window now and must be rejected as too old.
        Assert.False(window.TryAccept(5));

        // A counter just inside the window must still be accepted exactly once.
        ulong justInside = 1_000_000 - ReplayWindow.WindowSizeInCounters + 1;
        Assert.True(window.TryAccept(justInside));
        Assert.False(window.TryAccept(justInside));
    }

    [Fact]
    public void TryAccept_StepAcrossTheWindowBoundary_DoesNotResurrectOldCounters()
    {
        ReplayWindow window = new();

        for (ulong counter = 0; counter < ReplayWindow.WindowSizeInCounters; counter++)
        {
            Assert.True(window.TryAccept(counter));
        }

        // This wraps the bitmap onto the slot counter 0 used. That slot must have been
        // cleared as the window advanced over it.
        Assert.True(window.TryAccept(ReplayWindow.WindowSizeInCounters));
        Assert.False(window.TryAccept(ReplayWindow.WindowSizeInCounters));

        // And counter 0 has now fallen out of the window entirely.
        Assert.False(window.TryAccept(0));
    }

    [Fact]
    public void TryAccept_FirstCounterIsNotZero_StillAccepted()
    {
        // Session counters start at zero today, but nothing in the window's contract says
        // they must, and a rekey will eventually hand it a counter that does not.
        ReplayWindow window = new();

        Assert.True(window.TryAccept(ulong.MaxValue / 2));
    }
}
