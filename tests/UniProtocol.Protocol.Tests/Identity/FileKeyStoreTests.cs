using UniProtocol.Protocol.Identity;

namespace UniProtocol.Protocol.Tests.Identity;

public sealed class FileKeyStoreTests : IDisposable
{
    private static int _instanceCounter;

    // A counter rather than a GUID: the banned-API rules keep non-reproducible sources out
    // of the codebase, and a per-process counter is unique enough for a temp directory.
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "uniprotocol-tests",
        $"{Environment.ProcessId}-{Interlocked.Increment(ref _instanceCounter)}");

    private string KeyPath => Path.Combine(_directory, "node.key");

    [Fact]
    public void TryLoad_NoFile_ReturnsFalse()
    {
        FileKeyStore store = new(KeyPath);

        Assert.False(store.TryLoad(out _));
    }

    [Fact]
    public void SaveThenLoad_RestoresTheSameIdentity()
    {
        FileKeyStore store = new(KeyPath);

        using UniIdentity original = UniIdentity.Generate();
        store.Save(original);

        Assert.True(store.TryLoad(out UniIdentity? restored));

        using (restored)
        {
            Assert.Equal(original.NodeId, restored.NodeId);
        }
    }

    [Fact]
    public void LoadOrCreate_CalledTwice_ReturnsTheSameIdentity()
    {
        IKeyStore store = new FileKeyStore(KeyPath);

        using UniIdentity first = store.LoadOrCreate();
        using UniIdentity second = store.LoadOrCreate();

        Assert.Equal(first.NodeId, second.NodeId);
    }

    [Fact]
    public void TryLoad_CorruptedFile_ThrowsWithTheOffendingPath()
    {
        Directory.CreateDirectory(_directory);
        File.WriteAllText(KeyPath, "not a key file");

        FileKeyStore store = new(KeyPath);

        InvalidDataException exception = Assert.Throws<InvalidDataException>(() => store.TryLoad(out _));
        Assert.Contains(KeyPath, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TryLoad_MalformedSeed_Throws()
    {
        Directory.CreateDirectory(_directory);
        File.WriteAllLines(KeyPath, ["uniprotocol-key-v1", "!!!not-base32!!!"]);

        FileKeyStore store = new(KeyPath);

        Assert.Throws<InvalidDataException>(() => store.TryLoad(out _));
    }

    [Fact]
    public void Save_CreatesAFileReadableOnlyByItsOwnerOnUnix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        FileKeyStore store = new(KeyPath);
        using UniIdentity identity = UniIdentity.Generate();
        store.Save(identity);

        UnixFileMode mode = File.GetUnixFileMode(KeyPath);

        Assert.Equal(UnixFileMode.None, mode & (UnixFileMode.GroupRead | UnixFileMode.OtherRead));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
