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

    [Fact]
    public void Save_FailingPartWayThrough_LeavesTheExistingKeyIntact()
    {
        // The one mistake here whose damage cannot be undone. Truncating the real file and
        // writing into it means a crash, a full disk or a power cut destroys the identity:
        // every ticket naming it, and for a relay every client that pinned it, stops working
        // and no backup short of the file itself can bring it back.
        FileKeyStore store = new(KeyPath);

        using UniIdentity original = UniIdentity.Generate();
        store.Save(original);

        // Standing in for the crash: a directory that cannot be written to makes the staging
        // write fail at the point where the old code had already truncated the key itself.
        using (UniIdentity replacement = UniIdentity.Generate())
        {
            MakeDirectoryUnwritable();

            try
            {
                store.Save(replacement);
            }
#pragma warning disable CA1031 // Whether it throws is not the point; what survives is.
            catch (Exception)
            {
                // Expected. The assertion that matters is the one below.
            }
#pragma warning restore CA1031
            finally
            {
                RestoreDirectory();
            }
        }

        Assert.True(store.TryLoad(out UniIdentity? survivor));

        using (survivor)
        {
            Assert.Equal(original.NodeId, survivor.NodeId);
        }
    }

    [Fact]
    public void Save_OverAnExistingKey_ReplacesItAndLeavesNoTemporaryFileBehind()
    {
        FileKeyStore store = new(KeyPath);

        using UniIdentity first = UniIdentity.Generate();
        store.Save(first);

        using UniIdentity second = UniIdentity.Generate();
        store.Save(second);

        Assert.True(store.TryLoad(out UniIdentity? loaded));

        using (loaded)
        {
            Assert.Equal(second.NodeId, loaded.NodeId);
        }

        Assert.Empty(Directory.GetFiles(_directory, "*" + FileKeyStore.TemporarySuffix));
    }

    [Fact]
    public void Save_WithAStaleTemporaryFilePresent_DoesNotInheritItsPermissions()
    {
        // Permissions are applied when a file is created, never when an existing one is
        // opened — and the temporary file is then moved onto the key, carrying its access
        // list with it. A leftover .tmp, which is precisely what an interrupted save leaves
        // behind, would hand the key whatever permissions that file happened to have.
        Directory.CreateDirectory(_directory);

        string temporaryPath = KeyPath + ".abcdefgh.ijk" + FileKeyStore.TemporarySuffix;
        File.WriteAllText(temporaryPath, "left over from a save that died");

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                temporaryPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }

        FileKeyStore store = new(KeyPath);
        using UniIdentity identity = UniIdentity.Generate();
        store.Save(identity);

        Assert.True(store.TryLoad(out UniIdentity? loaded));

        using (loaded)
        {
            Assert.Equal(identity.NodeId, loaded.NodeId);
        }

        if (!OperatingSystem.IsWindows())
        {
            UnixFileMode mode = File.GetUnixFileMode(KeyPath);
            Assert.Equal(UnixFileMode.None, mode & (UnixFileMode.GroupRead | UnixFileMode.OtherRead));
        }
    }

    /// <summary>
    /// Makes file creation in the key's directory fail, on either platform.
    /// </summary>
    /// <remarks>
    /// The read-only attribute does not stop file creation on Windows, so that platform needs
    /// an explicit deny entry.
    /// </remarks>
    private void MakeDirectoryUnwritable()
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(_directory, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            return;
        }

        SetWindowsCreateFilesDenied(denied: true);
    }

    private void RestoreDirectory()
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                _directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            return;
        }

        SetWindowsCreateFilesDenied(denied: false);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void SetWindowsCreateFilesDenied(bool denied)
    {
        using System.Security.Principal.WindowsIdentity self = System.Security.Principal.WindowsIdentity.GetCurrent();

        System.Security.AccessControl.DirectorySecurity security = new DirectoryInfo(_directory).GetAccessControl();
        System.Security.AccessControl.FileSystemAccessRule rule = new(
            self.User!,
            System.Security.AccessControl.FileSystemRights.CreateFiles,
            System.Security.AccessControl.AccessControlType.Deny);

        if (denied)
        {
            security.AddAccessRule(rule);
        }
        else
        {
            security.RemoveAccessRule(rule);
        }

        new DirectoryInfo(_directory).SetAccessControl(security);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
