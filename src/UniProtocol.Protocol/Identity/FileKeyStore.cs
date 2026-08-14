using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace UniProtocol.Protocol.Identity;

/// <summary>
/// Stores the identity seed in a single file, readable only by its owner.
/// </summary>
/// <remarks>
/// <para>
/// The format is deliberately boring: a version line and the base32 seed. It is
/// hand-inspectable, safe to copy between machines, and survives a text editor.
/// </para>
/// <para>
/// The seed is stored in the clear, protected by file permissions alone. That is
/// appropriate for a server whose disk is already trusted, and it is <em>not</em>
/// appropriate for a shared or removable device — those platforms get a keystore backed by
/// the OS secret store instead.
/// </para>
/// </remarks>
public sealed class FileKeyStore : IKeyStore
{
    private const string FormatHeader = "uniprotocol-key-v1";

    /// <summary>Suffix of the files a save is staged in before one replaces the real one.</summary>
    /// <remarks>
    /// The full name has a random component in front of this, so two processes saving at once
    /// cannot pick the same staging file. Public so that cleanup and tests can recognise one.
    /// </remarks>
    public const string TemporarySuffix = ".tmp";

    private readonly string _path;

    /// <summary>Creates a store backed by the file at <paramref name="path"/>.</summary>
    public FileKeyStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        _path = path;
    }

    /// <summary>The default location, under the user's application data directory.</summary>
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create),
        "uniprotocol",
        "node.key");

    /// <inheritdoc />
    public bool TryLoad([NotNullWhen(true)] out UniIdentity? identity)
    {
        identity = null;

        if (!File.Exists(_path))
        {
            return false;
        }

        string[] lines = File.ReadAllLines(_path);
        if (lines.Length < 2 || !string.Equals(lines[0].Trim(), FormatHeader, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                string.Create(CultureInfo.InvariantCulture, $"'{_path}' is not a UniProtocol key file."));
        }

        Span<byte> seed = stackalloc byte[UniIdentity.SeedSizeInBytes];

        if (!Base32.TryDecode(lines[1].Trim(), seed))
        {
            throw new InvalidDataException(
                string.Create(CultureInfo.InvariantCulture, $"The seed in '{_path}' is malformed."));
        }

        identity = UniIdentity.FromSeed(seed);
        CryptographicOperations.ZeroMemory(seed);

        return true;
    }

    /// <inheritdoc />
    public void Save(UniIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        string? directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        Span<byte> seed = stackalloc byte[UniIdentity.SeedSizeInBytes];
        identity.ExportSeed(seed);

        Span<char> encoded = stackalloc char[Base32.GetEncodedLength(UniIdentity.SeedSizeInBytes)];
        Base32.Encode(seed, encoded);
        CryptographicOperations.ZeroMemory(seed);

        // Written to a staging file and then moved into place. Truncating the real file and
        // writing into it is the one mistake here whose damage cannot be undone: a crash, a
        // full disk or a power cut between the two leaves an empty key file, and the identity
        // it held is gone — every ticket naming it, and for a relay every client that pinned
        // it, is dead. A move within one directory is atomic on both Windows and POSIX, so a
        // reader sees either the old key or the new one and never a half-written one.
        //
        // The staging name is unique rather than fixed. Two processes pointed at the same key
        // file — two unipd instances, or a service racing an operator running the CLI — would
        // otherwise choose the same path and one would truncate the file the other was
        // partway through writing. A random name also removes the need to clear a leftover
        // first, which was itself a race between the check and the create.
        //
        // Path.GetRandomFileName is not the seeded IRandomSource the rest of the codebase
        // uses, and should not be: this names a file, never anything a peer observes or a
        // simulator has to reproduce, and a reproducible name would defeat the whole point.
        string temporaryPath = _path + "." + Path.GetRandomFileName() + TemporarySuffix;

        try
        {
            // CreateNew, never Create. An access list — and a Unix mode — is applied only
            // when a file is *created*: opening an existing one keeps whatever permissions it
            // already had, and File.Move then carries those onto the key. Under ProgramData
            // that would mean every local account could read the relay's private key.
            using (FileStream stream = CreateOwnerOnlyFile(temporaryPath))
            {
                using (StreamWriter writer = new(stream, leaveOpen: true))
                {
                    // Written through the handle that carries the permissions, so the secret
                    // is never on disk under any others, not even briefly.
                    writer.Write(FormatHeader);
                    writer.Write(Environment.NewLine);
                    writer.Write(encoded);
                    writer.Write(Environment.NewLine);
                }

                // Forced to the platter before the rename. Without it the move can be durable
                // while the bytes it points at are not, and a crash leaves a key file that
                // exists, is the right length, and is full of zeros — the exact outcome the
                // staging file was introduced to prevent.
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, _path, overwrite: true);
        }
        catch
        {
            TryDelete(temporaryPath);
            throw;
        }
        finally
        {
            encoded.Clear();
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
#pragma warning disable CA1031 // Cleaning up after a failed save must not mask the failure.
        catch (Exception)
        {
            // The temporary file is left behind; the next save overwrites it.
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Creates a new file readable only by its owner and returns the handle to write through.
    /// </summary>
    /// <remarks>
    /// <see cref="FileMode.CreateNew"/>, never <see cref="FileMode.Create"/>: permissions are
    /// applied at creation only, so reusing an existing file silently keeps that file's
    /// permissions.
    /// </remarks>
    private static FileStream CreateOwnerOnlyFile(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return CreateOwnerOnlyFileOnWindows(path);
        }

        return new FileStream(
            path,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
    }

    /// <summary>
    /// Creates the file with an explicit access list naming only its owner.
    /// </summary>
    /// <remarks>
    /// The permissions cannot be left to inheritance. A key file under the user's profile
    /// would indeed inherit an owner-only list, but this store is also pointed at shared
    /// locations — a relay's key lives under <c>ProgramData</c>, which grants
    /// <c>BUILTIN\Users</c> read access and passes it down. Inheriting there would publish the
    /// relay's private key to every account on the machine.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    private static FileStream CreateOwnerOnlyFileOnWindows(string path)
    {
        using WindowsIdentity owner = WindowsIdentity.GetCurrent();

        FileSecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            owner.User ?? throw new InvalidOperationException("The current Windows identity has no user SID."),
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        return new FileInfo(path).Create(
            FileMode.CreateNew,
            FileSystemRights.WriteData | FileSystemRights.WriteAttributes,
            FileShare.None,
            bufferSize: 4096,
            FileOptions.None,
            security);
    }
}
