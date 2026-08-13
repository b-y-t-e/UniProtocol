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

        // Create the file with owner-only permissions before writing, so the secret is
        // never briefly world-readable. Writing first and chmod-ing after would leave
        // exactly that window.
        CreateOwnerOnlyFile(_path);
        File.WriteAllText(_path, $"{FormatHeader}{Environment.NewLine}{new string(encoded)}{Environment.NewLine}");

        encoded.Clear();
    }

    private static void CreateOwnerOnlyFile(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            CreateOwnerOnlyFileOnWindows(path);
            return;
        }

        using FileStream stream = new(
            path,
            new FileStreamOptions
            {
                Mode = FileMode.Create,
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
    private static void CreateOwnerOnlyFileOnWindows(string path)
    {
        using WindowsIdentity owner = WindowsIdentity.GetCurrent();

        FileSecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            owner.User ?? throw new InvalidOperationException("The current Windows identity has no user SID."),
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        using FileStream stream = new FileInfo(path).Create(
            FileMode.Create,
            FileSystemRights.WriteData | FileSystemRights.WriteAttributes,
            FileShare.None,
            bufferSize: 1,
            FileOptions.None,
            security);
    }
}
