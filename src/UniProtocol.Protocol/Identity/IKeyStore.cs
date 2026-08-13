using System.Diagnostics.CodeAnalysis;

namespace UniProtocol.Protocol.Identity;

/// <summary>
/// Persists a node's long-term identity.
/// </summary>
/// <remarks>
/// Abstracted because where a seed belongs is entirely platform-specific: a file on a
/// server, <c>EncryptedSharedPreferences</c> backed by the hardware keystore on Android,
/// the Keychain on Apple platforms, or nothing at all for an ephemeral test node. The core
/// only needs "give me my identity".
/// </remarks>
public interface IKeyStore
{
    /// <summary>Loads the stored identity, if there is one.</summary>
    bool TryLoad([NotNullWhen(true)] out UniIdentity? identity);

    /// <summary>Stores <paramref name="identity"/>, replacing any existing one.</summary>
    void Save(UniIdentity identity);

    /// <summary>
    /// Loads the stored identity, creating and saving a new one when none exists.
    /// </summary>
    sealed UniIdentity LoadOrCreate()
    {
        if (TryLoad(out UniIdentity? identity))
        {
            return identity;
        }

        identity = UniIdentity.Generate();
        Save(identity);

        return identity;
    }
}
