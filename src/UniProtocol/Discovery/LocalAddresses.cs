using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using UniProtocol.Protocol;

namespace UniProtocol.Discovery;

/// <summary>
/// Enumerates the addresses this machine can be reached at on the local network.
/// </summary>
/// <remarks>
/// A first cut of what path management will do properly. It moves behind the platform
/// abstraction when Android arrives, because <see cref="NetworkInterface"/> is historically
/// incomplete there and the answer has to come from <c>ConnectivityManager</c> instead.
/// </remarks>
internal static class LocalAddresses
{
    /// <summary>
    /// Returns the usable unicast addresses of the given family, paired with
    /// <paramref name="port"/>.
    /// </summary>
    /// <remarks>
    /// Loopback is included only when nothing else is available. It is useless to a peer on
    /// another machine, but it is the only address that works when two processes on one
    /// machine are being paired — which is exactly what someone trying the tool out will do
    /// first.
    /// </remarks>
    public static IReadOnlyList<NetworkAddress> Enumerate(AddressFamily family, ushort port)
    {
        List<NetworkAddress> routable = [];
        List<NetworkAddress> loopback = [];

        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            foreach (UnicastIPAddressInformation unicast in adapter.GetIPProperties().UnicastAddresses)
            {
                IPAddress address = unicast.Address;

                if (address.AddressFamily != family)
                {
                    continue;
                }

                // Link-local IPv6 needs a scope identifier to be usable, and the scope is
                // meaningless to the peer receiving it, so it is not worth advertising.
                if (address.IsIPv6LinkLocal || address.IsIPv6Multicast)
                {
                    continue;
                }

                NetworkAddress converted = NetworkAddress.FromIPEndPoint(new IPEndPoint(address, port));

                if (IPAddress.IsLoopback(address))
                {
                    loopback.Add(converted);
                }
                else
                {
                    routable.Add(converted);
                }
            }
        }

        return routable.Count > 0 ? routable : loopback;
    }
}
