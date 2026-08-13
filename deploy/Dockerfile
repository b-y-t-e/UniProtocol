# Relay server image. Native AOT, so the runtime image carries no .NET installation and
# starts in milliseconds.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

# Native AOT needs a C toolchain and zlib to link the final binary.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends clang zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Restore first, against just the project graph, so editing source does not invalidate the
# package cache layer.
COPY global.json NuGet.config Directory.Build.props Directory.Build.targets Directory.Packages.props BannedSymbols.txt ./
COPY src/UniProtocol.Crypto/UniProtocol.Crypto.csproj        src/UniProtocol.Crypto/
COPY src/UniProtocol.Protocol/UniProtocol.Protocol.csproj    src/UniProtocol.Protocol/
COPY src/UniProtocol.Server/UniProtocol.Server.csproj        src/UniProtocol.Server/
COPY src/UniProtocol.Server.Host/UniProtocol.Server.Host.csproj src/UniProtocol.Server.Host/
RUN dotnet restore src/UniProtocol.Server.Host/UniProtocol.Server.Host.csproj

COPY src/ src/
RUN dotnet publish src/UniProtocol.Server.Host/UniProtocol.Server.Host.csproj \
        --configuration Release \
        --output /app

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0

# The relay handles untrusted input from the internet, so it does not run as root. Binding
# port 443 is left to the container runtime (publish it as -p 443:8443) rather than granting
# the process the capability to bind a privileged port itself.
RUN useradd --system --create-home --home-dir /var/lib/uniprotocol --uid 10001 uniprotocol

WORKDIR /app
COPY --from=build /app/unipd ./unipd

USER uniprotocol

# The identity lives here; mount a volume so the relay keeps the same NodeId across
# restarts. Clients pin that key, so losing it means reissuing every relay address.
ENV UNIPD_KEY=/var/lib/uniprotocol/relay.key
VOLUME ["/var/lib/uniprotocol"]

EXPOSE 8443

ENTRYPOINT ["/app/unipd", "--port", "8443", "--path", "/var/lib/uniprotocol/relay.key"]
