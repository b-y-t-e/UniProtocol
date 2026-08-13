<#
.SYNOPSIS
    Installs unipd on Windows so it starts at boot and restarts if it stops.

.DESCRIPTION
    Registers a scheduled task rather than a Windows service. unipd is a plain console
    application: sc.exe can be pointed at one, but it will not answer the service control
    manager and Windows kills it shortly after start. A scheduled task triggered at boot,
    running whether or not anyone is logged on and restarting on failure, gives the same
    practical behaviour without pretending to be something it is not.

    For a genuine service entry, wrap the binary with NSSM or WinSW; both drive an
    unmodified console application correctly.

.PARAMETER PublicHost
    The name or IP address clients will use to reach this machine. It goes into the printed
    relay address.

.PARAMETER Port
    TCP port to listen on. Defaults to 443.

.PARAMETER InstallPath
    Where to copy the binary. Defaults to C:\Program Files\UniProtocol.

.EXAMPLE
    .\install-windows.ps1 -PublicHost relay.example.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PublicHost,

    [int] $Port = 443,

    [string] $InstallPath = "$env:ProgramFiles\UniProtocol"
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell prompt: it writes to Program Files and registers a boot task.'
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $repositoryRoot 'src\UniProtocol.Server.Host'

Write-Host 'Publishing unipd...' -ForegroundColor Cyan
dotnet publish $projectPath --configuration Release --runtime win-x64 --output "$InstallPath" | Out-Null

$executable = Join-Path $InstallPath 'unipd.exe'
if (-not (Test-Path $executable)) {
    throw "Publish did not produce $executable."
}

# The key lives outside Program Files so an upgrade that replaces the binaries cannot take
# the relay's identity with it. Clients pin that key.
$dataPath = Join-Path $env:ProgramData 'UniProtocol'
$keyPath = Join-Path $dataPath 'relay.key'
New-Item -ItemType Directory -Path $dataPath -Force | Out-Null

# Lock the directory down BEFORE the key file is created. ProgramData grants BUILTIN\Users
# read access and passes it down by inheritance, so a directory created there with default
# permissions would put the relay's private key — the thing every client pins — in reach of
# any account on the machine. Inheritance is switched off entirely rather than adding a Deny
# rule, because a Deny would also have to be maintained against every future inherited ACE.
Write-Host 'Restricting access to the key directory...' -ForegroundColor Cyan

$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)   # protected, and drop the inherited rules

# Identified by well-known SID, not by name: the account names are localised, so
# 'BUILTIN\Administrators' does not resolve on a non-English Windows.
$administrators = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

foreach ($wellKnown in 'LocalSystemSid', 'BuiltinAdministratorsSid', 'LocalServiceSid') {
    $sid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::$wellKnown, $null)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}

$acl.SetOwner($administrators)
Set-Acl -Path $dataPath -AclObject $acl

Write-Host 'Relay address:' -ForegroundColor Cyan
& $executable --print-address --host $PublicHost --port $Port --path $keyPath

$taskName = 'UniProtocol Relay'
$arguments = "--port $Port --host `"$PublicHost`" --path `"$keyPath`""

$action = New-ScheduledTaskAction -Execute $executable -Argument $arguments -WorkingDirectory $InstallPath
$trigger = New-ScheduledTaskTrigger -AtStartup

# LocalService rather than SYSTEM: the relay handles untrusted input from the internet and
# needs no local authority beyond a listening socket and one file.
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount -RunLevel Limited

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

if ($Port -lt 1024) {
    Write-Host "Allowing inbound TCP $Port through the firewall..." -ForegroundColor Cyan
}

New-NetFirewallRule -DisplayName "UniProtocol Relay (TCP $Port)" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue | Out-Null

Start-ScheduledTask -TaskName $taskName

Write-Host ''
Write-Host "Installed. The relay starts at boot and is running now." -ForegroundColor Green
Write-Host "  Binary:  $executable"
Write-Host "  Key:     $keyPath"
Write-Host "  Manage:  Get-ScheduledTask '$taskName' | Stop-ScheduledTask"
