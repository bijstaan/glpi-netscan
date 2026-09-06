<#
.SYNOPSIS
    Install the GLPI Netscan scanner as a Windows service.

.DESCRIPTION
    Lays down the same versioned tree the self-updater maintains — versions\<v>
    plus a `current` junction — so a freshly installed scanner and one that has
    updated itself are the identical shape. Anything else would mean the update
    path is only ever exercised on machines that have already updated once,
    which is exactly the wrong way round.

.EXAMPLE
    .\install-windows.ps1 -Server https://glpi.example.com -Secret abc123
    .\install-windows.ps1 -Server https://glpi.example.com -Secret abc123 -CaCert C:\ca.pem
    .\install-windows.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string] $Server,
    [string] $Secret,
    [string] $CaCert,
    [string] $Name,
    [switch] $NoUpdates,
    [switch] $Uninstall,
    [string] $InstallRoot = "$env:ProgramFiles\GLPI Netscan"
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'GLPINetscan'
$DataRoot    = "$env:ProgramData\GLPINetscan"

function Assert-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This installer must run from an elevated PowerShell session: registering a service and writing under Program Files both need administrative rights.'
    }
}

Assert-Administrator

if ($Uninstall) {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host '==> stopping and removing the service'
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
    }
    # The junction is removed with rmdir rather than Remove-Item -Recurse:
    # some PowerShell versions follow a junction and would delete the version
    # directory it points at along with it.
    $current = Join-Path $InstallRoot 'current'
    if (Test-Path $current) { cmd /c rmdir "$current" | Out-Null }
    Remove-Item -Recurse -Force $InstallRoot -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $DataRoot -ErrorAction SilentlyContinue
    Write-Host 'Removed.'
    return
}

$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$binary = Join-Path $here 'glpi-netscan.exe'
if (-not (Test-Path $binary)) { throw "No scanner binary at $binary" }

# Ask the binary its own version rather than taking it from a filename or a
# build variable that could disagree with what it reports to GLPI. The updater
# compares the two, so a mismatch seeded here would surface later as a rejected
# update with a confusing message.
$version = (& $binary -version) -replace '^glpi-netscan ', ''
if (-not $version) { throw 'Could not determine the binary version' }

Write-Host "==> installing version $version"

$versionDir = Join-Path $InstallRoot "versions\$version"
New-Item -ItemType Directory -Force -Path $versionDir | Out-Null
Copy-Item $binary (Join-Path $versionDir 'glpi-netscan.exe') -Force

# A junction rather than a symlink: creating a symlink needs developer mode or
# SeCreateSymbolicLinkPrivilege, which an installer cannot rely on, whereas a
# directory junction works for any administrator. The updater flips it the same
# way, so both paths leave the same thing on disk.
$current = Join-Path $InstallRoot 'current'
if (Test-Path $current) { cmd /c rmdir "$current" | Out-Null }
cmd /c mklink /J "$current" "$versionDir" | Out-Null

$agent = Join-Path $current 'glpi-netscan.exe'
New-Item -ItemType Directory -Force -Path (Join-Path $DataRoot 'state') | Out-Null

if ($Server -and $Secret) {
    Write-Host '==> enrolling'
    $enrollArgs = @('install', '--server', $Server, '--secret', $Secret, '--install-root', $InstallRoot)
    if ($CaCert)    { $enrollArgs += @('--ca-cert', $CaCert) }
    if ($Name)      { $enrollArgs += @('--name', $Name) }
    if ($NoUpdates) { $enrollArgs += '--no-updates' }
    & $agent @enrollArgs
    if ($LASTEXITCODE -ne 0) { throw "Enrolment failed with exit code $LASTEXITCODE" }
}

$configPath = Join-Path $DataRoot 'agent.conf'
if (-not (Test-Path $configPath)) {
    Write-Warning @"
Installed, but not enrolled. Run:
  & '$agent' install --server https://glpi.example.com --secret <key>
then re-run this script to register the service.
"@
    return
}

Write-Host '==> registering the service'
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# LocalService, not LocalSystem: the scanner sends SNMP and HTTPS and writes its
# own state, and needs no privilege beyond that. This is the Windows equivalent
# of the empty capability bounding set on the systemd unit.
New-Service -Name $ServiceName `
    -BinaryPathName "`"$agent`" -config `"$configPath`"" `
    -DisplayName 'GLPI Netscan scanner' `
    -Description 'Scans network equipment over SNMP and reports inventory to GLPI.' `
    -StartupType Automatic | Out-Null

sc.exe config $ServiceName obj= "NT AUTHORITY\LocalService" | Out-Null

# The state directory has to be writable by that account: it holds the scanner's
# token and the update markers.
icacls "$DataRoot" /grant "*S-1-5-19:(OI)(CI)M" /T | Out-Null
# ...and the install root, or self-update cannot lay down a new version.
icacls "$InstallRoot" /grant "*S-1-5-19:(OI)(CI)M" /T | Out-Null

# Restart on failure, and treat a deliberate exit as a failure for this purpose
# too — failureflag 1 — because the scanner stops on purpose after staging an
# update so it comes back on the new version. Without the flag the SCM would
# consider a clean exit final and the update would never complete.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null

Start-Service -Name $ServiceName
Get-Service -Name $ServiceName | Format-List Name, Status, StartType

Write-Host @"

Installed. Useful commands:
  Get-Service $ServiceName
  Get-EventLog -LogName Application -Source $ServiceName -Newest 20
  .\install-windows.ps1 -Uninstall
"@
