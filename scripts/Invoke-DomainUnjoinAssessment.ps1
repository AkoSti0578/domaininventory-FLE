#Requires -Version 5.1
<#
.SYNOPSIS
    Risico-inventarisatie voor het uit het domein halen van een machine, inclusief applicatie-inventaris
    (system-wide versus per gebruiker). Alles komt in een rapport.

.DESCRIPTION
    Het script verandert niets aan de configuratie van de machine. Alleen voor de applicatie-inventaris worden
    profielen van niet-ingelogde gebruikers tijdelijk geladen (NTUSER.DAT) en direct weer ontkoppeld.

    Deel 1 - Unjoin-risico's:
      - Domeinstatus, domain controller-rol, secure channel, openstaande herstart
      - Lokaal admin-account, LAPS, domeinaccounts in Administrators / Remote Desktop Users
      - Domeinprofielen en per-user applicaties in die profielen
      - Services en geplande taken onder domeinaccounts
      - GPO's, WSUS, tijdsynchronisatie
      - Netwerkprofiel, RDP-firewallregels, AD CS-certificaten, 802.1X (WiFi en bekabeld)
      - BitLocker, hybrid Entra join, Intune, ConfigMgr
      - Serverrollen: shares, SQL, IIS, cluster, AVD-sessiehost

    Deel 2 - Applicatie-inventaris:
      - System-wide: HKLM Uninstall (x64 en WOW6432Node)
      - Per gebruiker: HKU\<SID> Uninstall voor ieder profiel (lokaal, domein en Entra ID)
      - Optioneel Appx/MSIX-pakketten

    Uitvoer: een HTML-rapport (Yellow Spring-huisstijl) en twee CSV-bestanden (risico's en applicaties).
    De resultaten worden daarnaast naar de inventarisatie-website gestuurd (tenzij -NoUpload).

.PARAMETER OutputFolder
    Map voor het rapport. Standaard C:\Users\Public.

.PARAMETER IncludeProfileSize
    Bereken de grootte van domeinprofielen (kan lang duren).

.PARAMETER IncludeSystemComponents
    Neem in de inventaris ook verborgen componenten, updates en hotfixes mee.

.PARAMETER IncludeAppx
    Neem in de inventaris ook Store/MSIX/Appx-pakketten mee.

.PARAMETER NoOpen
    Open het HTML-rapport niet automatisch (handig bij uitrol via RMM/Intune).

.PARAMETER PassThru
    Geef de resultaten ook terug als object met de eigenschappen Checks en Applications.

.PARAMETER ReportUrl
    Adres van de inventarisatie-website waar de resultaten naartoe gestuurd worden.
    Wordt automatisch ingevuld bij het downloaden van het script vanaf de website.

.PARAMETER ApiKey
    Upload-sleutel van de inventarisatie-website. Wordt automatisch ingevuld bij het downloaden.

.PARAMETER NoUpload
    Stuur de resultaten niet naar de website; maak alleen het lokale rapport.

.EXAMPLE
    .\Invoke-DomainUnjoinAssessment.ps1
.EXAMPLE
    .\Invoke-DomainUnjoinAssessment.ps1 -IncludeProfileSize -IncludeAppx -OutputFolder C:\Temp
.EXAMPLE
    $r = .\Invoke-DomainUnjoinAssessment.ps1 -NoOpen -PassThru
    $r.Applications | Where-Object Scope -eq 'User'

.NOTES
    Draai als administrator in 64-bit Windows PowerShell 5.1 voor een volledig rapport.
#>
[CmdletBinding()]
param(
    [string]$OutputFolder = $env:PUBLIC,
    [switch]$IncludeProfileSize,
    [switch]$IncludeSystemComponents,
    [switch]$IncludeAppx,
    [switch]$NoOpen,
    [switch]$PassThru,
    [string]$ReportUrl = '__REPORT_URL__',
    [string]$ApiKey = '__API_KEY__',
    [switch]$NoUpload
)

$scriptVersion = '1.1.0'

#region Basis en hulpfuncties
$checks = [System.Collections.Generic.List[object]]::new()
$apps   = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet('Risico', 'Waarschuwing', 'Info', 'OK')][string]$Status,
        [string]$Detail,
        [string]$Advice = ''
    )
    $checks.Add([pscustomobject]@{
        Categorie = $Category
        Controle  = $Check
        Status    = $Status
        Detail    = $Detail
        Advies    = $Advice
    })
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$computer    = $env:COMPUTERNAME
$cs          = Get-CimInstance -ClassName Win32_ComputerSystem
$os          = Get-CimInstance -ClassName Win32_OperatingSystem
$domainFqdn  = $cs.Domain
$isRdp       = $env:SESSIONNAME -like 'RDP-Tcp*'
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name

$netbios = $null
if ($cs.PartOfDomain) {
    $netbios = (Get-CimInstance -ClassName Win32_NTDomain -ErrorAction SilentlyContinue |
        Where-Object { $_.DnsForestName -and $_.DomainName } | Select-Object -First 1).DomainName
    if (-not $netbios) { $netbios = ($domainFqdn -split '\.')[0].ToUpper() }
}

$machineSid = $null
try { $machineSid = (Get-LocalUser -ErrorAction Stop | Select-Object -First 1).SID.AccountDomainSid.Value } catch { }

if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}

function Test-IsDomainAccount {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $n = $Name.Trim()

    if ($n -match '^S-1-5-21-') {
        if ($machineSid -and $n.StartsWith($machineSid)) { return $false }
        return $true
    }
    if ($n -match '^S-1-') { return $false }   # Well-known SID's en Entra ID (S-1-12-1-*)
    if ($n -match '^(LocalSystem|LocalService|NetworkService|SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') { return $false }
    if ($n -match '@') { return $true }
    if ($n -match '\\') {
        $prefix = $n.Split('\')[0]
        $excluded = @('.', $computer, 'NT AUTHORITY', 'NT SERVICE', 'BUILTIN', 'NT VIRTUAL MACHINE',
                      'IIS APPPOOL', 'Window Manager', 'Font Driver Host', 'AzureAD', 'MicrosoftAccount',
                      'APPLICATION PACKAGE AUTHORITY', 'NT-INSTANTIE', 'NT-SERVICE')
        if ($prefix -in $excluded) { return $false }
        return $true
    }
    return $false
}

function Resolve-SidName {
    param([string]$Sid, [string]$Fallback)
    try { return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Fallback }
}

function Get-LocalGroupMembersAdsi {
    # ADSI in plaats van Get-LocalGroupMember: die faalt bij verweesde SID's en Entra-leden
    param([string]$GroupSid)
    try {
        $groupName = ([System.Security.Principal.SecurityIdentifier]$GroupSid).Translate(
            [System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        $group = [ADSI]"WinNT://$computer/$groupName,group"
        foreach ($m in @($group.Invoke('Members'))) {
            $path  = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
            $name  = $m.GetType().InvokeMember('Name',    'GetProperty', $null, $m, $null)
            $class = $m.GetType().InvokeMember('Class',   'GetProperty', $null, $m, $null)
            $parts = ($path -replace '^WinNT://', '').Split('/')
            $isLocal = ($parts.Count -ge 2 -and $parts[-2] -eq $computer)
            $dom = if ($isLocal) { $computer } elseif ($parts.Count -ge 2) { $parts[-2] } else { '' }
            [pscustomobject]@{
                Name      = if ($dom) { "$dom\$name" } else { $name }
                ShortName = $name
                Class     = $class
                IsLocal   = $isLocal
            }
        }
    }
    catch {
        Write-Warning "Kon leden van groep $GroupSid niet uitlezen: $($_.Exception.Message)"
    }
}

function Convert-InstallDate {
    param($Value)
    if ($Value -match '^\d{8}$') {
        try { return [datetime]::ParseExact($Value, 'yyyyMMdd', $null).ToString('yyyy-MM-dd') } catch { }
    }
    return $Value
}

function Get-UninstallEntries {
    param(
        [string]$RootPath,
        [string]$Scope,
        [string]$UserName,
        [string]$UserSid,
        [string]$Architecture
    )
    if (-not (Test-Path -LiteralPath $RootPath)) { return }

    Get-ChildItem -LiteralPath $RootPath -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
        if (-not $p -or -not $p.DisplayName) { return }

        if (-not $IncludeSystemComponents) {
            if ($p.SystemComponent -eq 1) { return }
            if ($p.ParentKeyName) { return }
            if ($p.ReleaseType -in @('Update', 'Hotfix', 'Security Update', 'Update Rollup')) { return }
        }

        [pscustomobject]@{
            Scope           = $Scope
            User            = $UserName
            UserSid         = $UserSid
            Name            = $p.DisplayName
            Version         = $p.DisplayVersion
            Publisher       = $p.Publisher
            InstallDate     = Convert-InstallDate $p.InstallDate
            Architecture    = $Architecture
            InstallerType   = if ($p.WindowsInstaller -eq 1) { 'MSI' } else { 'EXE/Overig' }
            InstallLocation = $p.InstallLocation
            UninstallString = $p.UninstallString
        }
    }
}

$uninstallSubKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
$uninstallWowKey = 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
#endregion

#region Deel 2 - Applicatie-inventaris (eerst, zodat de risico-check de resultaten kan gebruiken)
Write-Host 'Applicatie-inventaris uitlezen...' -ForegroundColor Cyan

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Add-Check 'Algemeen' '32-bit PowerShell' 'Waarschuwing' 'Het script draait in 32-bit PowerShell op een 64-bit OS; HKLM wordt omgeleid.' `
        'Start 64-bit PowerShell voor een volledige applicatie-inventaris.'
}

# System-wide
$hklmArch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
foreach ($e in Get-UninstallEntries -RootPath "HKLM:\$uninstallSubKey" -Scope 'System' -UserName 'Alle gebruikers' -UserSid '' -Architecture $hklmArch) { $apps.Add($e) }
foreach ($e in Get-UninstallEntries -RootPath "HKLM:\$uninstallWowKey" -Scope 'System' -UserName 'Alle gebruikers' -UserSid '' -Architecture 'x86') { $apps.Add($e) }

# Per gebruiker
$allProfiles = @(Get-CimInstance -ClassName Win32_UserProfile |
    Where-Object { -not $_.Special -and $_.SID -match '^S-1-5-21-|^S-1-12-1-' })
$skippedProfiles = @()

foreach ($prof in $allProfiles) {
    $sid      = $prof.SID
    $userName = Resolve-SidName -Sid $sid -Fallback (Split-Path -Path $prof.LocalPath -Leaf)
    $hiveRoot = "HKU:\$sid"
    $tempHive = $null

    if (-not (Test-Path -LiteralPath $hiveRoot)) {
        $ntUserDat = Join-Path $prof.LocalPath 'NTUSER.DAT'
        if (-not $isAdmin -or -not (Test-Path -LiteralPath $ntUserDat)) {
            $skippedProfiles += $userName
            continue
        }
        $tempHive = "TmpUnjoinScan_$sid"
        $null = & reg.exe load "HKU\$tempHive" "$ntUserDat" 2>&1
        if ($LASTEXITCODE -ne 0) {
            $skippedProfiles += $userName
            $tempHive = $null
            continue
        }
        $hiveRoot = "HKU:\$tempHive"
    }

    try {
        foreach ($e in Get-UninstallEntries -RootPath "$hiveRoot\$uninstallSubKey" -Scope 'User' -UserName $userName -UserSid $sid -Architecture 'User') { $apps.Add($e) }
        foreach ($e in Get-UninstallEntries -RootPath "$hiveRoot\$uninstallWowKey" -Scope 'User' -UserName $userName -UserSid $sid -Architecture 'x86') { $apps.Add($e) }
    }
    finally {
        if ($tempHive) {
            # Open registry-handles vrijgeven voordat de hive wordt ontkoppeld
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            Start-Sleep -Milliseconds 300
            $null = & reg.exe unload "HKU\$tempHive" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Hive van $userName kon niet worden ontkoppeld. Handmatig: reg unload HKU\$tempHive"
            }
        }
    }
}

if ($skippedProfiles) {
    Add-Check 'Algemeen' 'Applicatie-inventaris' 'Info' ("Profielen overgeslagen (niet ingelogd, in gebruik of geen rechten): " + ($skippedProfiles -join ', ')) `
        'Draai het script als administrator en zonder dat deze gebruikers ingelogd zijn voor een volledige inventaris.'
}

# Appx / MSIX (optioneel)
if ($IncludeAppx) {
    try {
        if ($isAdmin) {
            Get-AppxProvisionedPackage -Online -ErrorAction Stop | ForEach-Object {
                $apps.Add([pscustomobject]@{
                    Scope = 'System (Appx provisioned)'; User = 'Alle gebruikers'; UserSid = ''
                    Name = $_.DisplayName; Version = $_.Version; Publisher = $_.PublisherId; InstallDate = $null
                    Architecture = $_.Architecture; InstallerType = 'Appx/MSIX'; InstallLocation = $_.InstallLocation; UninstallString = $null
                })
            }
            Get-AppxPackage -AllUsers -ErrorAction Stop |
                Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne 'System' } |
                ForEach-Object {
                    $pkg = $_
                    foreach ($ui in $pkg.PackageUserInformation) {
                        if ($ui.InstallState -ne 'Installed') { continue }
                        $apps.Add([pscustomobject]@{
                            Scope = 'User (Appx)'
                            User = if ($ui.UserSecurityId.Username) { $ui.UserSecurityId.Username } else { $ui.UserSecurityId.Sid }
                            UserSid = $ui.UserSecurityId.Sid
                            Name = $pkg.Name; Version = $pkg.Version; Publisher = $pkg.Publisher; InstallDate = $null
                            Architecture = $pkg.Architecture; InstallerType = 'Appx/MSIX'; InstallLocation = $pkg.InstallLocation; UninstallString = $null
                        })
                    }
                }
        }
        else {
            Get-AppxPackage -ErrorAction Stop |
                Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne 'System' } |
                ForEach-Object {
                    $apps.Add([pscustomobject]@{
                        Scope = 'User (Appx)'; User = $currentUser; UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                        Name = $_.Name; Version = $_.Version; Publisher = $_.Publisher; InstallDate = $null
                        Architecture = $_.Architecture; InstallerType = 'Appx/MSIX'; InstallLocation = $_.InstallLocation; UninstallString = $null
                    })
                }
        }
    }
    catch {
        Add-Check 'Algemeen' 'Appx-inventaris' 'Info' "Appx-pakketten konden niet worden uitgelezen: $($_.Exception.Message)" `
            'Gebruik Windows PowerShell 5.1 als administrator.'
    }
}

$appsSorted = @($apps | Sort-Object Scope, User, Name, Version -Unique)
#endregion

#region Deel 1 - Unjoin-risico's
Write-Host 'Unjoin-risico''s controleren...' -ForegroundColor Cyan

# --- Algemeen ---
if (-not $isAdmin) {
    Add-Check 'Algemeen' 'Rechten' 'Waarschuwing' 'Script draait niet als administrator; enkele controles zijn beperkt of overgeslagen.' `
        'Start PowerShell als administrator voor een volledig rapport.'
}

if (Test-IsDomainAccount $currentUser) {
    Add-Check 'Algemeen' 'Ingelogd account' 'Waarschuwing' "Je bent ingelogd als domeinaccount $currentUser." `
        'Na de unjoin kun je met dit account niet meer inloggen. Zorg voor een lokaal admin-account met bekend wachtwoord.'
}

if ($isRdp) {
    Add-Check 'Algemeen' 'Externe sessie' 'Waarschuwing' 'Je bent via RDP met deze machine verbonden.' `
        'De unjoin vereist een herstart. Zorg voor alternatieve toegang (console, Hyper-V, Azure Serial Console, iDRAC/iLO, RMM).'
}

$pending = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'Component Based Servicing' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'Windows Update' }
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).PendingFileRenameOperations) { $pending += 'PendingFileRenameOperations' }
if ($pending) {
    Add-Check 'Algemeen' 'Openstaande herstart' 'Waarschuwing' ("Herstart staat open: " + ($pending -join ', ')) `
        'Herstart de machine eerst en controleer of hij netjes opstart, voordat je de unjoin uitvoert.'
}
else {
    Add-Check 'Algemeen' 'Openstaande herstart' 'OK' 'Geen openstaande herstart gevonden.'
}

# --- Domein ---
$roleNames = @{ 0 = 'Standalone werkstation'; 1 = 'Werkstation (domeinlid)'; 2 = 'Standalone server';
                3 = 'Server (domeinlid)'; 4 = 'Backup domain controller'; 5 = 'Primary domain controller' }

if ($cs.PartOfDomain) {
    Add-Check 'Domein' 'Domeinlidmaatschap' 'Info' "Lid van $domainFqdn (NetBIOS: $netbios). Rol: $($roleNames[[int]$cs.DomainRole])."
}
else {
    Add-Check 'Domein' 'Domeinlidmaatschap' 'Info' "Machine is geen lid van een domein (werkgroep: $($cs.Workgroup))." `
        'Er is niets uit het domein te halen; resterende controles zijn alleen informatief.'
}

if ($cs.DomainRole -ge 4) {
    Add-Check 'Domein' 'Domain controller' 'Risico' 'Deze machine is een domain controller.' `
        'Een DC kun je niet uit het domein halen. Eerst demoten (Uninstall-ADDSDomainController) en FSMO-rollen/DNS controleren.'
}

if ($cs.PartOfDomain -and $isAdmin) {
    try {
        if (Test-ComputerSecureChannel -ErrorAction Stop) {
            Add-Check 'Domein' 'Secure channel' 'OK' "Secure channel met $domainFqdn werkt; een DC is bereikbaar." `
                'Na de unjoin het computerobject in AD uitschakelen/verwijderen (eerst LAPS- en BitLocker-gegevens veiligstellen).'
        }
        else {
            Add-Check 'Domein' 'Secure channel' 'Waarschuwing' 'Secure channel werkt niet.' `
                'De unjoin gebeurt dan alleen lokaal. Ruim het computerobject in AD handmatig op.'
        }
    }
    catch {
        Add-Check 'Domein' 'Secure channel' 'Waarschuwing' "Secure channel kon niet worden getest: $($_.Exception.Message)" `
            'Mogelijk is er geen DC bereikbaar. Ruim het computerobject in AD na afloop handmatig op.'
    }
}

# --- Lokale toegang ---
$admins = @(Get-LocalGroupMembersAdsi 'S-1-5-32-544')

$localAdminUsers = @()
foreach ($a in ($admins | Where-Object { $_.IsLocal -and $_.Class -eq 'User' })) {
    $u = Get-LocalUser -Name $a.ShortName -ErrorAction SilentlyContinue
    if ($u) { $localAdminUsers += $u }
}
$enabledLocalAdmins  = @($localAdminUsers | Where-Object Enabled)
$disabledLocalAdmins = @($localAdminUsers | Where-Object { -not $_.Enabled })

if ($enabledLocalAdmins.Count -gt 0) {
    $list = $enabledLocalAdmins | ForEach-Object {
        $set = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('dd-MM-yyyy') } else { 'onbekend' }
        "$($_.Name) (wachtwoord gezet: $set)"
    }
    Add-Check 'Lokale toegang' 'Lokaal admin-account' 'OK' ("Ingeschakelde lokale admin(s): " + ($list -join ', ')) `
        'Controleer vooraf dat je het wachtwoord van minimaal een van deze accounts kent en test het inloggen.'
}
else {
    $dis = if ($disabledLocalAdmins) { " Uitgeschakeld: " + (($disabledLocalAdmins | ForEach-Object Name) -join ', ') + '.' } else { '' }
    Add-Check 'Lokale toegang' 'Lokaal admin-account' 'Risico' ("Geen ingeschakeld lokaal account in de groep Administrators.$dis") `
        'Maak vooraf een lokaal admin-account aan of schakel er een in en sla het wachtwoord veilig op. Anders heb je na de unjoin geen beheerderstoegang meer.'
}

$domainAdmins = @($admins | Where-Object { Test-IsDomainAccount $_.Name })
if ($domainAdmins) {
    Add-Check 'Lokale toegang' 'Domeinaccounts in Administrators' 'Waarschuwing' (($domainAdmins | ForEach-Object Name) -join "`n") `
        'Deze beheerrechten vervallen na de unjoin.'
}

$rdpUsers = @(Get-LocalGroupMembersAdsi 'S-1-5-32-555' | Where-Object { Test-IsDomainAccount $_.Name })
if ($rdpUsers) {
    Add-Check 'Lokale toegang' 'Domeinaccounts in Remote Desktop Users' 'Waarschuwing' (($rdpUsers | ForEach-Object Name) -join "`n") `
        'Deze gebruikers kunnen na de unjoin niet meer via RDP inloggen.'
}

$lapsDir = $null
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS',
               'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS',
               'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config') {
    $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if ($v -and $null -ne $v.BackupDirectory) { $lapsDir = [int]$v.BackupDirectory; break }
}
$legacyLaps = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1

if ($lapsDir -eq 2 -or $legacyLaps) {
    $type = if ($lapsDir -eq 2) { 'Windows LAPS (AD)' } else { 'Legacy Microsoft LAPS (AD)' }
    Add-Check 'Lokale toegang' 'LAPS' 'Waarschuwing' "$type actief: het lokale admin-wachtwoord staat in Active Directory." `
        'Haal het actuele wachtwoord op (Get-LapsADPassword of LAPS UI) voor de unjoin. Na de unjoin wordt het niet meer geroteerd en verdwijnt het met het computerobject.'
}
elseif ($lapsDir -eq 1) {
    Add-Check 'Lokale toegang' 'LAPS' 'Info' 'Windows LAPS met back-up naar Entra ID.' `
        'Haal het wachtwoord vooraf op; bij hybrid join kan de koppeling met Entra na de unjoin vervallen.'
}
else {
    Add-Check 'Lokale toegang' 'LAPS' 'Info' 'Geen LAPS-configuratie gevonden.'
}

# --- Gebruikers ---
$domainProfiles = @($allProfiles | Where-Object { Test-IsDomainAccount $_.SID })

if ($domainProfiles) {
    $lines = foreach ($p in $domainProfiles) {
        $name = Resolve-SidName -Sid $p.SID -Fallback (Split-Path $p.LocalPath -Leaf)
        $last = if ($p.LastUseTime) { $p.LastUseTime.ToString('dd-MM-yyyy') } else { 'onbekend' }
        $size = ''
        if ($IncludeProfileSize) {
            $bytes = (Get-ChildItem -LiteralPath $p.LocalPath -Recurse -Force -File -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
            $size = ', {0:N1} GB' -f ($bytes / 1GB)
        }
        "$name - $($p.LocalPath) (laatst gebruikt: $last$size)"
    }
    Add-Check 'Gebruikers' 'Domeinprofielen' 'Waarschuwing' ($lines -join "`n") `
        'Profielen blijven op schijf staan maar zijn na de unjoin niet meer te gebruiken. Migreer ze naar een lokaal of Entra-account (bijv. ForensiT User Profile Wizard of USMT) of maak eerst een back-up (OneDrive, Bureaublad/Documenten).'
}
else {
    Add-Check 'Gebruikers' 'Domeinprofielen' 'OK' 'Geen profielen van domeingebruikers gevonden.'
}

# Koppeling met de inventaris: per-user apps in domeinprofielen
$domainUserApps = @($appsSorted | Where-Object { $_.Scope -like 'User*' -and (Test-IsDomainAccount $_.UserSid) })
if ($domainUserApps) {
    $lines = $domainUserApps | Group-Object User | ForEach-Object {
        $names = ($_.Group | Select-Object -ExpandProperty Name -Unique | Select-Object -First 8) -join ', '
        $more  = if ($_.Count -gt 8) { ", ... (+$($_.Count - 8))" } else { '' }
        "$($_.Name): $($_.Count) app(s) - $names$more"
    }
    Add-Check 'Gebruikers' 'Per-user applicaties in domeinprofielen' 'Waarschuwing' ($lines -join "`n") `
        'Deze apps staan alleen in het domeinprofiel en zijn na de unjoin niet meer bruikbaar. Herinstalleer ze system-wide of in het nieuwe account (zie de applicatie-inventaris).'
}

# --- Services en taken ---
$domainServices = @(Get-CimInstance -ClassName Win32_Service | Where-Object { Test-IsDomainAccount $_.StartName })
if ($domainServices) {
    Add-Check 'Services en taken' 'Services onder domeinaccount' 'Risico' (($domainServices | ForEach-Object { "$($_.DisplayName) [$($_.Name)] - $($_.StartName) ($($_.StartMode), $($_.State))" }) -join "`n") `
        'Deze services starten na de unjoin niet meer. Zet ze vooraf om naar een lokaal account of LocalSystem/NetworkService.'
}
else {
    Add-Check 'Services en taken' 'Services onder domeinaccount' 'OK' 'Geen services gevonden die onder een domeinaccount draaien.'
}

try {
    $domainTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.State -ne 'Disabled' -and
        $_.TaskPath -notlike '\Microsoft\*' -and
        $_.TaskName -notlike 'OneDrive*' -and
        ((Test-IsDomainAccount $_.Principal.UserId) -or (Test-IsDomainAccount $_.Principal.GroupId))
    })
    if ($domainTasks) {
        Add-Check 'Services en taken' 'Geplande taken onder domeinaccount' 'Waarschuwing' (($domainTasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName) - $($_.Principal.UserId)$($_.Principal.GroupId)" }) -join "`n") `
            'Deze taken draaien na de unjoin niet meer. Pas het account aan of verwijder de taak.'
    }
    else {
        Add-Check 'Services en taken' 'Geplande taken onder domeinaccount' 'OK' 'Geen actieve geplande taken onder een domeinaccount gevonden.'
    }
}
catch {
    Add-Check 'Services en taken' 'Geplande taken' 'Info' "Geplande taken konden niet worden uitgelezen: $($_.Exception.Message)"
}

# --- Beleid ---
$gpos = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\GPO-List' -ErrorAction SilentlyContinue |
    ForEach-Object { (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName } |
    Where-Object { $_ -and $_ -ne 'Local Group Policy' } | Sort-Object -Unique

if ($gpos) {
    Add-Check 'Beleid' 'Toegepaste computer-GPO''s' 'Waarschuwing' ($gpos -join "`n") `
        'Deze instellingen worden niet meer ververst, maar registry-policies blijven deels actief (tattooing). Bepaal wat vervangen moet worden door Intune of lokaal beleid.'
}

$wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
$au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
if ($wu.WUServer -and $au.UseWUServer -eq 1) {
    Add-Check 'Beleid' 'Windows Update via WSUS' 'Waarschuwing' "Windows Update wijst naar WSUS: $($wu.WUServer)" `
        'Deze policy blijft na de unjoin staan. Verwijder de WSUS-instellingen of vervang ze door Intune/WUfB, anders krijgt de machine mogelijk geen updates meer.'
}

$w32Type = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue).Type
if ($w32Type -eq 'NT5DS') {
    Add-Check 'Beleid' 'Tijdsynchronisatie' 'Info' 'Tijd wordt gesynchroniseerd via de domeinhierarchie (NT5DS).' `
        'Controleer na de unjoin de tijdbron; zet zo nodig NTP in: w32tm /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /update'
}

# --- Netwerk ---
$netProfiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
$domainNets  = @($netProfiles | Where-Object NetworkCategory -eq 'DomainAuthenticated')
if ($domainNets) {
    Add-Check 'Netwerk' 'Netwerkprofiel' 'Info' (($domainNets | ForEach-Object { "$($_.InterfaceAlias) ($($_.Name)) - Domein" }) -join "`n") `
        'Na de unjoin wordt dit netwerk Openbaar (of Prive). Firewallregels die alleen voor het domeinprofiel gelden werken dan niet meer.'
}

$rdpEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
if ($rdpEnabled) {
    $rdpRules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.Group -eq '@FirewallAPI.dll,-28752' -and $_.Action -eq 'Allow' })
    $nonDomainRules = @($rdpRules | Where-Object { $_.Profile.ToString() -match 'Any|Private|Public' })

    if ($nonDomainRules) {
        $profilesText = ($nonDomainRules | ForEach-Object { $_.Profile.ToString() } | Sort-Object -Unique) -join ', '
        Add-Check 'Netwerk' 'RDP-bereikbaarheid' 'OK' "RDP staat aan; firewallregel geldt ook buiten het domeinprofiel ($profilesText)."
    }
    else {
        $status = if ($isRdp) { 'Risico' } else { 'Waarschuwing' }
        Add-Check 'Netwerk' 'RDP-bereikbaarheid' $status 'RDP staat aan, maar de firewallregel geldt alleen voor het domeinprofiel (of is uitgeschakeld).' `
            'Na de unjoin is RDP geblokkeerd. Schakel de RDP-regel in voor Prive en zet het netwerk op Prive, of zorg voor console-toegang.'
    }
}
else {
    Add-Check 'Netwerk' 'RDP-bereikbaarheid' 'Info' 'Extern bureaublad staat uit.'
}

$templateOids = @('1.3.6.1.4.1.311.21.7', '1.3.6.1.4.1.311.20.2')
$adcsCerts = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
    $_.Extensions | Where-Object { $_.Oid.Value -in $templateOids }
})
if ($adcsCerts) {
    $lines = foreach ($c in $adcsCerts) {
        $ext  = $c.Extensions | Where-Object { $_.Oid.Value -in $templateOids } | Select-Object -First 1
        $tmpl = (($ext.Format($false) -split ',')[0] -replace '^[^=]*=', '') -replace '\(.*$', ''
        "$($c.Subject) - sjabloon: $($tmpl.Trim()) - geldig tot $($c.NotAfter.ToString('dd-MM-yyyy'))"
    }
    Add-Check 'Netwerk' 'Machinecertificaten (AD CS)' 'Waarschuwing' ($lines -join "`n") `
        'Deze certificaten worden na de unjoin niet meer verlengd. Controleer of ze gebruikt worden voor 802.1X, VPN, WiFi of ConfigMgr en regel vervanging (bijv. Intune SCEP/PKCS).'
}

$wlanTemp = Join-Path $env:TEMP ("wlan_" + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $wlanTemp -Force | Out-Null
    $null = & netsh.exe wlan export profile folder="$wlanTemp" 2>&1
    $entWlan = foreach ($f in (Get-ChildItem -Path $wlanTemp -Filter *.xml -ErrorAction SilentlyContinue)) {
        [xml]$x = Get-Content -LiteralPath $f.FullName -Raw
        $auth = $x.WLANProfile.MSM.security.authEncryption.authentication
        if ($auth -match '^(WPA|WPA2|WPA3|WPA3ENT|WPA3ENT192)$' -or $x.WLANProfile.MSM.security.OneX) {
            $mode = $x.WLANProfile.MSM.security.OneX.authMode
            if (-not $mode) { $mode = 'standaard' }
            "$($x.WLANProfile.name) ($auth, authMode: $mode)"
        }
    }
    if ($entWlan) {
        Add-Check 'Netwerk' 'WiFi 802.1X / Enterprise' 'Waarschuwing' ($entWlan -join "`n") `
            'Authenticatie met domeincredentials of -certificaten werkt na de unjoin niet meer. Zorg dat de machine via een ander netwerk bereikbaar blijft.'
    }
}
catch { }
finally {
    Remove-Item -LiteralPath $wlanTemp -Recurse -Force -ErrorAction SilentlyContinue
}

$dot3 = Get-Service -Name dot3svc -ErrorAction SilentlyContinue
if ($dot3 -and $dot3.Status -eq 'Running') {
    Add-Check 'Netwerk' 'Bekabeld 802.1X' 'Waarschuwing' 'Wired AutoConfig (dot3svc) is actief: mogelijk 802.1X op de bekabelde poort.' `
        'Controleer of de switchpoort 802.1X afdwingt. Na de unjoin kan de machine dan in een quarantaine-VLAN of zonder netwerk belanden.'
}

# --- Beveiliging ---
if ($isAdmin -and (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ($bl.ProtectionStatus -eq 'On') {
            $rp = @($bl.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
            if ($rp) {
                Add-Check 'Beveiliging' 'BitLocker' 'Waarschuwing' ("BitLocker actief op $env:SystemDrive. Herstelwachtwoord-ID: " + (($rp | ForEach-Object KeyProtectorId) -join ', ')) `
                    'De herstelsleutel staat waarschijnlijk in AD. Sla hem buiten AD op (BackupToAAD-BitLockerKeyProtector of IT Glue) voordat je het computerobject opruimt.'
            }
            else {
                Add-Check 'Beveiliging' 'BitLocker' 'Risico' "BitLocker actief op $env:SystemDrive zonder herstelwachtwoord." `
                    'Voeg een herstelwachtwoord toe (Add-BitLockerKeyProtector -RecoveryPasswordProtector) en sla het veilig op.'
            }
        }
        else {
            Add-Check 'Beveiliging' 'BitLocker' 'Info' "BitLocker is niet actief op $env:SystemDrive."
        }
    }
    catch {
        Add-Check 'Beveiliging' 'BitLocker' 'Info' "BitLocker-status kon niet worden uitgelezen: $($_.Exception.Message)"
    }
}

# --- Entra en beheer ---
$dsreg = & dsregcmd.exe /status 2>$null
function Get-DsregValue {
    param([string]$Key)
    $line = $dsreg | Where-Object { $_ -match "^\s*$Key\s*:" } | Select-Object -First 1
    if ($line) { ($line -split ':', 2)[1].Trim() }
}
$aadJoined = Get-DsregValue 'AzureAdJoined'
$tenant    = Get-DsregValue 'TenantName'

if ($aadJoined -eq 'YES' -and $cs.PartOfDomain) {
    Add-Check 'Entra en beheer' 'Hybrid Entra join' 'Risico' "Apparaat is hybrid Entra joined (tenant: $tenant)." `
        'Na de unjoin vervalt de hybrid join: geen SSO/PRT, Conditional Access-compliance en mogelijk geen Intune-beheer meer. Plan een Entra join (Autopilot/handmatig) en ruim het apparaatobject in Entra op.'
}
elseif ($aadJoined -eq 'YES') {
    Add-Check 'Entra en beheer' 'Entra join' 'Info' "Apparaat is Entra joined (tenant: $tenant)."
}

$mdm = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue } |
    Where-Object { $_.ProviderID -eq 'MS DM Server' } | Select-Object -First 1
if ($mdm) {
    Add-Check 'Entra en beheer' 'Intune-inschrijving' 'Waarschuwing' "Ingeschreven in Intune (UPN: $($mdm.UPN))." `
        'Bij inschrijving via GPO/hybrid join kan het apparaat na de unjoin uit beheer vallen. Controleer de status in Intune na afloop.'
}

if (Get-Service -Name CcmExec -ErrorAction SilentlyContinue) {
    Add-Check 'Entra en beheer' 'ConfigMgr-client' 'Info' 'ConfigMgr (SCCM)-client is geinstalleerd.' `
        'Boundaries en discovery zijn vaak AD-gebaseerd. Bepaal of beheer via ConfigMgr nodig blijft.'
}

# --- Serverrollen ---
if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
    $shares = @(Get-SmbShare -Special $false -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'print$' })
    $domainShares = foreach ($s in $shares) {
        $acc = @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | Where-Object { Test-IsDomainAccount $_.AccountName })
        if ($acc) { "$($s.Name) ($($s.Path)): " + (($acc | ForEach-Object AccountName | Sort-Object -Unique) -join ', ') }
    }
    if ($domainShares) {
        Add-Check 'Serverrollen' 'Shares met domeinrechten' 'Waarschuwing' ($domainShares -join "`n") `
            'Domeingebruikers verliezen toegang; NTFS-rechten op domein-SID''s worden onbruikbaar. Plan migratie van de data of rechten.'
    }
    elseif ($shares) {
        Add-Check 'Serverrollen' 'Shares' 'Info' (($shares | ForEach-Object { "$($_.Name) ($($_.Path))" }) -join "`n")
    }
}

if (Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue) {
    Add-Check 'Serverrollen' 'SQL Server' 'Waarschuwing' 'SQL Server is geinstalleerd.' `
        'Controleer logins op domeinaccounts/-groepen en SPN''s. Zorg vooraf voor een SQL- of lokaal sysadmin-login.'
}
if (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) {
    Add-Check 'Serverrollen' 'IIS' 'Info' 'IIS is geinstalleerd.' `
        'Controleer app pool-identiteiten en sites met Windows-authenticatie op domeinafhankelijkheden.'
}
if (Get-Service -Name ClusSvc -ErrorAction SilentlyContinue) {
    Add-Check 'Serverrollen' 'Failover Cluster' 'Risico' 'Failover Clustering-service is aanwezig.' `
        'Een AD-gebaseerd cluster werkt niet meer na de unjoin. Haal de node eerst uit het cluster.'
}
if (Get-Service -Name RDAgentBootLoader -ErrorAction SilentlyContinue) {
    Add-Check 'Serverrollen' 'AVD-sessiehost' 'Waarschuwing' 'Azure Virtual Desktop-agent is geinstalleerd.' `
        'Zet de sessiehost in drain mode, log gebruikers af en verwijder hem uit de hostpool. Domeingebruikers kunnen na de unjoin niet meer aanmelden.'
}
#endregion

#region Rapport
if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$stamp       = Get-Date -Format 'yyyyMMdd_HHmm'
$baseName    = "DomainUnjoin_${computer}_$stamp"
$htmlPath    = Join-Path $OutputFolder "$baseName.html"
$csvChecks   = Join-Path $OutputFolder "${baseName}_risicos.csv"
$csvApps     = Join-Path $OutputFolder "${baseName}_applicaties.csv"

$order  = @{ 'Risico' = 0; 'Waarschuwing' = 1; 'Info' = 2; 'OK' = 3 }
$sorted = @($checks | Sort-Object { $order[$_.Status] }, Categorie, Controle)

$nRisk = @($checks | Where-Object Status -eq 'Risico').Count
$nWarn = @($checks | Where-Object Status -eq 'Waarschuwing').Count
$nOk   = @($checks | Where-Object Status -eq 'OK').Count
$nInfo = @($checks | Where-Object Status -eq 'Info').Count

if ($nRisk -gt 0)     { $verdict = 'Niet uit het domein halen voordat de risico''s zijn opgelost.'; $vClass = 'risk' }
elseif ($nWarn -gt 0) { $verdict = 'Uit het domein halen is mogelijk na het afhandelen van de waarschuwingen.'; $vClass = 'warn' }
else                  { $verdict = 'Geen blokkerende risico''s gevonden.'; $vClass = 'ok' }

function ConvertTo-HtmlText {
    param([string]$Text)
    ([System.Net.WebUtility]::HtmlEncode($Text)) -replace "`r?`n", '<br>'
}

$checkRows = foreach ($c in $sorted) {
    $cls = switch ($c.Status) { 'Risico' { 'risk' } 'Waarschuwing' { 'warn' } 'OK' { 'ok' } default { 'info' } }
    "<tr><td><span class='badge $cls'>$($c.Status)</span></td><td>$(ConvertTo-HtmlText $c.Categorie)</td><td><strong>$(ConvertTo-HtmlText $c.Controle)</strong></td><td>$(ConvertTo-HtmlText $c.Detail)</td><td>$(ConvertTo-HtmlText $c.Advies)</td></tr>"
}

$nAppsSystem = @($appsSorted | Where-Object { $_.Scope -like 'System*' }).Count
$nAppsUser   = @($appsSorted | Where-Object { $_.Scope -like 'User*' }).Count

$summaryRows = $appsSorted | Group-Object Scope, User | Sort-Object Name | ForEach-Object {
    $first = $_.Group[0]
    $isDom = if ($first.UserSid -and (Test-IsDomainAccount $first.UserSid)) { " <span class='badge warn'>domein</span>" } else { '' }
    "<tr><td>$(ConvertTo-HtmlText $first.Scope)</td><td>$(ConvertTo-HtmlText $first.User)$isDom</td><td>$($_.Count)</td></tr>"
}

$scopeOptions = ($appsSorted | Select-Object -ExpandProperty Scope -Unique | Sort-Object | ForEach-Object {
    "<option value='$(ConvertTo-HtmlText $_)'>$(ConvertTo-HtmlText $_)</option>"
}) -join ''

$appRows = foreach ($a in $appsSorted) {
    $scopeCls = if ($a.Scope -like 'System*') { 'info' } else { 'user' }
    "<tr data-scope='$(ConvertTo-HtmlText $a.Scope)'><td><span class='badge $scopeCls'>$(ConvertTo-HtmlText $a.Scope)</span></td><td>$(ConvertTo-HtmlText $a.User)</td><td><strong>$(ConvertTo-HtmlText $a.Name)</strong></td><td>$(ConvertTo-HtmlText $a.Version)</td><td>$(ConvertTo-HtmlText $a.Publisher)</td><td>$(ConvertTo-HtmlText $a.InstallDate)</td><td>$(ConvertTo-HtmlText $a.Architecture)</td><td>$(ConvertTo-HtmlText $a.InstallerType)</td></tr>"
}

$domainText = if ($cs.PartOfDomain) { $domainFqdn } else { "geen (werkgroep $($cs.Workgroup))" }
$generated  = Get-Date -Format 'dd-MM-yyyy HH:mm'

$html = @"
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Unjoin-check $computer</title>
<style>
  :root { --purple:#6F2C91; --yellow:#F3E04F; --tint:#F3EDF7; --soft:#E6D8EF; --mid:#8A4FAB; --text:#2B1A36; --grey:#6B6B6B; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:'Segoe UI',Arial,sans-serif; color:var(--text); background:#fff; font-size:14px; }
  header { background:var(--purple); color:#fff; padding:24px 32px; border-bottom:6px solid var(--yellow); }
  header h1 { margin:0 0 4px; font-size:24px; }
  header p { margin:0; color:var(--soft); }
  nav { background:var(--tint); padding:10px 32px; display:flex; gap:20px; flex-wrap:wrap; }
  nav a { color:var(--purple); font-weight:600; text-decoration:none; }
  nav a:hover { text-decoration:underline; }
  main { padding:24px 32px; max-width:1400px; }
  h2 { color:var(--purple); border-bottom:3px solid var(--yellow); padding-bottom:6px; margin-top:36px; }
  h3 { color:var(--purple); margin:20px 0 8px; }
  .meta { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; margin-bottom:20px; }
  .meta div { background:var(--tint); padding:10px 14px; border-radius:6px; }
  .meta span { display:block; font-size:12px; color:var(--grey); }
  .verdict { padding:14px 18px; border-radius:6px; font-size:16px; font-weight:600; margin-bottom:16px; border-left:6px solid; }
  .verdict.risk { background:#FDECEA; border-color:#C62828; }
  .verdict.warn { background:#FDF9DD; border-color:var(--yellow); }
  .verdict.ok   { background:#E8F5E9; border-color:#2E7D32; }
  .counts { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:20px; }
  .counts div { padding:8px 14px; border-radius:6px; background:var(--tint); }
  .tablewrap { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; }
  th { background:var(--purple); color:#fff; text-align:left; padding:10px; font-weight:600; }
  td { padding:10px; border-bottom:1px solid var(--soft); vertical-align:top; }
  tr:nth-child(even) td { background:#FAF7FC; }
  table.small { max-width:700px; }
  .badge { display:inline-block; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:600; white-space:nowrap; }
  .badge.risk { background:#C62828; color:#fff; }
  .badge.warn { background:var(--yellow); color:var(--text); }
  .badge.ok   { background:#2E7D32; color:#fff; }
  .badge.info { background:var(--soft); color:var(--purple); }
  .badge.user { background:var(--mid); color:#fff; }
  .filters { display:flex; gap:10px; flex-wrap:wrap; margin:10px 0 14px; align-items:center; }
  .filters input, .filters select { padding:8px 10px; border:1px solid var(--soft); border-radius:6px; font:inherit; color:var(--text); }
  .filters input { min-width:260px; flex:1; max-width:420px; }
  #appCount { color:var(--grey); }
  footer { padding:16px 32px; color:var(--grey); font-size:12px; }
  footer strong { color:var(--purple); }
  @media (max-width:800px) { main, header, nav { padding-left:16px; padding-right:16px; } td, th { padding:6px; font-size:12px; } .filters input { min-width:0; width:100%; } }
</style>
</head>
<body>
<header>
  <h1>Controle uit domein halen: $computer</h1>
  <p>Risico-inventarisatie en applicatie-overzicht voorafgaand aan het verwijderen uit het domein</p>
</header>
<nav><a href="#risicos">Risico's</a><a href="#applicaties">Applicaties</a></nav>
<main>
  <div class="meta">
    <div><span>Computer</span>$computer</div>
    <div><span>Domein</span>$(ConvertTo-HtmlText $domainText)</div>
    <div><span>Besturingssysteem</span>$(ConvertTo-HtmlText $os.Caption) ($($os.Version))</div>
    <div><span>Uitgevoerd door / op</span>$(ConvertTo-HtmlText $currentUser) / $generated</div>
  </div>

  <h2 id="risicos">Risico's bij uit domein halen</h2>
  <div class="verdict $vClass">$verdict</div>
  <div class="counts">
    <div><span class="badge risk">Risico</span> $nRisk</div>
    <div><span class="badge warn">Waarschuwing</span> $nWarn</div>
    <div><span class="badge info">Info</span> $nInfo</div>
    <div><span class="badge ok">OK</span> $nOk</div>
  </div>
  <div class="tablewrap">
  <table>
    <thead><tr><th>Status</th><th>Categorie</th><th>Controle</th><th>Bevinding</th><th>Advies</th></tr></thead>
    <tbody>
$($checkRows -join "`n")
    </tbody>
  </table>
  </div>

  <h2 id="applicaties">Applicatie-inventaris</h2>
  <div class="counts">
    <div><span class="badge info">System-wide</span> $nAppsSystem</div>
    <div><span class="badge user">Per gebruiker</span> $nAppsUser</div>
  </div>

  <h3>Overzicht per scope en gebruiker</h3>
  <div class="tablewrap">
  <table class="small">
    <thead><tr><th>Scope</th><th>Gebruiker</th><th>Aantal apps</th></tr></thead>
    <tbody>
$($summaryRows -join "`n")
    </tbody>
  </table>
  </div>

  <h3>Alle applicaties</h3>
  <div class="filters">
    <input id="appFilter" type="search" placeholder="Zoek op naam, uitgever of gebruiker...">
    <select id="scopeFilter"><option value="">Alle scopes</option>$scopeOptions</select>
    <span id="appCount"></span>
  </div>
  <div class="tablewrap">
  <table id="appTable">
    <thead><tr><th>Scope</th><th>Gebruiker</th><th>Naam</th><th>Versie</th><th>Uitgever</th><th>Installatiedatum</th><th>Architectuur</th><th>Type</th></tr></thead>
    <tbody>
$($appRows -join "`n")
    </tbody>
  </table>
  </div>
</main>
<footer><strong>Yellow Spring</strong> &middot; ICT kan slimmer. Het kan. &middot; Read-only controle; er is niets gewijzigd aan de configuratie van de machine.</footer>
<script>
(function () {
  var input = document.getElementById('appFilter');
  var scope = document.getElementById('scopeFilter');
  var rows  = document.querySelectorAll('#appTable tbody tr');
  var count = document.getElementById('appCount');
  function apply() {
    var q = input.value.toLowerCase(), s = scope.value, shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var ok = (!s || r.getAttribute('data-scope') === s) && (!q || r.textContent.toLowerCase().indexOf(q) !== -1);
      r.style.display = ok ? '' : 'none';
      if (ok) shown++;
    }
    count.textContent = shown + ' van ' + rows.length + ' applicaties';
  }
  input.addEventListener('input', apply);
  scope.addEventListener('change', apply);
  apply();
})();
</script>
</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding utf8
$sorted     | Export-Csv -Path $csvChecks -NoTypeInformation -Delimiter ';' -Encoding UTF8
$appsSorted | Export-Csv -Path $csvApps   -NoTypeInformation -Delimiter ';' -Encoding UTF8

Write-Host ''
Write-Host "Unjoin-check $computer" -ForegroundColor Cyan
Write-Host "  Risico: $nRisk  Waarschuwing: $nWarn  Info: $nInfo  OK: $nOk"
$color = switch ($vClass) { 'risk' { 'Red' } 'warn' { 'Yellow' } default { 'Green' } }
Write-Host "  $verdict" -ForegroundColor $color
Write-Host "  Applicaties: $nAppsSystem system-wide, $nAppsUser per gebruiker"
$sorted | Where-Object { $_.Status -in 'Risico', 'Waarschuwing' } |
    Format-Table Status, Categorie, Controle -AutoSize
Write-Host "Rapport:          $htmlPath" -ForegroundColor Green
Write-Host "CSV risico's:     $csvChecks" -ForegroundColor Green
Write-Host "CSV applicaties:  $csvApps" -ForegroundColor Green
#endregion

#region Upload naar inventarisatie-website
if (-not $NoUpload) {
    if ([string]::IsNullOrWhiteSpace($ReportUrl) -or $ReportUrl -like '__*' -or
        [string]::IsNullOrWhiteSpace($ApiKey) -or $ApiKey -like '__*') {
        Write-Warning 'Geen ReportUrl/ApiKey ingesteld; resultaten zijn niet naar de website gestuurd. Download het script opnieuw vanaf de website of geef -ReportUrl en -ApiKey op.'
    }
    else {
        function ConvertTo-PayloadString {
            param($Value)
            if ($null -eq $Value) { return $null }
            return [string]$Value
        }

        $payload = [ordered]@{
            schemaVersion = 1
            scriptVersion = $scriptVersion
            computer      = $computer
            domain        = $domainText
            partOfDomain  = [bool]$cs.PartOfDomain
            domainRole    = $roleNames[[int]$cs.DomainRole]
            os            = "$($os.Caption) ($($os.Version))"
            runBy         = $currentUser
            isAdmin       = [bool]$isAdmin
            generatedAt   = (Get-Date).ToString('o')
            verdict       = $verdict
            verdictClass  = $vClass
            checks        = @($sorted | ForEach-Object {
                [ordered]@{
                    category = ConvertTo-PayloadString $_.Categorie
                    check    = ConvertTo-PayloadString $_.Controle
                    status   = ConvertTo-PayloadString $_.Status
                    detail   = ConvertTo-PayloadString $_.Detail
                    advice   = ConvertTo-PayloadString $_.Advies
                }
            })
            applications  = @($appsSorted | ForEach-Object {
                [ordered]@{
                    scope           = ConvertTo-PayloadString $_.Scope
                    user            = ConvertTo-PayloadString $_.User
                    userSid         = ConvertTo-PayloadString $_.UserSid
                    isDomainUser    = [bool]($_.UserSid -and (Test-IsDomainAccount $_.UserSid))
                    name            = ConvertTo-PayloadString $_.Name
                    version         = ConvertTo-PayloadString $_.Version
                    publisher       = ConvertTo-PayloadString $_.Publisher
                    installDate     = ConvertTo-PayloadString $_.InstallDate
                    architecture    = ConvertTo-PayloadString $_.Architecture
                    installerType   = ConvertTo-PayloadString $_.InstallerType
                    installLocation = ConvertTo-PayloadString $_.InstallLocation
                }
            })
        }

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $json  = $payload | ConvertTo-Json -Depth 5 -Compress
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $uri   = $ReportUrl.TrimEnd('/') + '/api/reports'
            $resp  = Invoke-RestMethod -Uri $uri -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' `
                -Headers @{ 'X-Api-Key' = $ApiKey } -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
            Write-Host "Resultaten verstuurd naar $($ReportUrl.TrimEnd('/')) (rapport-ID: $($resp.reportId))." -ForegroundColor Green
        }
        catch {
            Write-Warning "Versturen naar $ReportUrl is mislukt: $($_.Exception.Message). Het lokale rapport is wel aangemaakt."
        }
    }
}
#endregion

if (-not $NoOpen) { Invoke-Item -LiteralPath $htmlPath }
if ($PassThru) {
    [pscustomobject]@{
        Checks       = $sorted
        Applications = $appsSorted
    }
}
