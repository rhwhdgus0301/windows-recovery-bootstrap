[CmdletBinding()]
param(
    [ValidateSet('Run','SelfTest')][string]$Mode = 'Run',
    [string]$ExpectedSha256
)

$ErrorActionPreference = 'Stop'
$utf8 = New-Object Text.UTF8Encoding($false)
$interventions = New-Object System.Collections.Generic.List[string]
if ($Mode -eq 'SelfTest') {
    $selfHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    if ($selfHash -notmatch '^[A-F0-9]{64}$') { throw 'SHA-256 self-test failed' }
    if ('../escape' -match '^\d{8}T\d{6}Z-[0-9a-f]{12}$') { throw 'Set ID self-test failed' }
    Write-Host 'OK: bootstrap hash and set ID self-test'
    return
}
if (-not $ExpectedSha256) { throw 'ExpectedSha256 from the pinned recovery card is required' }
if ($ExpectedSha256) {
    $actual = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    if ($actual -ine $ExpectedSha256) { throw 'Bootstrap SHA-256 mismatch' }
}
if ([Environment]::OSVersion.Version.Build -lt 22000) { throw 'Windows 11 is required' }

function Require-Program([string]$Name, [string]$PackageId) {
    if (Get-Command $Name -ErrorAction SilentlyContinue) { return }
    & winget.exe install --exact --id $PackageId --source winget --accept-package-agreements --accept-source-agreements | Out-Host
    $env:PATH = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { throw "Program unavailable after install: $Name" }
}

Require-Program 'node.exe' 'OpenJS.NodeJS.LTS'
Require-Program 'restic.exe' 'restic.restic'
if (-not (Get-Command 'npm.cmd' -ErrorAction SilentlyContinue)) { throw 'npm is unavailable' }
if (-not (Get-Command 'codex.cmd' -ErrorAction SilentlyContinue)) {
    & npm.cmd install --global '@openai/codex' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Codex npm installation failed' }
    $env:PATH = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
}
$codex = Get-Command 'codex.cmd' -ErrorAction Stop
if ($codex.Source -notmatch '[\\/]npm[\\/]codex\.cmd$') { throw 'codex is not the npm-original executable' }
& $codex.Source --version | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Codex CLI cannot start' }
& $codex.Source login status *> $null
if ($LASTEXITCODE -ne 0) { $interventions.Add('codex_login') }
Start-Process -FilePath 'cmd.exe' -ArgumentList @('/k', ('"' + $codex.Source + '" -a never -s danger-full-access'))
Write-Host 'Codex opened in a separate interactive window. Complete its login there.'

$vpnName = Read-Host 'VPN profile name'
$interventions.Add('vpn_profile')
if (-not $vpnName) { throw 'VPN profile name required' }
$vpn = Get-VpnConnection -Name $vpnName -ErrorAction SilentlyContinue
if (-not $vpn) { $vpn = Get-VpnConnection -Name $vpnName -AllUserConnection -ErrorAction SilentlyContinue }
if (-not $vpn) {
    $server = Read-Host 'VPN server address'
    $interventions.Add('vpn_server')
    if (-not $server) { throw 'VPN server required' }
    $secret = Read-Host 'VPN pre-shared key' -AsSecureString
    $interventions.Add('vpn_psk')
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        Add-VpnConnection -Name $vpnName -ServerAddress $server -TunnelType L2tp -L2tpPsk $plain -EncryptionLevel Optional -AuthenticationMethod Pap,MSChapv2 -SplitTunneling -RememberCredential -Force | Out-Null
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        Remove-Variable plain -ErrorAction SilentlyContinue
    }
    $vpn = Get-VpnConnection -Name $vpnName -ErrorAction Stop
}
$routes = Read-Host 'VPN split route CIDRs from recovery card, comma-separated'
$interventions.Add('vpn_routes')
if (-not $routes) { throw 'At least one VPN split route is required' }
foreach ($route in ($routes -split ',')) {
    $route = $route.Trim()
    if ($route -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') { throw "Invalid route CIDR: $route" }
    if (-not @($vpn.Routes | Where-Object { $_.DestinationPrefix -eq $route }).Count) {
        if ($vpn.AllUserConnection) { throw 'Shared VPN route needs administrator setup before bootstrap can continue' }
        Add-VpnConnectionRoute -ConnectionName $vpnName -DestinationPrefix $route -ErrorAction Stop | Out-Null
    }
}
& rasdial.exe $vpnName | Out-Host
$interventions.Add('vpn_connection')
$vpn = if ($vpn.AllUserConnection) { Get-VpnConnection -Name $vpnName -AllUserConnection -ErrorAction Stop } else { Get-VpnConnection -Name $vpnName -ErrorAction Stop }
if ($vpn.ConnectionStatus -ne 'Connected' -or -not $vpn.SplitTunneling) { throw 'VPN is not Connected with split tunneling' }
foreach ($route in ($routes -split ',')) {
    if (@($vpn.Routes | Where-Object { $_.DestinationPrefix -eq $route.Trim() }).Count -ne 1) { throw "VPN route not present: $route" }
}

$labHost = Read-Host 'Lab host or IP from recovery card'
$interventions.Add('lab_host')
$fingerprint = Read-Host 'Expected lab SSH host-key SHA256 fingerprint'
$interventions.Add('lab_fingerprint')
if (-not $labHost -or $fingerprint -notmatch '^SHA256:[A-Za-z0-9+/]+$') { throw 'Lab host identity input missing' }
$scan = & ssh-keyscan.exe -t ed25519 $labHost 2>$null
if ($LASTEXITCODE -ne 0 -or -not $scan) { throw 'Lab SSH host key unavailable' }
$seen = $scan | & ssh-keygen.exe -lf -
if ($LASTEXITCODE -ne 0 -or $seen -notmatch [regex]::Escape($fingerprint)) { throw 'Lab SSH host-key mismatch' }

$share = Read-Host 'Read-only recovery share name'
$interventions.Add('recovery_share')
$account = Read-Host 'Dedicated recovery account'
$interventions.Add('recovery_account')
if (-not $share -or -not $account) { throw 'Recovery share credentials missing' }
$credential = Get-Credential -UserName $account -Message 'Read-only repository account'
$interventions.Add('smb_password')
$drive = 'R'
if (Get-PSDrive -Name $drive -ErrorAction SilentlyContinue) { throw 'Recovery drive letter R is already in use' }
New-PSDrive -Name $drive -PSProvider FileSystem -Root "\\$labHost\$share" -Credential $credential -Persist -Scope Global | Out-Null
if (-not (Test-Path -LiteralPath 'R:\config' -PathType Leaf)) { throw 'Restic repository config not readable' }

$password = Read-Host 'Restic repository password' -AsSecureString
$interventions.Add('restic_password')
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
try {
    $env:RESTIC_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    $env:RESTIC_REPOSITORY = 'R:\'
    $snapshotsText = (& restic.exe --no-lock snapshots --json) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read restic snapshots' }
    $snapshots = $snapshotsText | ConvertFrom-Json
    $ready = @()
    foreach ($snapshot in $snapshots) {
        if ($snapshot.tags -contains 'recovery-ready') { $ready += $snapshot }
    }
    $ready = @($ready | Sort-Object time -Descending)
    if (-not $ready.Count) { throw 'No recovery-ready receipt snapshot exists' }
    $receiptSnapshot = $ready[0]
    $receiptText = (& restic.exe --no-lock dump $receiptSnapshot.id recovery-receipt.json) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read recovery-ready receipt' }
    $receipt = $receiptText | ConvertFrom-Json
    if ($receipt.status -ne 'recovery-ready' -or $receipt.set_id -notmatch '^\d{8}T\d{6}Z-[0-9a-f]{12}$' -or $receiptSnapshot.tags -notcontains $receipt.set_id) {
        throw 'Recovery receipt and snapshot tags do not match'
    }
    foreach ($name in @('vault_snapshot_id','payload_snapshot_id')) {
        if ($receipt.$name -notmatch '^[a-f0-9]{64}$') { throw "Invalid recovery snapshot ID: $name" }
    }
    foreach ($file in $receipt.kit_sha256.PSObject.Properties.Name) {
        if ($file -notmatch '^05_System/(?:config|scripts)/[A-Za-z0-9_./-]+$' -or $file -match '(^|/)\.\.(/|$)') {
            throw "Unsafe recovery kit path: $file"
        }
    }
    $setRoot = Join-Path $env:LOCALAPPDATA "VaultRecovery\$($receipt.set_id)"
    $kit = Join-Path $setRoot 'kit'
    New-Item -ItemType Directory -Path $kit -Force | Out-Null
    $interventionPath = Join-Path $setRoot 'interventions.json'
    $previousReasons = @()
    if (Test-Path -LiteralPath $interventionPath -PathType Leaf) {
        $previousReasons = @((Get-Content -LiteralPath $interventionPath -Raw -Encoding UTF8 | ConvertFrom-Json).reasons)
    }
    $reasons = @($previousReasons) + @($interventions.ToArray())
    [IO.File]::WriteAllText($interventionPath, (@{schema=1; count=$reasons.Count; reasons=$reasons} | ConvertTo-Json -Depth 4), $utf8)
    $receipt | Add-Member -NotePropertyName receipt_snapshot_id -NotePropertyValue $receiptSnapshot.id
    [IO.File]::WriteAllText((Join-Path $kit 'recovery-receipt.json'), ($receipt | ConvertTo-Json -Depth 20), $utf8)
    $restoreArgs = @('--no-lock','restore',$receipt.vault_snapshot_id,'--target',$kit,'--overwrite','never')
    foreach ($file in $receipt.kit_sha256.PSObject.Properties.Name) { $restoreArgs += @('--include',('/' + $file.Replace('\','/'))) }
    & restic.exe @restoreArgs | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Recovery kit extraction failed' }
    foreach ($item in $receipt.kit_sha256.PSObject.Properties) {
        $path = Join-Path $kit $item.Name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $item.Value) {
            throw "Recovery kit hash mismatch: $($item.Name)"
        }
    }
    $vaultPath = Read-Host 'Destination path for the restored Vault'
    $interventions.Add('vault_destination')
    if (-not $vaultPath) { throw 'Vault destination required' }
    $reasons = @($reasons) + @('vault_destination')
    [IO.File]::WriteAllText($interventionPath, (@{schema=1; count=$reasons.Count; reasons=$reasons} | ConvertTo-Json -Depth 4), $utf8)
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $kit '05_System\scripts\workstation\restore_machine.ps1') -Mode Run -SetId $receipt.set_id -KitPath $kit -VaultPath $vaultPath
    if ($LASTEXITCODE -ne 0) { throw "Recovery paused at checkpoint: $(Join-Path $setRoot 'state.json')" }
} finally {
    $env:RESTIC_PASSWORD = $null
    $env:RESTIC_REPOSITORY = $null
    if (Get-PSDrive -Name $drive -ErrorAction SilentlyContinue) { Remove-PSDrive -Name $drive -Force -ErrorAction SilentlyContinue }
}
