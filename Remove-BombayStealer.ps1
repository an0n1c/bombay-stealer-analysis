
# Remove-BombayStealer.ps1
# Defensive detection and removal of identified Bombay Stealer persistence artifacts.
# SHA-256 is not required.
#
# Scan:
#   .\Remove-BombayStealer.ps1
#
# Removal:
#   .\Remove-BombayStealer.ps1 -Remove
#
# Preview:
#   .\Remove-BombayStealer.ps1 -Remove -WhatIf

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

$targetDir = Join-Path $env:LOCALAPPDATA 'WindowsRecovery'
$targetExe = Join-Path $targetDir 'Update.exe'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$valueName = 'WindowsRecovery'

Write-Host ''
Write-Host 'Bombay Stealer - Detection and Cleanup' -ForegroundColor Cyan
Write-Host '====================================='
Write-Host "Target file: $targetExe"
Write-Host "Registry key: $runKey"
Write-Host "Registry value: $valueName"
Write-Host ''

# Check for directory/file redirection.
if (Test-Path -LiteralPath $targetDir) {
    $dirItem = Get-Item -LiteralPath $targetDir -Force

    if ($dirItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Installation directory is a reparse point. Manual inspection required.'
    }
}

$fileExists = Test-Path -LiteralPath $targetExe -PathType Leaf

if ($fileExists) {
    $fileItem = Get-Item -LiteralPath $targetExe -Force

    if ($fileItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Executable is a reparse point. Manual inspection required.'
    }

    Write-Host '[FOUND] Executable at expected path.' -ForegroundColor Yellow

    try {
        $hash = (Get-FileHash -LiteralPath $targetExe -Algorithm SHA256).Hash
        Write-Host "SHA-256: $hash"
    }
    catch {
        Write-Warning "Could not calculate SHA-256: $_"
    }
}
else {
    Write-Host '[OK] Expected executable not found.' -ForegroundColor Green
}

# Inspect the autorun value.
$registryMatches = $false
$registryPresent = $false

if (Test-Path -LiteralPath $runKey) {
    $runProperties = Get-ItemProperty -LiteralPath $runKey -ErrorAction Stop

    $registryProperty = $runProperties.PSObject.Properties[$valueName]

    if ($null -ne $registryProperty) {
        $registryPresent = $true
        $registryData = [string]$registryProperty.Value
        $normalizedData = [Environment]::ExpandEnvironmentVariables(
            $registryData.Trim().Trim('"')
        )

        Write-Host "[FOUND] Autorun value: $registryData" -ForegroundColor Yellow

        if ($normalizedData -ieq $targetExe) {
            $registryMatches = $true
            Write-Host '[MATCH] Autorun points to the expected executable.' -ForegroundColor Green
        }
        else {
            Write-Warning 'Autorun value does not exactly match the expected path.'
        }
    }
}

if (-not $registryPresent) {
    Write-Host '[OK] Expected autorun value not found.' -ForegroundColor Green
}

# Detect running processes at the expected path.
$processes = @(
    Get-CimInstance Win32_Process -ErrorAction Stop |
        Where-Object {
            $_.ExecutablePath -and
            $_.ExecutablePath -ieq $targetExe
        }
)

foreach ($proc in $processes) {
    Write-Host "[FOUND] Running process: PID $($proc.ProcessId)" -ForegroundColor Yellow
}

Write-Host ''

if (-not $Remove) {
    Write-Host 'Scan complete. No changes were made.' -ForegroundColor Cyan
    Write-Host 'To attempt cleanup, use:'
    Write-Host '  .\Remove-BombayStealer.ps1 -Remove'
    return
}

# Refuse automatic removal without the matching Run entry.
# A file path alone does not prove that a file is malicious.
if (-not $registryMatches) {
    Write-Warning 'Automatic cleanup requires a matching WindowsRecovery autorun entry.'
    Write-Warning 'No files or processes were modified.'
    return
}

# Stop matching processes.
foreach ($proc in $processes) {
    if ($PSCmdlet.ShouldProcess(
        "PID $($proc.ProcessId)",
        'Stop process running from the identified executable path'
    )) {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
        Write-Host "[REMOVED] Stopped PID $($proc.ProcessId)"
    }
}

# Remove the matching Run value.
if ($PSCmdlet.ShouldProcess(
    "$runKey\$valueName",
    'Remove matching autorun entry'
)) {
    Remove-ItemProperty -LiteralPath $runKey `
        -Name $valueName -ErrorAction Stop

    Write-Host '[REMOVED] Autorun entry.' -ForegroundColor Green
}

# Remove the executable.
if ($fileExists) {
    if ($PSCmdlet.ShouldProcess(
        $targetExe,
        'Delete executable at matching persistence path'
    )) {
        Remove-Item -LiteralPath $targetExe -Force -ErrorAction Stop
        Write-Host '[REMOVED] Executable.' -ForegroundColor Green
    }
}

# Remove the directory only when empty.
if (Test-Path -LiteralPath $targetDir -PathType Container) {
    $remaining = @(Get-ChildItem -LiteralPath $targetDir -Force)

    if ($remaining.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess(
            $targetDir,
            'Remove empty installation directory'
        )) {
            Remove-Item -LiteralPath $targetDir -Force -ErrorAction Stop
            Write-Host '[REMOVED] Empty directory.' -ForegroundColor Green
        }
    }
    else {
        Write-Warning 'Additional files remain in the directory. They were preserved.'
    }
}

Write-Host ''
Write-Host 'Cleanup finished. Run Microsoft Defender Offline afterward.' -ForegroundColor Cyan
