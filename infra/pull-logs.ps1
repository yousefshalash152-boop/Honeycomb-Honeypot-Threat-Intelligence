# Pull the Cowrie log from the honeypot VM into data\raw\ (never committed).
# Usage:
#   powershell -ExecutionPolicy Bypass -File infra\pull-logs.ps1 -VmIp <IP> -AdminPort <PORT> -AdminUser <USER>
# Note: the Cowrie image has no cat/ls, so the log is read with Python inside the
# container. The Python code travels base64-encoded to avoid quoting problems.
param(
    [Parameter(Mandatory = $true)][string]$VmIp,
    [Parameter(Mandatory = $true)][int]$AdminPort,
    [Parameter(Mandatory = $true)][string]$AdminUser
)

$ErrorActionPreference = "Stop"

$outDir = Join-Path $PSScriptRoot "..\data\raw"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out = Join-Path $outDir "cowrie-$stamp.json"

$py = "import sys; sys.stdout.write(open('/cowrie/cowrie-git/var/log/cowrie/cowrie.json').read())"
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($py))
$remoteCmd = "echo $b64 | base64 -d | docker exec -i honeycomb-cowrie python -"

$data = ssh -p $AdminPort "$AdminUser@$VmIp" $remoteCmd
if ($LASTEXITCODE -ne 0) {
    throw "SSH or docker command failed (exit code $LASTEXITCODE). Nothing was saved."
}
if (-not $data) {
    Write-Host "Connected, but there are no events yet. Nothing saved."
    exit 0
}

$data | Set-Content -Path $out -Encoding UTF8
Write-Host "Saved $out"
