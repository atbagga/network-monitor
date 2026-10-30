$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path 'web\node_modules')) {
        & npm.cmd --prefix web ci --no-fund --no-audit
        if ($LASTEXITCODE -ne 0) { throw 'Dashboard dependency installation failed.' }
    }
    & npm.cmd --prefix web run build
    if ($LASTEXITCODE -ne 0) { throw 'Dashboard build failed.' }
    & go build -trimpath -o network-monitor.exe ./cmd/netmon
    if ($LASTEXITCODE -ne 0) { throw 'Service build failed.' }
    Write-Output 'Built network-monitor.exe. Run .\run.ps1 to open the local service on port 8787.'
}
finally {
    Pop-Location
}
