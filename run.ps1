$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path '.\network-monitor.exe')) {
        throw 'Build the app first with .\build.ps1.'
    }
    & '.\network-monitor.exe' @args
}
finally {
    Pop-Location
}
