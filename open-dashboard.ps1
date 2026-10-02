# Opens the dashboard in your default browser, already carrying IDS_API_TOKEN from the root .env.
# Safe by design: only someone who can read this machine's .env can do this; the server itself
# never hands the token out. Without a token set, it just opens the plain dashboard.
#   .\open-dashboard.ps1                      (http://localhost:5000)
#   .\open-dashboard.ps1 -Url http://host:5000
param([string]$Url = 'http://localhost:5000')

$envFile = Join-Path $PSScriptRoot '.env'
$token = $null
if (Test-Path -LiteralPath $envFile) {
    $line = Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^\s*IDS_API_TOKEN\s*=' } | Select-Object -First 1
    if ($line) { $token = ($line -replace '^\s*IDS_API_TOKEN\s*=\s*', '').Trim().Trim('"').Trim("'") }
}

$target = $Url.TrimEnd('/') + '/'
if ($token) {
    $target += '?token=' + [uri]::EscapeDataString($token)
    Write-Host "Opening $($Url.TrimEnd('/'))/ with the API token from .env (the page removes it from the address bar)." -ForegroundColor Green
} else {
    Write-Host "No IDS_API_TOKEN in .env - opening $target without a token." -ForegroundColor Yellow
}
Start-Process $target
