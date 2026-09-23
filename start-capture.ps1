$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $pwsh = (Get-Process -Id $PID).Path
    $arguments = '-NoExit -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
    Start-Process -FilePath $pwsh -Verb RunAs -ArgumentList $arguments
    exit
}

$root = $PSScriptRoot
$envFile = Join-Path $root '.env'
if (-not (Test-Path -LiteralPath $envFile)) {
    throw "Missing $envFile. Start the stack with docker compose and create the root .env from .env.example first."
}

$passwordLine = Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^\s*REDIS_PASSWORD\s*=' } | Select-Object -First 1
if (-not $passwordLine) {
    throw 'REDIS_PASSWORD is not set in the project root .env file.'
}
$redisPassword = ($passwordLine -replace '^\s*REDIS_PASSWORD\s*=\s*', '').Trim().Trim('"').Trim("'")
if (-not $redisPassword -or $redisPassword -match '^(your|change.?me|example)' ) {
    throw 'Set a real REDIS_PASSWORD in the project root .env file before starting capture.'
}

$env:REDIS_HOST = '127.0.0.1'
$env:REDIS_PORT = '6380'
$env:REDIS_PASSWORD = $redisPassword
$env:CAPTURE_INTERFACE = 'auto'
Set-Location (Join-Path $root 'backend')
python main.py --mode ids --interface $env:CAPTURE_INTERFACE
