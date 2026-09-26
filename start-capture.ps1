param(
    [string]$Interface = 'auto',
    [switch]$LiveLab,
    [switch]$EnableValidatedAeOnly,
    [string]$FeatureDump
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $pwsh = (Get-Process -Id $PID).Path
    $safeInterface = $Interface.Replace('"', '\"')
    $arguments = '-NoExit -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Interface "' + $safeInterface + '" -LiveLab:$' + $LiveLab + ' -EnableValidatedAeOnly:$' + $EnableValidatedAeOnly
    if ($FeatureDump) {
        $safeDump = $FeatureDump.Replace('"', '\"')
        $arguments += ' -FeatureDump "' + $safeDump + '"'
    }
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

$npcap = Get-Service -Name npcap -ErrorAction SilentlyContinue
if (-not $npcap) {
    throw 'Npcap is not installed. Install Npcap, then run this script again from Administrator PowerShell.'
}
if ($npcap.Status -ne 'Running') {
    throw "Npcap service is $($npcap.Status). Start Npcap or reboot, then run this script again."
}

if (-not (Test-NetConnection -ComputerName '127.0.0.1' -Port 6380 -InformationLevel Quiet)) {
    throw 'Redis is not reachable on 127.0.0.1:6380. Start Docker Desktop, then run `docker compose up --build` from the project root and keep it running.'
}

$env:REDIS_HOST = '127.0.0.1'
$env:REDIS_PORT = '6380'
$env:REDIS_PASSWORD = $redisPassword
$env:CAPTURE_INTERFACE = $Interface
$env:IDS_EVIDENCE_ORIGIN = if ($LiveLab) { 'live_lab' } else { 'live_unclassified' }
# Never enable AE-only alerting just because capture started. Enable it only
# after validate_live_capture.py passes on a labelled controlled-lab capture.
$env:IDS_AE_ONLY_ALERTING_VALIDATED = if ($EnableValidatedAeOnly) { 'true' } else { 'false' }
if ($FeatureDump) {
    $env:IDS_DUMP_FEATURES = if ([IO.Path]::IsPathRooted($FeatureDump)) {
        $FeatureDump
    } else {
        Join-Path $root $FeatureDump
    }
}
Set-Location (Join-Path $root 'backend')

python -c "import os, redis; redis.Redis(host='127.0.0.1', port=6380, password=os.environ.get('REDIS_PASSWORD'), socket_connect_timeout=2, socket_timeout=2).ping(); print('Redis auth OK')"
Write-Host "Starting IDS capture on interface '$Interface' (evidence: $env:IDS_EVIDENCE_ORIGIN). Leave this window open." -ForegroundColor Green
if ($FeatureDump) {
    Write-Host "Raw live features will be appended to: $FeatureDump" -ForegroundColor Yellow
}
if ($EnableValidatedAeOnly) {
    Write-Warning 'AE-only alerting enabled by explicit operator choice. Use this only after validate_live_capture.py passed on held-out controlled live-lab traffic.'
}
python main.py --mode ids --interface $env:CAPTURE_INTERFACE
