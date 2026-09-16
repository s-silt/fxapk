# Dot-source to select this checkout's Python and configured native tools for this session.
param([string]$Python)
$toolchainPreviousErrorActionPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Stop'
    if (-not $Python) {
        $Python = Join-Path (Split-Path $PSScriptRoot -Parent) '.venv\Scripts\python.exe'
    }
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "Python not found: $Python" }
    $probe = @'
import json, sys, sysconfig
from pathlib import Path
from apkscan.core import tools
names = ['adb', 'jadx', 'apktool', 'tshark', 'frida', 'frida-ps', 'frida-dexdump',
         'mitmdump', 'mitmproxy', 'mitmweb']
selected = {}
for name in names:
    value = tools.executable_path(name)
    if not value:
        raise SystemExit('Required tool unavailable: ' + name)
    selected[name] = value
print(json.dumps({'python': sys.executable, 'scripts': sysconfig.get_path('scripts'), 'tools': selected}))
'@
    $raw = & $Python -c $probe
    if ($LASTEXITCODE -ne 0) { throw 'Toolchain selection failed; session PATH was not changed.' }
    $selection = $raw | ConvertFrom-Json
    # Only prepend the project interpreter's scripts. Adding the isolated proxy's
    # scripts directory would also shadow python.exe. Aliases select exact tools.
    $env:PATH = (@($selection.scripts) + @($env:PATH -split ';' | Where-Object { $_ -and $_ -ne $selection.scripts })) -join ';'
    $env:VIRTUAL_ENV = Split-Path $selection.scripts -Parent
    Set-Alias -Name python -Value $selection.python -Scope Global
    Write-Host "Python: $($selection.python)"
    foreach ($entry in $selection.tools.PSObject.Properties) {
        Set-Alias -Name $entry.Name -Value $entry.Value -Scope Global
        Write-Host "$($entry.Name): $($entry.Value)"
    }
} finally {
    $ErrorActionPreference = $toolchainPreviousErrorActionPreference
}
