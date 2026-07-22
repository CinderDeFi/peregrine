# Soak the restart_recovery test under heavy CPU load.
#
# The flake only appears when the whole workspace suite is running, i.e. when
# every core is busy. Reproducing it therefore means competing for CPU on
# purpose: `-Load N` starts N spinner processes, then the test runs `-Runs`
# times and failures are counted.
param(
  [int]$Runs = 8,
  [int]$Load = 24,
  [string]$TestName = "restart_recovery"
)

$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
# Repo root = parent of this script's directory.
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Output "building test binary..."
cargo test -p peregrine-node --test $TestName --no-run 2>&1 | Select-String "^error" | Select-Object -First 5

$burners = @()
for ($i = 0; $i -lt $Load; $i++) {
  $burners += Start-Process -FilePath "powershell" `
    -ArgumentList "-NoProfile","-Command","`$x=0; while(`$true){ `$x = (`$x + 1) % 1000000 }" `
    -PassThru -WindowStyle Hidden
}
Write-Output "started $Load CPU burners"
Start-Sleep -Seconds 2

$fail = 0
$log = "$env:TEMP\soak-$TestName.log"
Remove-Item $log -ErrorAction SilentlyContinue

for ($r = 1; $r -le $Runs; $r++) {
  $out = cargo test -p peregrine-node --test $TestName -- --nocapture 2>&1 | Out-String
  Add-Content $log "===== run $r ====="
  Add-Content $log $out
  if ($out -match "test result: ok") {
    Write-Output "run ${r}: PASS"
  } else {
    $fail++
    Write-Output "run ${r}: FAIL"
    # Surface the reason immediately — that is the whole point of the soak.
    ($out -split "`n" | Select-String -Pattern "panicked|assertion|diverged|did not rejoin|left|right|Error" | Select-Object -First 6) | ForEach-Object { Write-Output "    $_" }
  }
}

foreach ($b in $burners) { Stop-Process -Id $b.Id -Force -ErrorAction SilentlyContinue }
Write-Output "=== $fail / $Runs failed === (full log: $log)"
