# Loop the FULL workspace suite, preserving each failing run's log.
#
# Individual-binary soaks miss cross-test contention: the real suite runs many
# test binaries at once, so sockets and CPU are fought over between binaries,
# not just within one. This reproduces that, and — crucially — keeps the log of
# any run that fails so the cause is not lost to a passing rerun.
param([int]$Runs = 8)

$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
# Repo root = parent of this script's directory.
Set-Location (Split-Path $PSScriptRoot -Parent)

cargo build --workspace --tests 2>&1 | Select-String "^error" | Select-Object -First 3
$fails = 0
for ($r = 1; $r -le $Runs; $r++) {
  $log = "$env:TEMP\soakfull-$r.log"
  cargo test --workspace 2>&1 | Out-File $log -Encoding utf8
  $txt = Get-Content $log -Raw
  if ($txt -match "test result: FAILED|error: test failed") {
    $fails++
    $which = ($txt -split "`n" | Select-String -Pattern "Running .*deps.\\(\w+)|rerun pass|panicked at|assertion|timed out|diverged|EADDR|FAILED\]" | Select-Object -First 8)
    Write-Output "run ${r}: FAIL  (log: $log)"
    $which | ForEach-Object { Write-Output "    $_" }
  } else {
    Write-Output "run ${r}: PASS"
    Remove-Item $log -ErrorAction SilentlyContinue
  }
}
Write-Output "=== $fails / $Runs full-suite runs failed ==="
