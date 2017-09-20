Import-Module "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\Get-FireDrill\Get-FireDrill.psm1" -Force -DisableNameChecking

Start-Transcript -Path 'D:\Scripts\AttackIQ\Logs\FDScenario.txt' -Append
# Script for Automation of Get-FireDrillResults from the AttackIQ FireDrill Results API

$FDResults = Get-FireDrill -attackIQAPI Scenarios
$SplunkReturnCount = '1500'

If (($FDResults) -notlike $null) {
    $SplunkResult = Set-FireDrillSplunkSearch -APISplunkSearch Scenarios -APIResultSource DEFAULT -APIResults $FDResults -SplunkReturnCount $SplunkReturnCount
} else {
    Write-Host "ERROR: FireDrill Results were empty... no results today or something could be wrong..."
    Stop-Transcript
    Break
}

$SampleSet = $FDResults | select -First 5

Write-Host "----------------------------------" -ForegroundColor Cyan
Write-host "SAMPLE SET: 5 FireDrill Scenarios" -ForegroundColor Cyan
Write-Output $SampleSet
Write-Host "----------------------------------" -ForegroundColor Cyan

Write-Host "----------------------------------" -ForegroundColor Cyan
Write-host "FireDrill Result Results" -ForegroundColor Cyan
Write-host $FDResults.count -ForegroundColor Cyan
Write-Host "----------------------------------" -ForegroundColor Cyan

Write-Host "----------------------------------" -ForegroundColor Cyan
Write-Host "FireDrill Result Splunk Results" -ForegroundColor Cyan
Write-host $SplunkResult.count  -ForegroundColor Cyan
Write-Host "----------------------------------" -ForegroundColor Cyan

Stop-Transcript
