[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryPath,

    [Parameter(Mandatory = $true)]
    [string]$Workspace,

    [string]$TaskName = "GovernedSignalToContentStatus",

    [string]$PythonExecutable = "python"
)

$ErrorActionPreference = "Stop"
$repository = (Resolve-Path -LiteralPath $RepositoryPath).Path
$runner = Join-Path $repository "scripts\run_watch.ps1"
if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw "Runner not found: $runner"
}

$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$runner`" -Workspace `"$Workspace`" -PythonExecutable `"$PythonExecutable`""
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

if ($PSCmdlet.ShouldProcess($TaskName, "Register a weekly local status task")) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "Local governed signal-to-content status check; no credentials embedded."
}
