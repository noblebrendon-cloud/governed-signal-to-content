[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Workspace,

    [string]$PythonExecutable = "python"
)

$ErrorActionPreference = "Stop"

& $PythonExecutable -m governed_signal_to_content status --workspace $Workspace
if ($LASTEXITCODE -ne 0) {
    throw "Governed workspace status check failed with exit code $LASTEXITCODE."
}

Write-Output "No discovery adapter is enabled by default. Status check completed; no external source was contacted."
