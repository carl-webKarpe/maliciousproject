$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'endpoint_agent.ps1'), [ref]$tokens, [ref]$errors) | Out-Null

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { $_.Message }
    exit 1
}

'PowerShell parse OK'
