param([string]$JsonFile)

$Tests = Get-Content $JsonFile -Raw | ConvertFrom-Json

$s = New-PSSession -HostName 192.168.122.115 -UserName huy

Invoke-Command -Session $s -ScriptBlock {
    param($Tests)

    Set-ExecutionPolicy Bypass -Scope Process -Force
    Import-Module powershell-yaml
    Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
    $Global:PathToAtomicsFolder = "C:\AtomicRedTeam\atomics"
    foreach ($t in $Tests) {

        Write-Host "START $($t.Technique) Test $($t.Test)"

        Invoke-AtomicTest $t.Technique -TestNumbers $t.Test -ErrorAction Continue

        Write-Host "END $($t.Technique) Test $($t.Test)"
        Invoke-AtomicTest $t.Technique -TestNumbers $t.Test -CleanUp
    }
} -ArgumentList (,$Tests)

Remove-PSSession $s

