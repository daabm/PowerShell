Import-Module $GitRepos\ForkedRepositories\UncommonSense.PowerShell.Documentation -Force
$ModuleDirs = Get-ChildItem $PSScriptRoot -Directory

Foreach ( $ModuleDir in $ModuleDirs ) {
    Import-Module $ModuleDir.FullName -Force
    $DescriptionFile = "$( $ModuleDir.FullName )\Description.md"
    If ( Test-Path -Path $DescriptionFile ) {
        $Description = Get-Content $DescriptionFile
    }

    Get-Command -Module $ModuleDir.Name |
        Sort-Object Noun, Verb |
        Convert-HelpToMarkDown -Title $ModuleDir.Name -Description $Description |
        Out-File "$( $ModuleDir.FullName ).\README.md" -Encoding utf8 -Force
}
