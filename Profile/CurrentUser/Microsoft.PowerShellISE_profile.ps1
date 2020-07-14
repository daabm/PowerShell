Try {
    Import-Module -Name UpdateInstalledModule
    Update-InstalledModule -Scope CurrentUser
    Remove-Module -Name UpdateInstalledModule -Force
  }
Catch { $_ }

$AutoLoadModules = @( 'CopyScriptToClipboard', 'IseSteroids', 'VariableExplorer', 'ScriptBrowser', "$ForkedRepos\UncommonSense.PowerShell.Documentation" )

Foreach ( $AutoloadModule in $AutoLoadModules ) {
    If ( $AutoloadModule -match '\\' -or ( Get-Module $AutoloadModule -ListAvailable ) ) {
        Import-Module -Name $AutoloadModule -ErrorAction SilentlyContinue
    }
}

Enable-ScriptAnalyzer -ErrorAction SilentlyContinue
