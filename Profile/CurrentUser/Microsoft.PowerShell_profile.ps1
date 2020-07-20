$NuGetApiKey = '#######################'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
[Net.WebRequest]::DefaultWebProxy = New-Object -TypeName Net.WebProxy( '########################' )
[Net.WebRequest]::DefaultWebProxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
[Net.WebRequest]::DefaultWebProxy.BypassProxyOnLocal = $true

$Personal = [Environment]::GetFolderPath( 'MyDocuments' )
$MyModules = $Personal + '\WindowsPowershell\Modules'
$GitRepos = $Personal + '\GIT'
$ForkedRepos = $GitRepos + '\ForkedRepositories'
$MyGITModules = $GitRepos+ '\MyRepositories\PowerShell\Modules'

<##>
If ( $env:PSModulePath -notmatch [regex]::Escape( $MyGITModules ) ) {
    $Paths = New-Object System.Collections.ArrayList
    [void]$Paths.AddRange( ( $env:PSModulePath -split ';' | ForEach-Object { $_ -replace ';', '' } ) )
    [void]$Paths.Add( $MyGITModules )
    $env:PSModulePath = $Paths -join ';'
}
#>
