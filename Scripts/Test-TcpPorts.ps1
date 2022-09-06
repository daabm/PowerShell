<#
    .SYNOPSIS

    Checks a list of well known ports that are required for Active Directory to work properly. Computers to test are derived from DNS resolution.

    Alternatively checks a list of custom ports against single or multiple computers, including RPC and SSL checks.

    .DESCRIPTION

    Often logon issues occur which are hard to track down, or spurious connectivity errors to domain controllers. This script evaluates all DCs in an environment. Then it queries defined ports against each DC, optionally including dynamic RPC endpoints and verifying SSL connectivity.

    This basic check ensures that at least no firewalls or stale DNS records are causing issues. All port checks are executed in parallel which greatly improves total processing time.

    Without any parameters, it evaluates the domain of the current computer. This domain is resolved through DNS lookup, and all IP addresses are checked for a predefined list of ports (88/135/389/445/464/636/3268/3269).

    The results are collected in an array of [PSCustomObject]. This array is piped to Out-Gridview for quick convenient analysis as well as to the clipboard for copy/paste to different targets. If you want to reuse the results, dot-source the script and grab $ComputerList.

    The columns of the result are mostly self explaining. Since we do a lot of DNS resolution which for cnames can "change" the computername, the original value that led us to each IP Address is also preserved in the results.

    The need for this script initially originated from complex domain environments with lots of trusts and infrastructure firewalls. Hence it has a builtin list of ports that we assume to be required for proper active directory communication to domain controllers.

    Since all required parameters are pipeline aware, you can also pipe an array of objects to the script. These objects must have the required properties, at least 'Computer'. Optionally, you can use 'Ports', 'SSLPorts' and other properties. This enables you to quickly test an array of computers where each computer is tested for different ports.

    .PARAMETER Computer

    Specify a list of computers (names or IP addresses) to check. Can also be a domain name which will resolve to multiple addresses.

    If you omit this parameter, the domain of the current computer is resolved in DNS and all resulting IP addresses are checked.

    If you specify a plain host name (no DNS suffix), the global DNSSuffix is appended (see below). FQDNs and IP addresses are used as provided.

    If you specify a domain name here, it will slightly mess the output, especially computer names. We don't know that you provided a domain and DNS also does not tell us that it is a domain. When we start reverse resolution for the IP addresses and there are multiple PTR records (or these PTR records resolve to names that themselves resolve to multiple host names), we are unable to extract a domain name or determine which A record is the real computername.

    .PARAMETER DNSSuffix

    For computers/DNS names with FQDN and for IP addresses, this parameter is ignored. All Netbios names (aka strings without dots in them) are padded with this DNS suffix. Makes things easier if you run the script interactively from a prompt :)

    If not specified, the primary dns suffix of the local computer will be used as DNSSuffix.

    .PARAMETER IncludeTrustedDomains

    If you do not specify computers to check, the domain of the current computer is verified. If you specify this switch, all domains that the current computer's domain is trusting will be also checked.

    If you specified one or more computers, this switch is ignored.

    .PARAMETER IncludeTrustingDomains

    If you do not specify computers to check, all domain controllers of the domain of the current computer are verified. If you specify this switch, all domains that trust the current computer's domain will be also checked.

    If you specified one or more computers, this switch is ignored.

    .PARAMETER Ports

    By default, a predefined list of ports is checked (88/135/389/445/464/636/3268/3269). If you want to check a custom port range, provide an array of port numbers to check. You can specify port numbers in a range from 1 to 65535. All port numbers are by default resolved to their names against etc/services.

    If you need a different set of ports to be checked by default, edit the script and modify the Ports parameter array to your needs.

    .PARAMETER ResolvePortNames

    If you provide a custom port list and some of these cannot be resolved to their well known service name via etc\services, the script will download the current list of all defined services from IANA and resolve the ports to their names.

    Note: The list of well known ports is downloaded directly from IANA - https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
    Since this list contains more than 14.000 entries, this may take a while (4 MB). And of course this only works if you have internet connectivity.

    .PARAMETER IncludeEPM

    Add this switch to query all dynamic RPC ports from the RPC endpoint mapper. This of course only works if EPM itself (TCP/135) is reachable. If you add this switch, EPM itself will be added to the list of ports to check if it is missing.

    This comes in extremely handy if you have systems with different RPC port ranges combined with infrastructure firewalls, like we do. Some of them are in the 5000 range, some in the 9000 range and some in the default range of 49152-65535. So we are required to not only know that we need RPC, but also  which RPC range our target computer uses.

    .PARAMETER ResolveEPM

    By default, all enumerated EPM ports will only be listed with their annotation or (if missing - not all endpoints have an annotation) their interface UUID. Some of the frequent endpoints are resolved with a static list that is hardcoded into the script.

    Usually unresolved GUIDs can be found through a web search. If you specify this switch, EPM port UUIDs will be checked against two lists found at https://raw.githubusercontent.com/csandker/RPCDump/main/CPP-RPCDump/rpc_resolve.h and https://gist.githubusercontent.com/masthoon/510dd757b21f04da47431e9d4e0a3f6e/raw/e8aac11140a36ef27423331fd3cd100ea4ecda7b/rpc_dump_rs4.txt. I could not find a better source that was accessible for a script.

    .PARAMETER EPMOnly

    Omit checking default ports, only check 135 and RPC endpoints.

    .PARAMETER VerifySSL

    By default, all port checks only validate basic reachability. If you specify this switch, the ports 636 (LDAP over SSL) and 3289 (global catalog over SSL) are also checked for the SSL protocols they accept. Valid protocols are enumerated from [Security.Authentication.SslProtocols]

    The certificate and DNS names from the remote SSL certificate are also added to the results.

    .PARAMETER SSLPorts

    If you want to check distinct ports for SSL connectivity, you can provide an array of port numbers. Without VerifySSL, this parameter has no effect. If a port listed here is not already listed in Ports, it will be added.

    If you omit this parameter, the default ports 636 and 3289 will be checked.

    .PARAMETER UseProxy

    By default, the downloads to resolve service names and RPC endpoint names use a direct internet connection. Enable this switch to use a proxy server. If required, use the -ProxyServer switch to specify the proxy to use.
    If a static proxy is configured in control panel, it will be used. If not, netsh winhttp proxy will be used. If both are undefined, no proxy will be used unless you specify one.

    .PARAMETER ProxyServer

    If you need to use a different proxy than configured in control panel or netsh winhttp, specify 'http://<name>:<port>'.

    .PARAMETER Timeout

    By default, the timeout for all ICMP and port checks is 1 seconds. You can override this timeout using this parameter. The minimum value is 1, the maximum value is 30.

    .PARAMETER MinThreads

    The script uses runspaces to execute all connectivity checks in parallel.

    This parameter specifies the mimimum Runspace Pool size. Defaults to 128, may be decreased if the computer is short on ressources. May as well be increased if you expect to check a huge number of ports overall.

    Minimum value is 16, maximum value is 1024.

    .PARAMETER MaxThreads

    The script uses runspaces to execute all connectivity checks in parallel.

    This parameter specifies the maximum Runspace Pool size. Defaults to 1024, may be decreased if the computer is short on ressources. May as well be increased if you expect to check a huge number of ports overall.

    Minimum value is 64, maximum value is 4096.

    .PARAMETER NonInteractive

    By default, the results are passed to Out-Gridview for interactive analysis. Use this switch to suppress the Gridview, if you want to automate processing of results.

    .PARAMETER PassThru

    By default, nothing is returned by this script. Add this switch if you want to retrieve the resulting array for further processing.

    .EXAMPLE

    .\Test-TcpPorts.ps1 -IncludeEPM

    Verifies the domain of the current computer against the builtin domain list. Then evaluates all IP addresses and verifies a pre defined port list against these. It also checks all dynamic RPC endpoints.

    .EXAMPLE

    'corp','tailspintoys.com' | .\Test-TcpPorts.ps1 -DNSSuffix 'contoso.com'

    Enumerates all IP Addresses for the provided names after appending the DNSSuffix 'contoso.com' to 'corp' and verifies a pre defined port list against these. Since this are domain names, they will resolve to IP addresses of all domain controllers.

    Depending on reverse resolution, it will possibly mess up the computer and domain names since we cannot know we are checking a domain (there's no flag for "I am a domain" in its DNS entry).

    .EXAMPLE

    .\Test-TcpPorts.ps1 'Computer1','Computer2' -CustomPorts 80,443 -ResolvePortNames -VerifySSL -SSLPorts 443

    Checks ports 80 and 443 on Computer1 and Computer2. Tries to resolve their names by checking etc\services. Will not reach out for IANA services and ports assignments because both ports can be resolved locally. Will also verify available SSL protocols on port 443 but not on port 80.

    .EXAMPLE

    @( [PSCustomObject]@{ Computer='Server1'; Ports=@( 135,445 ) }, [PSCustomObject]@{ Computer = 'Server2'; Ports = @( 80, 443 ) } ) | .\Test-TcpPorts.ps1

    Checks ports 135 and 445 on Server1 and ports 80 and 443 on Server2. For ports that were not checked on a computer, it shows '(n/a)' as result.

    .INPUTS

    [String[]]

    One or more computer names or IP addresses to check. If omitted, checks the domain of the current computer.

    [Object[]]

    An array of objects that have the properties required for the script. This includes at least 'computer', but can also include 'ports', 'sslports' and others.

    .OUTPUTS

    [PSCustomObject[]]

    A custom object for each computer that was checked. Each object contains the corresponding input string, the DNS name it resolved to, its IP address, and a column for each checked port.

    If SSL was checked, it contains a column for each port and protocol combination as well as a column for all DNS names in the certificate. In the raw results ($ComputerList), there's also the certificate itself present.

    .NOTES

    Credits go to Ryan Ries who wrote the initial RPC Port checker found in the Powershell Gallery at https://www.powershellgallery.com/packages/Test-RPC/1.0
    I changed .Connect to .BeginConnect, added the annotation string to the return array and converted it to a scriptblock.

    Credits go to https://stackoverflow.com/a/38729034 for how to disable server certificate validation using Invoke-WebRequest

    Credits go to http://blog.whatsupduck.net for the SSL protocol validation using [Net.Sockets.NetworkStream]

    Further credits go to lots of people helping me figuring out minor and major tweaks:
    - Use [Net.NetworkInformation.Ping] instead of Test-NetConnection to improve speed (Test-NetConnection takes 5 seconds per host)
    - Use [Net.Sockets.TCPClient] BeginConnect with AsyncWaitHandle to improve timeouts (the Connect method has a 42 second timeout)
    - Use [Net.Security.RemoteCertificateValidationCallback] to ignore certificate validation errors in the SSL port checks
    - Use Runspaces instead of Jobs to reduce memory and process footprint (Jobs run in processes where Runspaces provide threads)

#>

#Requires -Module DNSClient

[CmdletBinding( DefaultParameterSetName = 'NotEPMOnly' )]

Param(
    # the [URI]::CheckHostName() method returns 0 (undefined), 1 (basic), 2 (Dns), 3 (IPv4) or 4 (IPv6)
    # make sure the $computer parameter is neither undefined nor basic (which means "undetermined")
    [Parameter( ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 0 )]
    [ValidateScript({ [URI]::CheckHostName( $_).Value__ -gt 1 })]
    [String[]] $Computer,

    [Parameter( ValueFromPipelineByPropertyName = $true, ParameterSetName = 'NotEPMOnly' )]
    [ValidateRange( 1, 65535 )]
    [Int[]] $Ports = @( 88, 135, 389, 445, 464, 636, 3268, 3269 ),

    [Switch] $IncludeTrustedDomains,

    [Switch] $IncludeTrustingDomains,

    [Switch] $ResolvePortNames,

    [Parameter( ValueFromPipelineByPropertyName = $true, ParameterSetName = 'NotEPMOnly' )]
    [Switch] $IncludeEPM,

    [Switch] $ResolveEPM,

    [Parameter( ValueFromPipelineByPropertyName = $true, ParameterSetName = 'EPMOnly' )]
    [Switch] $EPMOnly,

    [Parameter( ValueFromPipelineByPropertyName = $true, ParameterSetName = 'NotEPMOnly' )]
    [Switch] $VerifySSL,

    [Parameter( ValueFromPipelineByPropertyName = $true, ParameterSetName = 'NotEPMOnly' )]
    [ValidateRange( 1, 65535 )]
    [Int[]] $SSLPorts = @( 636, 3269 ),

    [Parameter( ValueFromPipelineByPropertyName = $true )]
    [ValidateScript({ [URI]::CheckHostName( $_) -eq 'Dns' })]
    [String] $DNSSuffix = ( Get-ItemProperty 'HKLM:\system\CurrentControlSet\Services\tcpip\parameters' ).Domain,

    [Switch] $UseProxy,

    [ValidateScript( { [URI]::IsWellFormedUriString( $_, [UriKind]::Absolute ) } )]
    [String] $ProxyServer,

    [ValidateRange( 1, 30 )]
    [Int] $Timeout = 1,

    [ValidateRange( 16, 1024 )]
    [Int] $MinThreads = 128,

    [ValidateRange( 64, 4096 )]
    [Int] $MaxThreads = 1024,

    [Switch] $NonInteractive,
    
    [Switch] $PassThru

)

Begin {

    Import-Module -Name DnsClient -ErrorAction Stop

    If ( $UseProxy -and -not $ProxyServer ) {
        Try {
            $Proxies = ( Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' ).proxyServer
        } Catch {
            $Proxies = $null
        }
        If ( $Proxies ) {
            If ( $Proxies -like '*=*' ) {
                # means proxies specified per protocol
                # since http is the first, https the second and usually the same as http, simply pick first
                $ProxyServer = $Proxies -replace '=','://' -split ';' | Select-Object -First 1
            } else {
                # means only one proxy specified for all protocols
                $ProxyServer = 'http://' + $proxies
            }
            Write-Verbose "Using proxy server from control panel: $ProxyServer"
        } ElseIf ( & $env:WINDIR\System32\netsh.exe winhttp dump | Where-Object { $_ -match '^set proxy proxy-server="(?<Proxy>[^\s]+)"' } ) {
            # need to use netsh winhttp dump because it is language independend.
            # netsh winhttp show proxy uses localized output which is not welcome here...
            $ProxyServer = 'http://' + $Matches.Proxy
            Write-Verbose "Using proxy server from netsh winhttp: $ProxyServer"
        } Else {
            # cannot use a proxy because we don't have one...
            $UseProxy = $False
            Write-Warning 'Cannot use a proxy server - none specified on commandline and none found in control panel or netsh winhttp settings.'
        }
    }

    If ( $ResolvePortNames -or $ResolveEPM ) {
        # enable Tls1.1 and Tls1.2 if internet access is required - Powershell defaults to Tls1.0 which usually will be rejected
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
        # disable server certificate validation - otherwise we must in advance trust all root CAs that we will eventually encounter
        If ( -not ( [Management.Automation.PSTypeName] 'ServerCertificateValidationCallback' ).Type ) {
            $certCallback = @'
            using System;
            using System.Net;
            using System.Net.Security;
            using System.Security.Cryptography.X509Certificates;
            public class ServerCertificateValidationCallback
            {
                public static void Ignore()
                {
                    if(ServicePointManager.ServerCertificateValidationCallback ==null)
                    {
                        ServicePointManager.ServerCertificateValidationCallback += 
                            delegate
                            (
                                Object obj, 
                                X509Certificate certificate, 
                                X509Chain chain, 
                                SslPolicyErrors errors
                            )
                            {
                                return true;
                            };
                    }
                }
            }
'@

            Try {   
                Add-Type $certCallback
            } Catch {
            }
        }
        [ServerCertificateValidationCallback]::Ignore()
    }    


    $RpcUUIDs = @{
        "06bba54a-be05-49f9-b0a0-30f790261023" = "Windows Security Center"
        "0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53" = "Taskplaner idletask"
        "0d72a7d4-6148-11d1-b4aa-00c04fb66ea0" = "Cryptoservices ICertProtect"
        "0e4a0156-dd5d-11d2-8c2f-00c04fb6bcde" = "Microsoft Information Store"
        "1088a980-eae5-11d0-8d9b-00a02453c337" = "Message Queuing and Distributed Transaction Coordinator qm2qm"
        "10f24e8e-0fa6-11d2-a910-00c04f990f3b" = "Microsoft Information Store"
        "11220835-5b26-4d94-ae86-c3e475a809de" = "Protected storage ICryptProtect"
        "12345678-1234-abcd-ef00-0123456789ab" = "Spooler Service"
        "12345678-1234-abcd-ef00-01234567cffb" = "LSASS"
        "12345778-1234-abcd-ef00-0123456789ab" = "LSASS"
        "12345778-1234-abcd-ef00-0123456789ac" = "LSASS Protected Storage"
        "1257b580-ce2f-4109-82d6-a9459d0bf6bc" = "SessEnvPrivateRpc RpcShadow2"
        "12b81e99-f207-4a4c-85d3-77b42f76fd14" = "Secondary Logon service"
        "130ceefb-e466-11d1-b78b-00c04fa32883" = "Active Directory ISM IP Transport"
        "1453c42c-0fa6-11d2-a910-00c04f990f3b" = "Microsoft Information Store"
        "1544f5e0-613c-11d1-93df-00c04fd7bd09" = "MS Exchange Directory RFR, DSReferral"
        "16e0cf3a-a604-11d0-96b1-00a0c91ece30" = "Active Directory restore"
        "17fdd703-1827-4e34-79d4-24a55c53bb37" = "Messenger service"
        "1be617c0-31a5-11cf-a7d8-00805f48a135" = "IIS POP3"
        "1cbcad78-df0b-4934-b558-87839ea501c9" = "Active Directory DSRole"
        "1ff70682-0a51-30e8-076d-740be8cee98b" = "Taskplaner atsvc"
        "2465e9e0-a873-11d0-930b-00a0c90ab17c" = "IIS IMAP4"
        "29770a8f-829b-4158-90a2-78cd488501f7" = "SessEnvPrivateRpc TSSDFarmRpcGrantUserTSAccessRight"
        "2f59a331-bf7d-48cb-9ec5-7c090d76e8b8" = "Terminal Server Service"
        "2f5f3220-c126-1076-b549-074d078619da" = "NetDDE"
        "2f5f6520-ca46-1067-b319-00dd010662da" = "Telephony service TAPI"
        "2f5f6521-cb55-1059-b446-00df0bce31db" = "unimodem LRPC Endpoint"
        "300f3532-38cc-11d0-a3f0-0020af6b0add" = "Distributed Link Tracking Client"
        "326731e3-c1c0-4a69-ae20-7d9044a4ea5c" = "Winlogon IUserProfile"
        "338CD001-2244-31F1-AAAA-900038001003" = "WinReg"
        "342cfd40-3c6c-11ce-a893-08002b2e9c6d" = "License Logging service"
        "3473dd4d-2e88-4006-9cba-22570909dd10" = "WinHttp Auto-Proxy Service"
        "367abb81-9844-35f1-ad32-98f038001003" = "Service Control Manager"
        "369ce4f0-0fdc-11d3-bde8-00c04f8eee78" = "Winlogon Profile Mapper pmapapi"
        "378e52b0-c0a9-11cf-822d-00aa0051e40f" = "Taskplaner sasec"
        "38a94e72-a9bc-11d2-8faf-00c04fa378ff" = "MS Exchange MTA 'QAdmin'"
        "3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5" = "DHCP Client LRPC Endpoint DNSResolver"
        "3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6" = "DHCP Server dhcpcsvc6"
        "3dde7c30-165d-11d1-ab8f-00805f14db40" = "Protected storage BackupKey"
        "3f99b900-4d87-101b-99b7-aa0004007f07" = "Microsoft SQL Server ?ber RPC"
        "3faf4738-3a21-4307-b46c-fdda9bb8c0d5" = "Windows Audio audiosrv"
        "41208ee0-e970-11d1-9b9e-00e02c064c39" = "Message Queuing and Distributed Transaction Coordinator"
        "45776b01-5956-4485-9f80-f428f7d60129" = "DNS Client"
        "45f52c28-7f9f-101a-b52b-08002b2efabe" = "WINS"
        "469d6ec0-0d87-11ce-b13f-00aa003bac6c" = "MS Exchange System Attendant Public"
        "4825ea41-51e3-4c2a-8406-8f2d2698395f" = "Winlogon IProfileDialog"
        "4b112204-0e19-11d3-b42b-0000f81feb9f" = "SSDP Discovery Service service"
        "4b324fc8-1670-01d3-1278-5a47bf6ee188" = "File Server f?r Macintosh"
        "4da1c422-943d-11d1-acae-00c04fc2aa3f" = "Distributed Link Tracking Client"
        "4f82f460-0e21-11cf-909e-00805f48a135" = "IIS NNTP"
        "4fc742e0-4a10-11cf-8273-00aa004ae673" = "DFS"
        "50abc2a4-574d-40b3-9d66-ee4fd5fba076" = "DNS Server"
        "57674cd0-5200-11ce-a897-08002b2e9c6d" = "License Logging service"
        "5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc" = "Messenger service"
        "5b5b3580-b0e0-11d1-b92d-0060081e87f0" = "Message Queuing and Distributed Transaction Coordinator qmrepl"
        "5b821720-f63b-11d0-aad2-00c04fc324db" = "DHCP Server dhcpsrv2"
        "5ca4a760-ebb1-11cf-8611-00a0245420ed" = "Terminal Server winstation"
        "5cbe92cb-f4be-45c9-9fc9-33e73e557b20" = "Protected storage PasswordRecovery"
        "621dff68-3c39-4c6c-aae3-e68e2c6503ad" = "Windows Wireless Configuration"
        "629b9f66-556c-11d1-8dd2-00aa004abd5e" = "System Event Notification SENSNotify"
        "63fbe424-2029-11d1-8db8-00aa004abd5e" = "System Event Notification SensApi"
        "65a93890-fab9-43a3-b2a5-1e330ac28f11" = "DNS Client"
        "68b58241-c259-4f03-a2e5-a2651dcbc930" = "Cryptoservices IKeySvc2"
        "68dcd486-669e-11d1-ab0c-00c04fc2dcd2" = "Inter-site Messaging service"
        "6bffd098-a112-3610-9833-012892020162" = "Computer Browser"
        "6bffd098-a112-3610-9833-46c3f874532d" = "DHCP Server dhcpsrv"
        "70b51430-b6ca-11d0-b9b9-00a0c922e750" = "IMSAdminBase"
        "76d12b80-3467-11d3-91ff-0090272f9ea3" = "Message Queuing and Distributed Transaction Coordinator qmcomm2"
        "7c44d7d4-31d5-424c-bd5e-2b3e1f323d22" = "Active Directory dsaop"
        "811109bf-a4e1-11d1-ab54-00a0c91e9b45" = "WINS"
        "82ad4280-036b-11cf-972c-00aa006887b0" = "InetInfo"
        "83d72bf0-0d89-11ce-b13f-00aa003bac6c" = "MS Exchange System Attendant Private"
        "83da7c00-e84f-11d2-9807-00c04f8ec850" = "Windows File Protection SFC"
        "86d35949-83c9-4044-b424-db363231fd0c" = "Taskplaner ITaskSchedulerService"
        "894de0c0-0d55-11d3-a322-00c04fa321a1" = "WinLogon InitShutdown"
        "89742ace-a9ed-11cf-9c0c-08002be7ae86" = "Exchange Server STORE ADMIN"
        "8c7daf44-b6dc-11d1-9a4c-0020af6e7c57" = "Application Management service"
        "8cfb5d70-31a4-11cf-a7d8-00805f48a135" = "IIS SMTP"
        "8d0ffe72-d252-11d0-bf8f-00c04fd9126b" = "Cryptoservices IKeySvc"
        "8f09f000-b7ed-11ce-bbd2-00001a181cad" = "Routing and Remote Access"
        "8fb6d884-2388-11d0-8c35-00c04fda2795" = "Windows Time w32time"
        "906b0ce0-c70b-1067-b317-00dd010662da" = "IPSec Policy agent"
        "91ae6020-9e3c-11cf-8d7c-00aa00c091be" = "Zertifikatsdienst"
        "93149ca2-973b-11d1-8c39-00c04fb984f9" = "Security Configuration Editor Engine"
        "95958c94-a424-4055-b62b-b7f4d5c47770" = "Winlogon IRPCSCLogon"
        "97f83d5c-1994-11d1-a90d-00c04fb960f8" = "InetInfo"
        "99e64010-b032-11d0-97a4-00c04fd6551d" = "Exchange Server STORE ADMIN"
        "9b8699ae-0e44-47b1-8e7f-86a461d7ecdc" = "DCOM Server Process Launcher"
        "9e8ee830-4459-11ce-979b-00aa005ffebe" = "MS Exchange MTA 'MTA'"
        "a002b3a0-c9b7-11d1-ae88-0080c75e4ec1" = "Winlogon GetUserToken"
        "a00c021c-2be2-11d2-b678-0000f87a8f8e" = "PerfFRS"
        "a4f1db00-ca47-1067-b31e-00dd010662da" = "Exchange Server STORE ADMIN"
        "a4f1db00-ca47-1067-b31f-00dd010662da" = "Exchange 2003 Server STORE EMSMDB"
        "a520d06e-11de-11d2-ab59-00c04fa3590c" = "InetInfo"
        "a9e69612-b80d-11d0-b9b9-00a0c922e750" = "IADMCOMSINK"
        "b12fd546-c875-4b41-97d8-950487662202" = "SessEnvPrivateRpc VHDManage"
        "c386ca3e-9061-4a72-821e-498d83be188f" = "Windows Audio Audiorpc"
        "c681d488-d850-11d0-8c52-00c04fd90f7e" = "EFS"
        "c8cb7687-e6d3-11d2-a958-00c04f682e16" = "WebClient DAV-Service WebDAV"
        "c9378ff1-16f7-11d0-a0b2-00aa0061426a" = "Protected storage IPStoreProv"
        "c9ac6db5-82b7-4e55-ae8a-e464ed7b4277" = "SessEnvPublicRpc SysNotify"
        "d049b186-814f-11d1-9a3c-00c04fc9b232" = "NtFrs API"
        "d335b8f6-cb31-11d0-b0f9-006097ba4e54" = "IPSec Policy Agent"
        "d3fbb514-0e3b-11cb-8fad-08002b1d29c3" = "NsiC"
        "d6d70ef0-0e3b-11cb-acc3-08002b1d29c3" = "RPC locator service NsiS"
        "d6d70ef0-0e3b-11cb-acc3-08002b1d29c4" = "NsiM"
        "d95afe70-a6d5-4259-822e-2c84da1ddb0d" = "WindowsShutdown"
        "e1af8308-5d1f-11c9-91a4-08002b14a0fa" = "RPC Endpoint Mapper"
        "e3514235-4b06-11d1-ab04-00c04fc2dcd2" = "MS NT Directory DRS"
        "e67ab081-9844-3521-9d32-834f038001c0" = "Client Services f?r NetWare"
        "ea0a3165-4834-11d2-a6f8-00c04fa346cc" = "Fax Service"
        "ecec0d70-a603-11d0-96b1-00a0c91ece3" = "Active Directory backup "
        "f50aac00-c7f3-428e-a022-a6b71bfb9d43" = "Cryptoservices ICatDBSvc"
        "f5cc59b4-4264-101a-8c59-08002b2f8426" = "NtFrs Service"
        "f5cc5a18-4264-101a-8c59-08002b2f8426" = "Active Directory Name Service Provider (NSP), DSProxy"
        "f5cc5a7c-4264-101a-8c59-08002b2f8426" = "Active Directory Extended Directory Service (XDS)"
        "f930c514-1215-11d3-99a5-00a0c9b61b04" = "MS Exchange System Attendant Cluster"
        "fdb3a030-065f-11d1-bb9b-00a024ea5525" = "Message Queuing and Distributed Transaction Coordinator qmcomm"
    }

    If ( ( $IncludeEPM -or $EPMOnly ) -and $ResolveEPM ) {
        Try {
            $Parms = @{
                URI = 'https://raw.githubusercontent.com/csandker/RPCDump/main/CPP-RPCDump/rpc_resolve.h'
                ErrorAction = 'Stop'
            }
            If ( $UseProxy ) {
                $Parms[ 'Proxy' ] = $ProxyServer
            }
            $OldRpcUUIDCount = $RpcUUIDs.Count
            $RawData = ( Invoke-WebRequest @Parms ).Content -split "`r`n"
            Foreach ( $Line in $RawData ) {
                If ( $Line -match '^ +\{ L"(?<GUID>.+)", L"(?<Name>.+)" \}\,$' ) {
                    $RpcGuid = $Matches.GUID
                    $RpcName = $Matches.Name
                    If ( $RpcName -match '^(?<Name>\[.+\])' ) {
                        $RpcName = $Matches.Name
                    } elseif ( $RpcName.Replace( '(', '' ).Replace( ')', '' ) -match '\\(?<Name>[a-z0-9\.]+)$' ) {
                        $RpcName = $Matches.Name
                    }
                    If ( -not $RpcUUIDs.ContainsKey( $RpcGuid ) ) {
                        $RpcUUIDs[ $RpcGuid ] = $RpcName
                    }
                }
            }
            Write-Verbose "Resolved $( $RpcUUIDs.Count - $OldRpcUUIDCount ) RPC endpoint names from githubusercontent/csandker"
        } Catch {
            Write-Warning 'Failed to download rpc resolve header file from https://raw.githubusercontent.com'
            $error[0].Exception | Select-Object -Property * | Out-String | ForEach-Object { Write-Warning $_ }
        }

        Try {
            $Parms = @{
                URI = 'https://gist.githubusercontent.com/masthoon/510dd757b21f04da47431e9d4e0a3f6e/raw/e8aac11140a36ef27423331fd3cd100ea4ecda7b/rpc_dump_rs4.txt'
                ErrorAction = 'Stop'
            }
            If ( $UseProxy ) {
                $Parms[ 'Proxy' ] = $ProxyServer
            }
            $OldRpcUUIDCount = $RpcUUIDs.Count
            $RawData = ( Invoke-WebRequest @Parms ).Content -split "`n"
            Foreach ( $Line in $RawData ) {
                If ( $Line -match '^RPC +(?<GUID>[a-f0-9-]+) +\(.+\) -- .+\\(?<File>[^\\.]+?)\.\w+' ){
                    # these entries follow the pattern: RPC <guid> (version) -- <filepath>
                    # we extract the UUID and the plain filename
                    $RpcGuid = $Matches.GUID
                    $RpcName = $Matches.File
                }
                If ( $Line -match '\s+[0] -\> (?<Announcement>\w+)' ) {
                    # This is the first function name for any given RPC UUID and the first line following the RPC interface
                    # we extract teh function name and then add it to the IDL list
                    If ( -not $RpcUUIDs.ContainsKey( $RpcGuid ) ) {
                        $RpcUUIDs[ $RpcGuid ] = "$RpcName $( $Matches.Announcement )"
                    }
                }
            }
            Write-Verbose "Resolved $( $RpcUUIDs.Count - $OldRpcUUIDCount ) RPC endpoint names from githubusercontent/masthoon"
        } Catch {
            Write-Warning 'Failed to download rpc resolve header file from https://gist.githubusercontent.com'
            $error[0].Exception | Select-Object -Property * | Out-String | ForEach-Object { Write-Warning $_ }
        }
    }

    $ScriptBlockEPM = {
        $TargetComputer = $args[0]
        $Timeout = $args[1]

        $PInvokeCode = @'
        using System;
        using System.Collections.Generic;
        using System.Runtime.InteropServices;

        public class Rpc
        {
            // I found this crud in RpcDce.h

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
            public static extern int RpcBindingFromStringBinding(string StringBinding, out IntPtr Binding);

            [DllImport("Rpcrt4.dll")]
            public static extern int RpcBindingFree(ref IntPtr Binding);

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
            public static extern int RpcMgmtEpEltInqBegin(IntPtr EpBinding,
                                                    int InquiryType, // 0x00000000 = RPC_C_EP_ALL_ELTS
                                                    int IfId,
                                                    int VersOption,
                                                    string ObjectUuid,
                                                    out IntPtr InquiryContext);

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
            public static extern int RpcMgmtEpEltInqNext(IntPtr InquiryContext,
                                                    out RPC_IF_ID IfId,
                                                    out IntPtr Binding,
                                                    out Guid ObjectUuid,
                                                    out IntPtr Annotation);

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
            public static extern int RpcBindingToStringBinding(IntPtr Binding, out IntPtr StringBinding);

            public struct RPC_IF_ID
            {
                public Guid Uuid;
                public ushort VersMajor;
                public ushort VersMinor;
            }

            // Returns a dictionary of <Uuid, port>
            public static Dictionary<int, string> QueryEPM(string host)
            {
                Dictionary<int, string> ports_and_uuids = new Dictionary<int, string>();
                int retCode = 0; // RPC_S_OK 
                                
                IntPtr bindingHandle = IntPtr.Zero;
                IntPtr inquiryContext = IntPtr.Zero;                
                IntPtr elementBindingHandle = IntPtr.Zero;
                RPC_IF_ID elementIfId;
                Guid elementUuid;
                IntPtr elementAnnotation;

                try
                {                    
                    retCode = RpcBindingFromStringBinding("ncacn_ip_tcp:" + host, out bindingHandle);
                    if (retCode != 0)
                        throw new Exception("RpcBindingFromStringBinding: " + retCode);

                    retCode = RpcMgmtEpEltInqBegin(bindingHandle, 0, 0, 0, string.Empty, out inquiryContext);
                    if (retCode != 0)
                        throw new Exception("RpcMgmtEpEltInqBegin: " + retCode);
                    
                    do
                    {
                        IntPtr bindString = IntPtr.Zero;
                        retCode = RpcMgmtEpEltInqNext (inquiryContext, out elementIfId, out elementBindingHandle, out elementUuid, out elementAnnotation);
                        if (retCode != 0)
                            if (retCode == 1772)
                                break;

                        retCode = RpcBindingToStringBinding(elementBindingHandle, out bindString);
                        if (retCode != 0)
                            throw new Exception("RpcBindingToStringBinding: " + retCode);
                            
                        string s = Marshal.PtrToStringAuto(bindString).Trim().ToLower();
                        string a = Marshal.PtrToStringAuto(elementAnnotation).Trim();
                        if(s.StartsWith("ncacn_ip_tcp:"))
                            if (ports_and_uuids.ContainsKey(int.Parse(s.Split('[')[1].Split(']')[0])) == false) ports_and_uuids.Add(int.Parse(s.Split('[')[1].Split(']')[0]), elementIfId.Uuid.ToString()+';'+a.ToString() );
                            
                        RpcBindingFree(ref elementBindingHandle);
                        
                    }
                    while (retCode != 1772); // RPC_X_NO_MORE_ENTRIES

                }
                catch(Exception ex)
                {
                    Console.WriteLine(ex);
                    return ports_and_uuids;
                }
                finally
                {
                    RpcBindingFree(ref bindingHandle);
                }
                
                return ports_and_uuids;
            }
        }
'@
        Try {
            Add-Type $PInvokeCode
        } Catch {
        }

        $EPMOpen = $False
        $Socket = [Net.Sockets.TcpClient]::new()
        Try {
            # used $Socket.Connect initially, but that has a timeout of 42 (!!!) seconds...
            $Connection = $Socket.BeginConnect( $TargetComputer, 135, $null, $null )
            $Success = $Connection.AsyncWaitHandle.WaitOne( [Timespan]::FromSeconds( $Timeout ) )
            If ( $Success ) {
                $EPMOpen = $True
            }
            $Socket.Close()
        } Catch {
            $Socket.Dispose()
        }
        $Results = [Collections.ArrayList]::new()
        If ( $EPMOpen ) {
            # Dictionary <Uuid, Port>
            $RPC_ports_and_uuids = [Rpc]::QueryEPM( $TargetComputer )
            $PortDeDup = $RPC_ports_and_uuids.Keys | Sort-Object -Unique
            Foreach ( $Port In $PortDeDup ) {
                $Result = [PSCustomObject] @{
                    Port  = $Port
                    UUID  = $RPC_ports_and_uuids[ $Port ].Split( ';' )[0]
                    Annotation = $RPC_ports_and_uuids[ $Port ].Split( ';' )[1]
                    State = 'FILTERED'
                }
                $Socket = [Net.Sockets.TcpClient]::new()
                Try {
                    # used $Socket.Connect initially, but that has a timeout of 42 (!!!) seconds...
                    $Connection = $Socket.BeginConnect( $TargetComputer, $Port, $null, $null )
                    $Success = $Connection.AsyncWaitHandle.WaitOne( [Timespan]::FromSeconds( $Timeout ) )
                    If ( $Success ) {
                        $Result.State = 'Listening'
                    }
                    $Socket.Close()
                } Catch {
                    $Socket.Dispose()
                }
                [void] $Results.Add( $Result )
            }
        }
        Return $Results
    }

    # run Test-NetConnection for each port on each computer that is reachable via ICMP
    $ScriptBlockPortCheck = { 
        $TargetComputer = $args[0]
        $Port = $args[1]
        $Timeout = $args[2]
        $Result = 'FILTERED'
        $Socket = [Net.Sockets.TcpClient]::new()
        Try {
            # used $Socket.Connect initially, but that has a timeout of 42 (!!!) seconds...
            $Connection = $Socket.BeginConnect( $TargetComputer, $Port, $null, $null )
            $Success = $Connection.AsyncWaitHandle.WaitOne( [Timespan]::FromSeconds( $Timeout ) )
            If ( $Success ) {
                $Result = 'Listening'
            }
            $Socket.Close()
        } Catch {
            $Socket.Dispose()
        }
        Return $Result
    }

    # populate our computer list with metadata (DNS name, ICMP reachability)
    # done in script block because reverse lookup takes some time if we check a lot of servers
    $ScriptBlockPrepareServerList = {
        $IPAddress = $args[0]
        $OriginalName = $args[1]
        $Timeout = $args[2]

        Try {
            $FQDNs = @(( Resolve-DnsName $IPAddress -Type PTR -ErrorAction Stop ).NameHost )
            # see if $originalname looks like a domain and we can find hostnames in that domain
            # if we find ones, pick the longest which might be the real name
            $MatchString = '^(?<ServerName>\w+)' + [Regex]::Escape( ".$OriginalName" ) + '$'
            $DomainFQDN = $OriginalName
            $ServerFQDN = $FQDNs | Where-Object { $_ -match $MatchString } | Sort-Object -Property Length | Select-Object -Last 1
            If ( -not $ServerFQDN ) {
                # see if we can find "anything" that is hierarchically below the original DNS name we received
                $DomainFQDN = '(n/a)'
                $ServerFQDN = $FQDNs | Where-Object { $_ -match [Regex]::Escape( ".$OriginalName$" ) } | Sort-Object -Property Length | Select-Object -Last 1
            }
            If ( -not $ServerFQDN ) {
                # as we got at least one NameHost from reverse lookup, let's use that...
                $ServerFQDN = $FQDNs[0]
            }
        } Catch {
            $ServerFQDN = '(DNS lookup failed)'
            $DomainFQDN = '(n/a)'
        }

        # for ICMP, used Test-NetConnection initially, which takes 5 seconds (4 pings, 1 sec pause)
        $Ping = [Net.NetworkInformation.Ping]::new()
        $Return = [PSCustomObject] @{
            Name      = [String] $ServerFQDN
            IPAddress = [String] $IPAddress
            Domain    = [String] $DomainFQDN
            ICMP      = [String] ( $Ping.Send( $IPAddress, $Timeout * 1000 ) ).Status
        }
        $Ping.Dispose()
        Return $Return
    }

    # try to connect with different SSL protocols to the target computer and port
    $ScriptBlockVerifySSL =  {
        $TargetComputer = $args[0]
        $Port = $args[1]
        $Timeout = $args[2]

        $ProtocolNames = [Security.Authentication.SslProtocols] | 
            Get-Member -Static -MemberType Property |
            Where-Object { $_.Name -notin @( 'Default', 'None' )} |
            ForEach-Object { $_.Name }

        $Results = [Collections.ArrayList]::new()
        Foreach ( $ProtocolName in $ProtocolNames ) {
            [void] $Results.Add( [PSCustomObject] @{
                    Name = $ProtocolName
                    Port = $Port
                    State = 'N/A'
                    KeyLength = $null
                    SignatureAlgorithm = $null
                    Certificate = $null
                    Computername = $TargetComputer
                    CertificateName = $null
            } )
        }

        # dummy callback which will validate all certificates despite untrusted roots or other issues...
        $ValidationCallback = [Net.Security.RemoteCertificateValidationCallback] { return $True }

        $Socket = [Net.Sockets.TcpClient]::new()
        $Connection = $Socket.BeginConnect( $TargetComputer, $Port, $null, $null )
        $Success = $Connection.AsyncWaitHandle.WaitOne( [Timespan]::FromSeconds( $Timeout ) )
        $Socket.Dispose()
        If ( $Success ) {
            Foreach ( $Protocol in $Results ) {
                Try {
                    $Socket = [Net.Sockets.Socket]::new( [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp )
                    $Socket.Connect( $TargetComputer, $Port )
                    $NetStream = [Net.Sockets.NetworkStream]::new( $Socket, $true )
                    $SslStream = [Net.Security.SslStream]::new( $NetStream, $true, $ValidationCallback )
                    $SslStream.AuthenticateAsClient( $TargetComputer,  $null, $Protocol.Name, $false )
                    $RemoteCertificate = [Security.Cryptography.X509Certificates.X509Certificate2] $SslStream.RemoteCertificate
                    $Protocol.State = 'Available'
                    $Protocol.KeyLength = $RemoteCertificate.PublicKey.Key.KeySize
                    $Protocol.SignatureAlgorithm = $RemoteCertificate.SignatureAlgorithm.FriendlyName
                    $Protocol.Certificate = $RemoteCertificate
                    If ( $Protocol.Certificate.Subject -match '^CN=(?<Computername>[\w.]+),' ) {
                        $Protocol.CertificateName = $Matches.Computername
                    }
                    $SslStream.Close()
                } Catch  {
                } Finally {
                    $Socket.Dispose()
                }
            }
        } else {
            Foreach ( $Protocol in $Results ) {
                $Protocol.State = 'FILTERED'
            }
        }
        Return $Results
    }

    # Initialize RunspacePool
    $RunspacePool = [Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool( $MinThreads, $MaxThreads )
    $RunspacePool.ThreadOptions = [Management.Automation.Runspaces.PSThreadOptions]::Default
    $RunspacePool.ApartmentState = [Threading.ApartmentState]::MTA
    $RunspacePool.Open()

    # Array of column names to use in Out-Gridview
    $GlobalPortColumns = [Collections.ArrayList]::new()

    # Array to collect results in the End{} block
    $ResultList = [Collections.ArrayList]::new()
    
}

Process {

    $UnresolvedPorts = $false

    # now let's create our final portlist from Ports, IncludeEPM/EPMOnly and SSLPorts
    $PortList = [Collections.ArrayList]::new()

    If ( $EPMOnly ) {
        $Ports = @( 135 )
    } ElseIf ( $IncludeEPM ) {
        $Ports += 135
    }
    $EtcServices = Get-Content "$env:Windir\System32\Drivers\etc\services"
    Foreach ( $Port in $Ports | Select-Object -Unique ) {
        Try {
            # try to extract well known ports from etc\services. Get only first match (not interested in tcp or udp), first word.
            $PortName = ( $EtcServices | Where-Object { $_ -match "$Port/(tcp|udp)" } )[0].Split( ' ' )[0]
        } Catch {
            $PortName = '(n/a)'
            $UnresolvedPorts = $true # remember that we could not resolve all ports in etc\services
        }
        [void] $PortList.Add( [PSCustomObject] @{
                Name   = $PortName
                Number = $Port
                Status = 'N/A'
                Job    = $null
                VerifySSL = ( $VerifySSL -and $SSLPorts.Contains( $Port ) ) # enable VerifySSL if SSLPorts contains current port
                SSLJob = $null
        })
        [void] $GlobalPortColumns.Add( "$($Port)/$($PortName)" )
    }

    # if we want to verify SSL, make sure all SSLPorts are present in our PortList
    If ( $VerifySSL ) {
        Foreach ( $SSLPort in $SSLPorts | Select-Object -Unique ) {
            $PortListEntry = $Portlist | Where-Object { $_.Number -eq $SSLPort }
            If ( -not $PortListEntry ) {
                Try {
                    # try to extract well known ports from etc\services. Get only first match, first word.
                    $PortName = ( Get-Content "$env:Windir\System32\Drivers\etc\services" | Where-Object { $_ -match "$SSLPort/(tcp|udp)" } )[0].Split( ' ' )[0]
                } Catch {
                    $PortName = '(n/a)'
                    $UnresolvedPorts = $true # remember that we could not resolve all ports in etc\services
                }
                [void] $PortList.Add( [PSCustomObject] @{
                        Name   = $PortName
                        Number = $SSLPort
                        Status = 'N/A'
                        Job    = $null
                        VerifySSL = $true
                        SSLJob = $null
                })
                [void] $GlobalPortColumns.Add( "$($Port)/$($PortName)" )
            }
        }
    }

    If ( $ResolvePortNames -and $UnresolvedPorts ) {
        # only do this if we still have unresolved ports (= not available in etc/services) AND want to resolve all port names
        Try {
            $Parms = @{
                URI = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml'
                ErrorAction = 'Stop'
            }
            If ( $UseProxy ) {
                $Parms[ 'Proxy' ] = $ProxyServer
            }
            [xml] $Services = ( Invoke-WebRequest @Parms ).Content
            Foreach ( $Port in $PortList | Where-Object { $_.Name -eq '(n/a)' } ) {
                $Port.Name = $Services.registry.record | Select-Object -Property 'name', 'number', 'protocol' | Where-Object { $_.number -eq $Port.Number -and $_.protocol -eq 'tcp' } | Select-Object -ExpandProperty 'name'
                [void] $GlobalPortColumns.Add( "$($Port)/$($PortName)" )
            }
        } Catch {
            Write-Warning 'Failed to download service name and port number assignments from https://www.iana.org'
            $error[0].Exception | Select-Object -Property * | Out-String | ForEach-Object { Write-Warning $_ }
        }
    }

    # build a list of all computers we want to check
    $ComputerList = [Collections.ArrayList]::new()
        
    If ( $Computer ) {
        # got explicit computers to check - verify DNS names which can resolve to multiple IPs - what a mess with CNAME and PTR :(
        Foreach ( $c in $Computer ) {
            If ( [URI]::CheckHostName( $c ) -eq 'Dns' ) {
                If ( $c -notmatch '\.' ) { $c = "$c.$DNSSuffix" }
                Try {
                    $DNSEntries = @( Resolve-DnsName $c -Type A -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } )
                } Catch {
                    Write-Warning "Could not resolve host $c - host will not be checked!"
                    $DNSEntries = @()
                }
                Foreach ( $DNSEntry in $DNSEntries ) {
                    [void] $ComputerList.Add( [PSCustomObject] @{
                            OriginalName = $c
                            IPAddress   = [String] $DNSEntry.IPAddress
                            Domain      = $null
                    } )
                }
            } Else {
                [void] $ComputerList.Add( [PSCustomObject] @{
                        OriginalName = $c
                        IPAddress   = [String] $c
                        Domain      = $null
                } )
            }
        }
    } Else {
        # explicit computers omitted, so let's verify the computer domain itself.
        $DomainList = [Collections.ArrayList]::new()
        [void] $DomainList.Add( [DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name )
        If ( $IncludeTrustedDomains -or $IncludeTrustingDomains ) {
            $ADSearcher = [adsisearcher]::new()
            $ADSearcher.SearchRoot = [adsi]::new( "LDAP://$( $DomainList[0] )" )
            $ADSearcher.Filter = '(objectClass=trustedDomain)'
            $AllTrusts = $ADSearcher.FindAll() | Select-Object -ExpandProperty Properties
            Foreach ( $Trust in $AllTrusts | Where-Object { $IncludeTrustedDomains -and $_.trustdirection[0] -ne [DirectoryServices.ActiveDirectory.TrustDirection]::Inbound } ) {
                # all outbound and bidi trusts - .name is a property value collection, so pick first entry
                [void] $DomainList.Add( $Trust.name[0] )
            }
            Foreach ( $Trust in $AllTrusts | Where-Object { $IncludeTrustingDomains -and $_.trustdirection[0] -ne [DirectoryServices.ActiveDirectory.TrustDirection]::Outbound } ) {
                # all inbound and bidi trusts
                [void] $DomainList.Add( $Trust.name[0] )
            }
        }
        # Select -unique to remove duplicate bidi trusts
        Foreach ( $Domain in $DomainList | Select-Object -Unique ) {
            # if the domain does not contain a '.' (aka "is not an FQDN"), append common DNSSuffix
            # need [string] - for unknown reasons, $DomainFQDN is an array otherwise
            If ( $Domain -match '\.' ) { [String] $DomainFQDN = $Domain } Else { [String] $DomainFQDN = "$Domain.$DNSSuffix" }
            Try {
                $DNSEntries = @( Resolve-DnsName $DomainFQDN -Type A -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'A' } )
            } Catch {
                Write-Warning "Failed to resolve domain $DomainFQDN - domain will not be checked!"
                $DNSEntries = @()
            }
            Foreach ( $DNSEntry in $DNSEntries ) {
                [void] $ComputerList.Add( [PSCustomObject] @{
                        OriginalName = $Domain
                        IPAddress   = [String] $DNSEntry.IPAddress
                        Domain      = $Domain
                } )
            }
        }
    }
    Write-Verbose 'Inital list of computers:'
    $ComputerList | Select-Object -Property 'OriginalName', 'IPAddress' | Out-String | Write-Verbose

    Function New-RunspaceJob {
        [CmdletBinding()]
        Param(
            [Management.Automation.Runspaces.RunspacePool] $Pool,
            [String] $ScriptBlock,
            [Array] $Arguments
        )
        $Job = [PSCustomObject] @{ Powershell = $null; AsyncResult = $null }
        $Job.Powershell = [Powershell]::Create().AddScript( $ScriptBlock )
        Foreach ( $Argument in $Arguments ) {
            [void] $Job.Powershell.AddArgument( $Argument )
        }
        $Job.Powershell.RunspacePool = $Pool
        $Job.AsyncResult = $Job.Powershell.BeginInvoke()
        Return $Job
    }

    Write-Output "Initiating ICMP connection test for $( $ComputerList.Count ) computers."

    Foreach ( $Hostentry in $ComputerList ) {
        # add required properties to the computer object
        $HostEntry | Add-Member -NotePropertyMembers @{
            Name    = $null
            ICMP    = $null
            ICMPJob = $null
            Ports   = [Array] $Portlist | ForEach-Object { $_.PSObject.Copy() }
            EPMJob  = $null
        }
        Write-Verbose "Initiation ICMP connection test for $( $Hostentry.IPAddress )"
        $ArgumentList = @( $HostEntry.IPAddress, $HostEntry.OriginalName, $Timeout )
        $HostEntry.ICMPJob = New-RunspaceJob -Pool $RunspacePool -ScriptBlock $ScriptBlockPrepareServerList -Arguments $ArgumentList
    }

    Write-Output 'Collecting ICMP connection test result for all computers.'

    Foreach ( $HostEntry in $ComputerList ) {
        Write-Verbose "Collecting ICMP connection test result for $( $HostEntry.IPAddress )"
        $Result = $HostEntry.ICMPJob.Powershell.EndInvoke( $HostEntry.ICMPJob.AsyncResult )
        $HostEntry.Name = [String] $Result.Name
        $HostEntry.ICMP = [String] $Result.ICMP
        If ( -not $HostEntry.Domain ) { $HostEntry.Domain = [String] $Result.Domain }
    }

    Write-Verbose 'Prepared list of computers:'
    $ComputerList | Select-Object -Property 'OriginalName', 'Name', 'IPAddress', 'ICMP' | Out-String | Write-Verbose

    Write-Output "Detaching port connection test for $( $ComputerList.Count ) computers."
    $JobsTotal = 0

    Foreach ( $HostEntry in $ComputerList ) {
        If ( $HostEntry.ICMP -eq 'Success' ) {
            Write-Verbose ( 'Initiating connection test for computer {0}/{1} in domain {2}' -f $HostEntry.Name, $HostEntry.IPAddress, $HostEntry.Domain )
            Foreach ( $Port in $HostEntry.Ports ) {
                Write-Verbose ( 'Detaching port query {0}/{1}' -f $Port.Name, $Port.Number )
                $ArgumentList = @( $HostEntry.IPAddress, $Port.Number, $Timeout )
                $Port.Job = New-RunspaceJob -Pool $RunspacePool -ScriptBlock $ScriptBlockPortCheck -Arguments $ArgumentList
                $JobsTotal += 1
                If ( $VerifySSL -and $Port.VerifySSL ) {
                    Write-Verbose ( 'Detaching SSL verification {0}/{1}' -f $Port.Name, $Port.Number )
                    # since we are dealing with certificates, we need to provide a name and not an IP address only
                    # (with IP addresses, certificate validation will always fail)
                    If ( $HostEntry.Name -ne '(DNS Lookup failed)' ) {
                        $ServerName = $HostEntry.Name
                    } Else {
                        # if we have no computername, we must fallback to IPAddress - DomainName is quite useless
                        # because it will always resolve round robin to multiple Addresses
                        $ServerName = $HostEntry.IPAddress
                    }
                    $ArgumentList = @( $ServerName, $Port.Number, $Timeout )
                    $Port.SSLJob = New-RunspaceJob -Pool $RunspacePool -ScriptBlock $ScriptBlockVerifySSL -Arguments $ArgumentList
                    $JobsTotal += 1
                }
            }
            If ( $IncludeEPM -or $EPMOnly ) {
                Write-Verbose 'Detaching EPM query'
                $ArgumentList = @( $HostEntry.IPAddress, $Timeout )
                $HostEntry.EPMJob = New-RunspaceJob -Pool $RunspacePool -ScriptBlock $ScriptBlockEPM -Arguments $ArgumentList
                $JobsTotal += 1
            }
            Write-Verbose ( 'Detached all jobs for computer {0}/{1} in domain {2}.' -f $HostEntry.Name, $HostEntry.IPAddress, $HostEntry.Domain )
        } Else {
            Write-Warning ( 'Skipping connection tests for computer {0}/{1} in domain {2} - ICMP unreachable.' -f $HostEntry.Name, $HostEntry.IPAddress, $HostEntry.Domain )
        }
    }

    Write-Output "Detached $JobsTotal background jobs successfully."
    Write-Output "Collecting port connection test result for $( $ComputerList.Count ) computers."

    Foreach ( $HostEntry in $ComputerList ) {
        Write-Output ( 'Collecting results for computer {0}/{1} in domain {2}' -f $HostEntry.Name, $HostEntry.IPAddress, $HostEntry.Domain )
        Foreach ( $Port in $HostEntry.Ports | Where-Object { $_.Job }) {
            Write-Verbose ( 'Receiving port results for {0}/{1}' -f $Port.Name, $Port.Number )
            $Port.Status = $Port.Job.Powershell.EndInvoke( $Port.Job.AsyncResult )[0]
            $HostEntry | Add-Member -NotePropertyMembers @{
                 "$( $Port.Number )/$( $Port.Name )" = $Port.Status 
            } -Force
        }
        Foreach ( $Port in $HostEntry.Ports | Where-Object { $_.SSLJob }) {
            Write-Verbose ( 'Receiving SSL results for {0}/{1}' -f $Port.Name, $Port.Number )
            $Certificate = $null
            Foreach ( $SSLProtocol in ( $Port.SSLJob.Powershell.EndInvoke( $Port.SSLJob.AsyncResult ) | Sort-Object -Property Name )) {
                # $SSLProtocol | Format-Table -AutoSize | Out-String -Width 300
                $HostEntry | Add-Member -NotePropertyMembers @{
                     "$( $SSLProtocol.Port )/$( $SSLProtocol.Name )" = $SSLProtocol.State 
                } -Force
                # if we did SSL checks we have the computer name in the cert subject. If DNS lookup failed for whatever reason,
                # we can now use the cert name instead of '(DNS Lookup failed)'
                If ( $HostEntry.Name -eq '(DNS Lookup failed)' -and $SSLProtocol.CertificateName ) {
                    $HostEntry.Name = '(Cert) ' + $SSLProtocol.CertificateName.ToUpper()
                }
                If ( $SSLProtocol.Certificate ) {
                    $Certificate = $SSLProtocol.Certificate
                }
            }
            If ( $Certificate ) {
                # add certificate and all certificate DNS names to output
                $HostEntry | Add-Member -NotePropertyMembers @{
                    'CertNames' = ( $Certificate.DNSNameList.UniCode -join "`r`n" )
                    'Certificate' = $Certificate
                } -Force
            }
        }
        If ( $HostEntry.EPMJob ) {
            Write-Verbose 'Receiving EPM results'
            Foreach ( $EpmEndPoint in ( $HostEntry.EPMJob.Powershell.EndInvoke( $HostEntry.EPMJob.AsyncResult ))) {
                If ( $EpmEndPoint.Annotation -and $EpmEndPoint.Annotation -ne 'Impl friendly name' ) {
                    $EndpointName = $EpmEndPoint.Annotation
                } elseif ( $RpcUUIDs.ContainsKey( $EpmEndPoint.UUID )) {
                    $EndpointName = $RpcUUIDs[ $EpmEndPoint.UUID]
                } else {
                    $EndpointName = $EpmEndPoint.UUID
                }
                $HostEntry | Add-Member -NotePropertyMembers @{
                    $EndpointName = "$( $EpmEndPoint.Port ):$( $EpmEndPoint.State )" 
                } -Force
                [void] $GlobalPortColumns.Add( $EndpointName )
            }
        }
        [void] $ResultList.Add( $HostEntry )

    }
    
    Write-Output 'Collected all job results.'

}

End {

    $RunspacePool.Close()
    $RunspacePool.Dispose()
    
    # If we received an array of input objects from the pipeline, we might end up with results that were checked for different ports.
    # Out-Gridview will not work well with objects that have different properties, so we need to fix all objects to have the same properties.

    # cleanup $GlobalPortColumns, may contain duplicates
    $GlobalPortColumns = $GlobalPortColumns | Select-Object -Unique

    Foreach ( $Result in $ResultList ) {
        Foreach ( $GlobalPort in $GlobalPortColumns ) {
            Try {
                $Result | Add-Member -NotePropertyName $GlobalPort -NotePropertyValue '(n/a)' -ErrorAction SilentlyContinue
            } Catch {
            }
        }
    }
    
    # Output to gridview after removing the Ports and EPM property
    If ( -not $NonInteractive ) {
        $ResultList | Select-Object -Property * -ExcludeProperty 'Ports', 'ICMPJob', 'EPMJob', 'Certificate' | Out-GridView -Title "Connection test results - source computer: $env:Computername"
    }
    
    If ( $PassThru ) {
        $ResultList | Select-Object -Property * -ExcludeProperty 'Ports', 'ICMPJob', 'EPMJob' 
    }

}
