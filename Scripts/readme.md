# Test-TcpPorts

Script to check a whole bunch of tcp ports on a whole bunch of computers in parallel. Compared to Test-Netconnection it is faster than light :-)
And it also provides RPC and SSL checks.

Credits go to Ryan Ries who wrote the initial RPC Port checker found in the Powershell Gallery at https://www.powershellgallery.com/packages/Test-RPC/1.0
I changed .Connect to .BeginConnect, added the annotation string to the return array and converted it to a scriptblock.

Credits go to https://stackoverflow.com/a/38729034 for how to disable server certificate validation using Invoke-WebRequest

Credits go to http://blog.whatsupduck.net for the SSL protocol validation using [Net.Sockets.NetworkStream]

Further credits go to lots of people helping me figuring out minor and major tweaks:
- Use [Net.NetworkInformation.Ping] instead of Test-NetConnection to improve speed (Test-NetConnection takes 5 seconds per host)
- Use [Net.Sockets.TCPClient] BeginConnect with AsyncWaitHandle to improve timeouts (the Connect method has a 42 second timeout)
- Use [Net.Security.RemoteCertificateValidationCallback] to ignore certificate validation errors in the SSL port checks
- Use Runspaces instead of Jobs to reduce memory and process footprint (Jobs run in processes where Runspaces provide threads)

### Synopsis
Checks a list of well known ports that are required for Active Directory to work properly. Computers to test are derived from DNS resolution.

Alternatively checks a list of custom ports against single or multiple computers, including RPC and SSL checks.
### Description
Often logon issues occur which are hard to track down, or spurious connectivity errors to domain controllers. This script evaluates all DCs in an environment. Then it queries defined ports against each DC, optionally including dynamic RPC endpoints and verifying SSL connectivity.

This basic check ensures that at least no firewalls or stale DNS records are causing issues. All port checks are executed in parallel which greatly improves total processing time.

Without any parameters, it evaluates the domain of the current computer. This domain is resolved through DNS lookup, and all IP addresses are checked for a predefined list of ports (88/135/389/445/464/636/3268/3269).

The results are collected in an array of [PSCustomObject]. This array is piped to Out-Gridview for quick convenient analysis as well as to the clipboard for copy/paste to different targets. If you want to reuse the results, dot-source the script and grab $ComputerList.

The columns of the result are mostly self explaining. Since we do a lot of DNS resolution which for cnames can "change" the computername, the original value that led us to each IP Address is also preserved in the results.

The need for this script initially originated from complex domain environments with lots of trusts and infrastructure firewalls. Hence it has a builtin list of ports that we assume to be required for proper active directory communication to domain controllers.

### Syntax
```powershell
Test-TcpPorts.ps1 [[-Computer] <string[]>] [-DNSSuffix <string>] [-IncludeTrustedDomains] [-IncludeTrustingDomains] [-Ports <int[]>] [-ResolvePortNames] [-IncludeEPM] [-ResolveEPM] [-VerifySSL] [-SSLPorts <int[]>] [-UseProxy] [-ProxyServer <string>] [-Timeout <int>] [-MinThreads <int>] [-MaxThreads <int>] [<CommonParameters>]
Test-TcpPorts.ps1 [[-Computer] <string[]>] [-DNSSuffix <string>] [-IncludeTrustedDomains] [-IncludeTrustingDomains] [-ResolvePortNames] [-ResolveEPM] [-EPMOnly] [-UseProxy] [-ProxyServer <string>] [-Timeout <int>] [-MinThreads <int>] [-MaxThreads <int>] [<CommonParameters>]
```
### Parameters
#### Computer &lt;String[]&gt;
    Specify a list of computers (names or IP addresses) to check. Can also be a domain name which will resolve to multiple addresses. If you omit this parameter, the domain of the current computer is resolved in DNS and all resulting IP addresses are checked.
    
    If you specify a plain host name (no DNS suffix), the global DNSSuffix is appended (see below). FQDNs and IP addresses are used as provided.
    
    If you specify a domain name here, it will slightly mess the output, especially computer names. We don&#39;t know that you provided a domain and  DNS also does not tell us that it is a domain. When we start reverse resolution for the IP addresses and there are multiple PTR records (or these PTR records resolve to names that themselves resolve to multiple host names), we are unable to extract a domain name or determine which A record is the real computername.
    
    Erforderlich?                false
    Position?                    1
    Standardwert                 
    Pipelineeingaben akzeptieren?true (ByValue)
    Platzhalterzeichen akzeptieren?false

#### PARAMETER SourceComputer &lt;String[]&gt;

        Specify a list of computers (names, NOT IP addresses) to execute the checks from (requires Powershell remoting working through PSSession). Can NOT be a domain name or an IP address because WSMAN Authentication does not work with IP addresses.
        
        If you omit this parameter, all checks are ran from the local computer.

        If you specify a plain host name (no DNS suffix), the global DNSSuffix is appended (see below)

    Erforderlich?                false
    Position?                    named
    Standardwert
    Pipelineeingaben akzeptieren?true (ByValue)
    Platzhalterzeichen akzeptieren?false

#### DNSSuffix &lt;String&gt;
    For computers/DNS names with FQDN and for IP addresses, this parameter is ignored. All Netbios names (aka strings without dots in them) are padded with this DNS suffix. Makes things easier if you run the script interactively from a prompt :)
    
    If not specified, the primary dns suffix of the local computer will be used as DNSSuffix.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 ( Get-ItemProperty &#39;HKLM:\system\CurrentControlSet\Services\tcpip\parameters&#39; ).Domain
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### IncludeTrustedDomains [&lt;SwitchParameter&gt;]
    If you do not specify computers to check, the domain of the current computer is verified. If you specify this switch, all domains that the current computer&#39;s domain is trusting will be also checked.
    
    If you specified one or more computers, this switch is ignored.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### IncludeTrustingDomains [&lt;SwitchParameter&gt;]
    If you do not specify computers to check, all domain controllers of the domain of the current computer are verified. If you specify this switch, all domains that trust the current computer&#39;s domain will be also checked.
    
    If you specified one or more computers, this switch is ignored.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### Ports &lt;Int32[]&gt;
    By default, a predefined list of ports is checked (88/135/389/445/464/636/3268/3269). If you want to check a custom port range, provide a comma separated list of port numbers to check. You can specify port numbers in a range from 1 to 65535. All port numbers are by default resolved against etc/services.
    
    If you need a different set of ports to be checked by default, edit the script and modify the Ports parameter array to your needs.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 @( 88, 135, 389, 445, 464, 636, 3268, 3269 )
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### ResolvePortNames [&lt;SwitchParameter&gt;]
    If you provide a custom port list and some of these cannot be resolved to their well known service name via etc\services, the script will download the current list of all defined services from IANA and resolve the ports to their names.
    
    Note: The list of well known ports is downloaded directly from IANA - https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
    Since this list contains more than 14.000 entries, this may take a while (4 MB). And of course this only works if you have internet connectivity.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### IncludeEPM [&lt;SwitchParameter&gt;]
    Add this switch to query all dynamic RPC ports from the RPC endpoint mapper. This of course only works if EPM itself (TCP/135) is reachable. If you add this switch, EPM itself will be added to the list of ports to check if it is missing.
    
    This comes in extremely handy if you have systems with different RPC port ranges combined with infrastructure firewalls, like we do. Some of them are in the 5000 range, some in the 9000 range and some in the default range of 49152-65535. So we are required to not only know that we need RPC, but also  which RPC range our target computer uses.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### ResolveEPM [&lt;SwitchParameter&gt;]
    By default, all enumerated EPM ports will only be listed with their annotation or (if missing - not all endpoints have an annotation) their interface UUID. Some of the frequent endpoints are resolved with a static list that is hardcoded into the script.
    
    Usually unresolved GUIDs can be found through a web search. If you specify this switch, EPM port UUIDs will be checked against two lists found at https://raw.githubusercontent.com/csandker/RPCDump/main/CPP-RPCDump/rpc_resolve.h and https://gist.githubusercontent.com/masthoon/510dd757b21f04da47431e9d4e0a3f6e/raw/e8aac11140a36ef27423331fd3cd100ea4ecda7b/rpc_dump_rs4.txt. I could not find a better source that was accessible for a script.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### EPMOnly [&lt;SwitchParameter&gt;]
    Omit checking  default ports, only check 135 and RPC endpoints.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### VerifySSL [&lt;SwitchParameter&gt;]
    By default, all port checks only validate basic reachability. If you specify this switch, the ports 636 (LDAP over SSL) and 3289 (global catalog over SSL) are also checked for the SSL protocols they accept. Valid protocols are enumerated from [Security.Authentication.SslProtocols]
    
    The certificate and DNS names from the remote SSL certificate are also added to the results.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### SSLPorts &lt;Int32[]&gt;
    If you want to check distinct ports for SSL connectivity, you can provide an array of port numbers. Without VerifySSL, this parameter has no effect. If a port listet here is not already listet in Ports, it will be added.
    
    If you omit this parameter, the default ports 636 and 3289 will be checked.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 @( 636, 3269 )
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### UseProxy [&lt;SwitchParameter&gt;]
    By default, the downloads to resolve service names and RPC endpoint names use a direct internet connection. Enable this switch to use a proxy server. If required, use the -ProxyServer switch to specify the proxy to use.
    If a static proxy is configured in control panel, it will be used. If not, netsh winhttp proxy will be used. If both are undefined, no proxy will be used unless you specify one.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### ProxyServer &lt;String&gt;
    If you need to use a different proxy than configured in control panel or netsh winhttp, specify &#39;http://&lt;name&gt;:&lt;port&gt;&#39;.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### Timeout &lt;Int32&gt;
    By default, the timeout for all port checks in the used methods is 1 seconds. You can override this timeout using this parameter. The minimum value is 1, the maximum value is 30.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 1
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### MinThreads &lt;Int32&gt;
    Specifies the mimimum Runspace Pool size. Defaults to 128, may be decreased if the computer is short on ressources. May as well be increased if you expect to check a huge number of ports overall.
    
    Minimum value is 16, maximum value is 1024.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 128
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### MaxThreads &lt;Int32&gt;
    Specifies the maximum Runspace Pool size. Defaults to 1024, may be decreased if the computer is short on ressources. May as well be increased if you expect to check a huge number of ports overall.
    
    Minimum value is 64, maximum value is 4096.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 1024
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
### Examples
#### BEISPIEL 1 
```powershell
.\Test-TcpPorts.ps1 -IncludeEPM

```

Verifies the domain of the current computer against the builtin domain list. Then evaluates all IP addresses and verifies a pre defined port list against these. It also checks all dynamic RPC endpoints.
#### BEISPIEL 2 
```powershell
'corp','tailspintoys.com' | .\Test-TcpPorts.ps1 -DNSSuffix 'contoso.com'

```

Enumerates all IP Addresses for the provided names after appending the DNSSuffix 'contoso.com' to 'corp' and verifies a pre defined port list against these. Since this are domain names, they will resolve to IP addresses of all domain controllers.

Depending on reverse resolution, it will possibly mess up the computer and domain names since we cannot know we are checking a domain (there's no flag for "I am a domain" in its DNS entry).
#### BEISPIEL 3 
```powershell
.\Test-TcpPorts.ps1 'Computer1','Computer2' -CustomPorts 80,443 -ResolvePortNames -VerifySSL -SSLPorts 443

```

Checks ports 80 and 443 on Computer1 and Computer2. Tries to resolve their names by checking etc\services. Will not reach out for IANA services and ports assignments because both ports can be resolved locally. Will also verify available SSL protocols on port 443 but not on port 80.
<div style='font-size:small; color: #ccc'>Generated 12-05-2022 16:13</div>

# Invoke-SysvolD4Restore

Script to perform an authoritative Sysvol restore (aka D4) in a domain using DFSR for sysvol replication. Doing this by hand is quite time consuming if you have a large number of domain controllers...

### SYNOPSIS

The script performs all the steps Microsoft describes in https://learn.microsoft.com/de-de/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization

It supports Whatif, so you can look what it would do.

### PARAMETERS
#### TargetDomain &lt;String&gt;
    The domain where DFSR should be reset.
    
    If not specified, the primary dns suffix of the local computer will be used as DNSSuffix.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 Get-ADDomain -Current LocalComputer
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### DfsrSleep &lt;Int&gt;
    The time to wait for DFSR events after PollAD
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 10
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false

### EXAMPLES
#### BEISPIEL 1
```powershell
.\Invoke-SysvolD4Restore.ps1 -Verbose
Processing domain corp.contoso.com - found domain controllers:

HostName             IsPDC
--------             -----
DC2.corp.contoso.com  True
DC1.corp.contoso.com False



Step 0: Checking prerequisites - DFSR management tools must be enabled on all DCs
VERBOSE: Checking feature states on DC2.corp.contoso.com...
VERBOSE: Checking feature states on DC1.corp.contoso.com...
Step 1: Set dfsr to manual mode and stop on all DCs
VERBOSE: 
MachineName          DisplayName      Status StartType
-----------          -----------      ------ ---------
DC2.corp.contoso.com DFS Replication Stopped Automatic
DC1.corp.contoso.com DFS Replication Stopped Automatic



VERBOSE: 
MachineName          DisplayName      Status StartType
-----------          -----------      ------ ---------
DC2.corp.contoso.com DFS Replication Stopped    Manual
DC1.corp.contoso.com DFS Replication Stopped    Manual



Step 2: Set PDC to authoritative (msDFSR-Options=1)
VERBOSE: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC2,OU=Domain Controllers,DC=corp,DC=contoso,DC=com
Step 3: Disable Sysvol replication
VERBOSE: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC2,OU=Domain Controllers,DC=corp,DC=contoso,DC=com
VERBOSE: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC1,OU=Domain Controllers,DC=corp,DC=contoso,DC=com
Step 4: Replicate AD objects from PDC to all other DCs
VERBOSE: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC2,OU=Domain Controllers,DC=corp,DC=contoso,DC=com
VERBOSE: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC1,OU=Domain Controllers,DC=corp,DC=contoso,DC=com
Step 5: Start dfsr on authoritative PDC
VERBOSE: 
MachineName          DisplayName      Status StartType
-----------          -----------      ------ ---------
DC2.corp.contoso.com DFS Replication Running    Manual



Step 6: Check for event 4114 in DFSR event log on PDC
VERBOSE: Performing the operation "Wait for DFSR event 4114" on target "DC2.corp.contoso.com".
Step 7: Set msDFSR-Enabled=TRUE on PDC
VERBOSE: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC2,OU=Domain Controllers,DC=corp,DC=contoso,DC=com
Step 8: Replicate from PDC to all other DCs
VERBOSE: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC2,OU=Domain Controllers,DC=corp,DC=contoso,DC=com
Step 9: Poll AD on PDC
VERBOSE: Successfully updated the DFSR Active Directory Domain Service configuration on the computer named DC2.corp.
contoso.com
Step 10: Check for event 4602 in DFSR event log on PDC
VERBOSE: Performing the operation "Wait for DFSR event 4602" on target "DC2.corp.contoso.com".
Step 11: start dfsr on all other DCs
VERBOSE: 
MachineName          DisplayName      Status StartType
-----------          -----------      ------ ---------
DC1.corp.contoso.com DFS Replication Running    Manual



Sleeping 5 seconds to allow dfsr to initialize properly...
Step 12: Set msDFSR-Enabled=TRUE on all other DCs and replicate to all DCs
VERBOSE: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC1,OU=Domain Controllers,DC=corp,DC=contoso,DC=com
Step 13: Poll AD on all other DCs
VERBOSE: Successfully updated the DFSR Active Directory Domain Service configuration on the computer named DC1.corp.
contoso.com
Step 14: Set dfsr to automatic on all DCs
VERBOSE: 
MachineName          DisplayName      Status StartType
-----------          -----------      ------ ---------
DC2.corp.contoso.com DFS Replication Running Automatic
DC1.corp.contoso.com DFS Replication Running Automatic
```
