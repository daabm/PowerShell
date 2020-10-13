# CopyGPOLinks

<a name="Copy-GPOLinks"></a>
## Copy-GPOLinks
### Synopsis
Copies the GPLink attribute from a specified source OU to a target OU in the same domain. Optionally appends or prepends to existing GPO links and recurses through child OUs.
### Description
When staging environments in a single AD, it is common to create a new identical OU structure for testing purposes. This structure should match the original one, including all child OUs and their linked GPOs. Copy-GPOLinks copies all linked GPOs from a source OU to a target OU in a given domain. Optionally, it recurses through child OUs and copies their GPOs, too. It also can create missing target child OUs automatically.

Note: By default, Copy-GPOLinks will not produce any screen output. If you want on-screen information, run it -verbose. If you need logging, intercept output streams or pipe to a file.

### Syntax
```powershell
Copy-GPOLinks [-SourceOU] <string> [-TargetOU] <string> [-CopyMode <string>] [-Recurse] [-CreateMissingChilds] [-ProtectedFromAccidentalDeletion <bool>] [-ResolveGPONames] [-TargetDomain <string>] [-Credential <pscredential>] [-WhatIf] [-Confirm] [<CommonParameters>]
```
### Parameters
#### SourceOU &lt;String&gt;
    Distinguished name of the OU to copy the GPLink attribute from. Both SourceOU and TargetOU must belong to the same domain.
    
    Erforderlich?                true
    Position?                    2
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### TargetOU &lt;String&gt;
    Distinguished name of the OU to copy the GPLink attribute to. Regardless of the CreateMissingChild switch, this OU must already exist or the cmdlet will fail.
    
    Erforderlich?                true
    Position?                    3
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### CopyMode &lt;String&gt;
    The copy mode for GPLink: Replace (overwrite), append or prepend to existing, or None. If you append or prepend and you run the command multiple times, you will create multiple links of the same set of GPOs. Within GPMC this cannot be done (GPMC has builtin logic that prevents this), but technically it is possible and valid. The &#39;None&#39; value is useful when combined with -CreateMissingChilds and -Whatif, see the samples section for more information.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 Replace
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### Recurse [&lt;SwitchParameter&gt;]
    Process child OUs, too. The target child OU names must match the names of the respective source child OUs. Child OUs that are found in source, but not in target, are ignored and will not raise an error.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### CreateMissingChilds [&lt;SwitchParameter&gt;]
    If the recurse switch is specified and for a given source child OU no matching target child OU is found, the target child OU is created automatically. ACLs are not copied.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### ProtectedFromAccidentalDeletion &lt;Boolean&gt;
    If missing child OUs are created, this parameter specifies whether they should be protected from accidental deletion or not. The default value is $True.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 True
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### ResolveGPONames [&lt;SwitchParameter&gt;]
    By default Copy-GPOLinks operates on the GPLink attribute. This attribute only contains GPO GUIDs, so if you want to know what was copied, you&#39;ll need to look either in GPMC or resolve those GUIDs. If you specify this switch, the source GPO names will be resolved and listed in the verbose output.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### TargetDomain &lt;String&gt;
    The Domain where TargetDomain can be found. Can be a different domain or forest. Defaults to the callers domain.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 ( Get-ADDomain ).DNSRoot
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### Credential &lt;PSCredential&gt;
    If the target domain requires different credentials, a credential object can be passed in.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### WhatIf [&lt;SwitchParameter&gt;]
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### Confirm [&lt;SwitchParameter&gt;]
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
### Examples
#### BEISPIEL 1 
```powershell
Copy-GPOLinks -SourceOU 'OU=Corp,DC=Corp,DC=Contoso,DC=Com' -TargetOU 'OU=Corp-Test,DC=Corp,DC=Contoso,DC=Com'

```
This command copies all linked GPOs from OU=Corp to OU=Corp-Test.
#### BEISPIEL 2 
```powershell
$VerbosePreference = 'Continue'

```
$SourceOU = 'OU=Corp,DC=Corp,DC=Contoso,DC=Com'
$TargetOU = 'OU=Corp-Test,DC=Corp,DC=Contoso,DC=Com'
Copy-GPOLinks -SourceOU $SourceOU -TargetOU $TargetOU -CopyMode Replace -Recurse -CreateMissingChilds -Whatif

This command recursively travels down OU=Corp. It would copy all GPOs linked, and it would create all missing OUs. Due to -WhatIf, for missing OUs it will write out that it would create them. But it will not write out that it would copy their GPOs, because copying is a different step. Since the target OU was not really created, the copy function will exit silently.
#### BEISPIEL 3 
```powershell
Copy-GPOLinks -SourceOU 'OU=Corp,DC=Corp,DC=Contoso,DC=Com' -TargetOU 'OU=Corp-Test,DC=Corp,DC=Contoso,DC=Com' -CreateMissingChilds -Recurse -CopyMode None

```
This Command works almost the same as above. But due to not trying to copy the GPLink attribute, it will only create some missing OUs. This can then be used with the next example.
#### BEISPIEL 4 
```powershell
Copy-GPOLinks -SourceOU 'OU=Corp,DC=Corp,DC=Contoso,DC=Com' -TargetOU 'OU=Corp-Test,DC=Corp,DC=Contoso,DC=Com' -Recurse -WhatIf

```
This again works almost the same as example #2 above. But if you first ran example #3, now all OUs are present and -WhatIf will be able to fully show what GPLinks it would copy.
<div style='font-size:small; color: #ccc'>Generated 13-10-2020 13:18</div>
