
NAME
    Add-GPLink
    
SYNOPSIS
    Links a new GPO to all OUs where a given GPO is already linked. Optionally removes the given GPO. Does not process GPOs linked to sites or the domain itself.
    
    
SYNTAX
    Add-GPLink [[-TargetDomain] <String>] [-SearchBase <String>] [-OUFilter <String>] [-RegexEscape] [-RelativeLinkPos <String>] [-Enforced {Unspecified | No | Yes}] [-LinkEnabled {Unspecified | 
    No | Yes}] [-WhatIf] [-Confirm] [<CommonParameters>]
    
    Add-GPLink [[-TargetDomain] <String>] [-SearchBase <String>] [-OUFilter <String>] [-RegexEscape] [-ReplaceLink] [-Enforced {Unspecified | No | Yes}] [-LinkEnabled {Unspecified | No | Yes}] 
    [-WhatIf] [-Confirm] [<CommonParameters>]
    
    Add-GPLink [[-TargetDomain] <String>] [-SearchBase <String>] [-OUFilter <String>] [-RegexEscape] [-LinkOrder <Int32>] [-Enforced {Unspecified | No | Yes}] [-LinkEnabled {Unspecified | No | 
    Yes}] [-WhatIf] [-Confirm] [<CommonParameters>]
    
    Add-GPLink [[-TargetDomain] <String>] [-SearchBase <String>] [-OUFilter <String>] [-RegexEscape] [-RemoveLink] [-WhatIf] [-Confirm] [<CommonParameters>]
    
    
DESCRIPTION
    Sometimes, new GPOs need to be deployed everywhere a given GPO is already in use. Or a given GPO needs to be replaced globally after testing.
    
    The Append-GPLink function takes a reference GPO and a new GPO (both must already exist). Then it enumerates the OUs where the reference GPO is linked. It then links the new GPO to these OUs 
    (bottom most link order by default). Link order and link properties can be modified.
    
    DYNAMIC PARAMETERS
    
    -ReferenceGPO <String>
        The GPO that serves as a reference. The OUs this GPO is linked to are enumerated and updated.
        Tab completion searches the list of GPOs in TargetDomain.
    
        Required?                    true
        Position?                    2
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
    
    -NewGPO <String>
        The GPO that will be linked to the OUs where ReferenceGPO is linked.
        This parameter is required if -RemoveLink is not specified.
        Tab completion searches the list of GPOs in TargetDomain.
    
        Required?                    true
        Position?                    3
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
    

PARAMETERS
    -TargetDomain <String>
        The domain where the actions should be performed. Defaults to the domain of the currently logged on user.
        
        Required?                    false
        Position?                    1
        Default value                $env:USERDNSDOMAIN
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -SearchBase <String>
        Use this distinguished name to limit the search for OUs where ReferenceGPO is linked to a specific searchbase. Since the domain is already defined, omit the domain from the searchbase 
        (do not include the DC=... parts)
        
        Required?                    false
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -OUFilter <String>
        By default, all OUs are processed where the ReferenceGPO is linked. Use this parameter to restrict the OUs to process. The filter is evaluated as a regular expression match against the 
        distinguished name of the OUs where the ReferenceGPO is linked.
        Filtering would be smarter if done via LDAPFilter, but there's no possibility to escape LDAP filters like it can be done with [Regex]::Escape for regular expressions.
        
        Required?                    false
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -RegexEscape [<SwitchParameter>]
        By default, the OUFilter will be used literally in a regex match. This means if you want to search for special characters like \ or *, you must escape them properly. Use this switch to 
        let the cmdlet escape your filter string.
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -RelativeLinkPos <String>
        By default, NewGPO will be appended at the bottom of the linked GPOs. With RelativeLinkPos, you can specify whether NewGPO should be inserted directly above or below ReferenceGPO. Valid 
        options are "before" and "after".
        
        Required?                    false
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -ReplaceLink [<SwitchParameter>]
        Specify this switch if you want to remove the link to ReferenceGPO, leaving only the NewGPO link active. NewGPO will be linked at the position where ReferenceGPO was linked.
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -LinkOrder <Int32>
        By default, NewGPO is linked at the last position (bottom) or near ReferenceGPO. Specify a different LinkOrder to link it e.g. at the top (Linkorder 1) or anywhere in between.
        
        Required?                    false
        Position?                    named
        Default value                0
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -Enforced
        Specify this parameter to select an enforcement state for the GPO link. The default is "unspecified" which effectively means "not enforced". Valid options are "unspecified" (0), "no" (1) 
        and "yes" (2).
        
        Required?                    false
        Position?                    named
        Default value                Unspecified
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -LinkEnabled
        Specify this parameter to select an enablement state for the GPO link. The default is "unspecified" which effectively means "enabled". Valid options are "unspecified" (0), "no" (1) and 
        "yes" (2).
        
        Required?                    false
        Position?                    named
        Default value                Unspecified
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -RemoveLink [<SwitchParameter>]
        Specify this switch to only remove the link to ReferenceGPO.
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -WhatIf [<SwitchParameter>]
        
        Required?                    false
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -Confirm [<SwitchParameter>]
        
        Required?                    false
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see 
        about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216). 
    
INPUTS
    This cmdlet does not take pipeline input.
    
    
OUTPUTS
    This cmdlet does not return pipeline output.
    
    
NOTES
    
    
        Because such mass operations are usually not required for sites or for the domain itself, it does not process these SOM types. Only OUs are searched.
    
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\>Append-GPLink -ReferenceGPO 'Server Default Policy' -NewGPO 'Server Addon Policy'
    
    Searches all OUs where the GPO named 'Server Default Policy' is linked, and links the GPO named 'Server Addon Policy' to these OUs. The link will be disabled and enforced.
    
    
    
    
    -------------------------- EXAMPLE 2 --------------------------
    
    PS C:\>Append-GPLink -ReferenceGPO 'Server Default Policy' -NewGPO 'Server New Default Policy' -OUFilter 'OU=Servers' -Replace -LinkOrder 1
    
    Searches all OUs matching 'OU=Servers' where the GPO named 'Server Default Policy' is linked, and links the GPO named 'Server New Default Policy' to these OUs at position 1 . Then it removes 
    the existing link to 'Server Default Policy'.
    
    
    
    
    -------------------------- EXAMPLE 3 --------------------------
    
    PS C:\>Append-GPLink -ReferenceGPO 'Server Default Policy' -Remove
    
    Searches all OUs where the GPO named 'Server Default Policy' is linked, and removes the existing link.
    
    
    
    
    
RELATED LINKS



