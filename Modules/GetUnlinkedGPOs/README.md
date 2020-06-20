
NAME
    Get-UnlinkedGPOs
    
SYNOPSIS
    Retrieves all GPOs in a domain. For each GPO, it determines whether the GPO is linked to any OU. All unlinked GPOs are returned.
    
    
SYNTAX
    Get-UnlinkedGPOs [-IncludeDisabledLinks] [-IncludeDisabledGPOs] [<CommonParameters>]
    
    
DESCRIPTION
    For housekeeping reasons, you might want to get rid of GPOs that do not apply to anything. This includes unlinked GPOs as well as GPOs that have disabled links only or where both computer 
    and user part are disabled.
    
    The Get-UnlinkedGPOs function searches a domain for these GPOs and returns the resulting GPO objects. It also adds 3 boolean properties to each returned GPO:
    $GPO.Unlinked: The GPO is selected because it is not linked at all
    $GPO.AllLinksDisabled: The GPO is selected because it has links, but all of these links are disabled
    $GPO.AllSettingsDisabled: The GPO is selected because all settings are disabled. Already contained in $GPO.GPOStatus, but for convenience.
    
    DYNAMIC PARAMETERS
    
    -Domain <String>
        The domain where the operation should be performed. This must the user's current domain or a trusting domain. Tab completion searches through the list of possible target domains.
    
        Required?                    true
        Position?                    1
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
    

PARAMETERS
    -IncludeDisabledLinks [<SwitchParameter>]
        By default, only GPOs are returned that have no links at all. Use this switch to also return all GPOs that have no enabled links (all links are disabled).
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    -IncludeDisabledGPOs [<SwitchParameter>]
        By default, only GPOs are returned that have no links at all. Use this switch to also return all GPOs where all settings are disabled (both user and computer settings).
        
        Required?                    false
        Position?                    named
        Default value                False
        Accept pipeline input?       false
        Accept wildcard characters?  false
        
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see 
        about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216). 
    
INPUTS
    This cmdlet does not take pipeline input
    
    
OUTPUTS
    [[Microsoft.GroupPolicy.GPMGPO]]
    
    
NOTES
    
    
        There are a lot of samples how to find unlinked GPOs with Powershell. All of them use Get-GPReport against all GPOs and parse the report for <LinksTo>-Elements. Whilst this approach 
        works well in small environments, it is a complete mess in large domains with thousands of GPOs.
        
        This function thus takes a completely different approach. It retrieves all SOMs that have a populated GPLink attribute and creates a hash of all GPOs in all these GPLinks. Then it 
        compares all GPO IDs to this hash.
        
        Although prepraring the hash takes some time (roughly 2 seconds per 100 SOMs), the overall time is significantly lower compared to Get-GPReport.
    
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\>Get-UnlinkedGPOs -Domain corp.contoso.com
    
    Gets all unlinked GPOs in the corp.contoso.com domain.
    
    
    
    
    -------------------------- EXAMPLE 2 --------------------------
    
    PS C:\>Get-UnlinkedGPOs -Domain corp.contoso.com -IncludeDisabledLinks | Remove-GPO -Confirm:$False
    
    Gets all unlinked GPOs including those with disabled links and pipes them to Remove-GPO for instant deletion (not recommended to use in the first place).
    
    
    
    
    
RELATED LINKS



