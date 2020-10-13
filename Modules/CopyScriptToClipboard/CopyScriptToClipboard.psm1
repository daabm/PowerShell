<#
.SYNOPSIS

Copy-ScriptToClipboard is designed for use in PowerShell ISE. It copies the entire contents
or your selection from the currently selected script pane to the system clipboard
colourised for RTF and HTML, black and white for Unicode Text.

.DESCRIPTION

Copy-ScriptToClipboard clipboards the entire script you have active in your scripting pane.
The clipboard can then be pasted into any application that supports pasting in UnicodeText,
RTF or HTML format. When pasting in HTML format the line numbers will also be visible.
It supports passing a file into it if need be.
There is a switch allowing you to use the default script pane colours as output, not
your own selected colours.

.PARAMETER Path

By default, Copy-ScriptToClipboard copies the currently active tab in PowerShell ISE to the clipboard.
You can specify a file with the path parameter to override this behavior.

.PARAMETER DefaultColour

The colourization of RTF and HTML in the clipboard will be taken from your current ISE colour settings.
Specify this switch to use ISE default colours.

.PARAMETER SelectedText

By default, the full content of the current tab will be copied. Specify this switch to copy only the current selection.

.INPUTS

This cmdlet does not take pipeline input.

.OUTPUTS

This cmdlet does not return any output.

.EXAMPLE

Copy-ScriptToClipboard

Simply copy the complete content of the current ISE tab to the clipboard in Text, HTML and RTF format.

.EXAMPLE

Copy-ScriptToClipboard .\Sample.ps1 -DefaultColours

Copy the content of Sample.ps1 to the clipboard and use ISE default colours instead of your current colour selection.

.EXAMPLE

Copy-ScriptToClipboard -SelectedText

Do not copy the complete script, but the current selection only.

.NOTES

The module is almost 100% based on a script written by NoneAndOne (Garth Moodie):
https://gallery.technet.microsoft.com/scriptcenter/Copy-Script-in-Colour-to-3a500fa1

I converted it to a module and added automatic creation of Add-Ons menu entries during module import
as well as automatic removal of these entries upon module removal.

The original script version was written by Vladimir Averkin in early 2009.  It was
quickly superceded by an updated version written by Lee Holmes in February 2009.
See Lee's version here:
http://www.leeholmes.com/blog/2009/02/03/more-powershell-syntax-highlighting/

.LINK

https://gallery.technet.microsoft.com/scriptcenter/Copy-Script-in-Colour-to-3a500fa1

.LINK

http://www.leeholmes.com/blog/2009/02/03/more-powershell-syntax-highlighting/

#>
Function Copy-ScriptToClipboard { 

    [CmdletBinding()] 
    param(
        [Parameter( ParameterSetName = 'Path' )]
        [string] $Path,

        [Parameter( ParameterSetName = 'Selection' )]
        [switch] $SelectedText,

        [switch] $DefaultColour
    )

    # Get the input from a file or the current script open in the PowerShell ISE
    If ( $Path ) {
        # The user supplied a full filename (path included)
        If ( Test-Path $Path ) {
            $Text = ( Get-Content $Path ) -join "`r`n"
        } Else {
            Write-Error "The file ""$Path"" is not available for copying."
        } 
    } ElseIf ( -not $psise.CurrentFile ) {
        Write-Error 'No current script are you running PowerShell ISE?' 
    } ElseIf ( $SelectedText ) {
        # See if the user wants a selection of text from the script pane
        $Text = $psise.CurrentFile.Editor.SelectedText
        If ( $Text ) {
            $psise.CurrentFile.Editor.InsertText( $Text )
            $CurrentLine = $psISE.CurrentFile.Editor.CaretLine
            $FirstLine   = $CurrentLine
        }
    } Else { # The user wants the whole script pane (default)
        $Text = $psise.CurrentFile.Editor.Text
        $CurrentLine = 1 
        $FirstLine = $CurrentLine
    }

    If ( $Text ) {
        # Ok, have data, can start
        # Set the colours to the standard Script Pane colours 
        # I have changed the Operator colour, it was too hard to read
        $TokenColours = @{ 
        #    Type                   Colour(Hex)
            'Attribute'          = '#FFADD8E6' 
            'Command'            = '#FF0000FF' 
            'CommandArgument'    = '#FF8A2BE2' 
            'CommandParameter'   = '#FF000080' 
            'Comment'            = '#FF006400' 
            'GroupEnd'           = '#FF000000' 
            'GroupStart'         = '#FF000000' 
            'Keyword'            = '#FF00008B' 
            'LineContinuation'   = '#FF000000' 
            'LoopLabel'          = '#FF00008B' 
            'Member'             = '#FF000000' 
            'NewLine'            = '#FF000000' 
            'Number'             = '#FF800080' 
    #        'Operator'           = '#FFA9A9A9' 
            'Operator'           = '#FF3CB371' 
            'Position'           = '#FF000000' 
            'StatementSeparator' = '#FF000000' 
            'String'             = '#FF8B0000' 
            'Type'               = '#FF008080' 
            'Unknown'            = '#FF000000' 
            'Variable'           = '#FFFF4500' 
        }
        # Default is overwrite the defaults with your personal PowerShell ISE colours
        If ( -not $DefaultColour ) {
            $TokenColours = $psise.Options.TokenColors 
        } 
        # Break the text up into a sequestial array of tokens, one token
        # for each of the Types above that it finds as it reads
        $errors = $null 
        $Tokens = [System.Management.Automation.PsParser]::Tokenize( $Text, [ref]$errors )

        # Initialise the HTML string builder. 
        Add-Type -Assembly System.Web 
        $HTMLBuilder = New-Object -TypeName System.Text.StringBuilder
   
        # Initialise the RTF builder. 
        $RTFBuilder            = New-Object -TypeName System.Text.StringBuilder
        $RTFTokenTypeColourNos = @{} 
        $RTFBuilder            = RTF-Initialise $RTFBuilder

        # Iterate through the tokens appending the content and colour of the token
        # to the RTF string builder and the HTML string builder.
        $Position = 0 
        ForEach ( $Token in $Tokens ) { 
            If ( $Position -lt $Token.Start ) { 
                $TokenContent = $text.Substring( $Position, ( $Token.Start - $Position ) )
                $TokenType    = 'Unknown' 
                $TokenColNo   = $RTFTokenTypeColourNos.$TokenType
                $RTFBuilder   = RTF-Append-Token $RTFBuilder $TokenContent $TokenColNo
                $CurrentLine  = HTML-Append-Token $CurrentLine $TokenContent $TokenType
            } 
            $TokenContent = $text.Substring( $Token.Start, $Token.Length ) 
            $TokenType    = $Token.Type.ToString() 
            $TokenColNo   = $RTFTokenTypeColourNos.$TokenType
            $RTFBuilder   = RTF-Append-Token $RTFBuilder $TokenContent $TokenColNo
            $CurrentLine  = HTML-Append-Token $CurrentLine $TokenContent $TokenType
        
            $Position = $Token.Start + $Token.Length 
        }

        # Append RTF ending brace. 
        [void]$RTFBuilder.Append( '}' )

        # Build the column of line numbers for the HTML
        $LineNoColBuilder = New-Object -TypeName System.Text.StringBuilder
        For ( $LineNoCounter = $FirstLine; $LineNoCounter -lt $CurrentLine; $LineNoCounter++ ) {
            [void]$LineNoColBuilder.Append( "{0:0}<BR />" -f $LineNoCounter )
        }
    
        # Copy console screen buffer contents to clipboard in three formats - 
        # text, HTML and RTF. 
        $ClipboardContent = New-Object -TypeName Windows.DataObject 
        $ClipboardContent.SetText( [string]$Text, [Windows.TextDataFormat]"UnicodeText" ) 

        $RTF = $RTFBuilder.ToString() 
        $ClipboardContent.SetText( [string]$RTF, [Windows.TextDataFormat]"Rtf" ) 

        $HTMLBuilt = $HTMLBuilder.ToString(); $LineNoColBuilt = $LineNoColBuilder.ToString()
        # Put all the collected HTML info into an HTML page
        $HTML = HTML-For-Clipboard $HTMLBuilt $LineNoColBuilt
        $ClipboardContent.SetText( [string]$HTML, [Windows.TextDataFormat]"Html" ) 

        [Windows.Clipboard]::SetDataObject( $ClipboardContent, $true ) 
    }
} 

<#
.SYNOPSIS

Shortcut function for copying the current selection. Calls Copy-ScriptToClipboard -SelectedText.
The associated menu item has a shortcut Ctrl-Shift-C. So you can simply type Ctrl-A, Ctrl-Shift-C to
copy the complete current script.

#>
Function Copy-SelectionToClipboard { Copy-ScriptToClipboard -SelectedText }

####################################################################################################
# Function Initialise-RTF
#
# The header part of the RTF string builder contains the information about the document.
# The function creates the header, assigning the screen font to the text and creates
# the list of RGB colours in use. The text is appended to the RTF string builder.
#
# Creates: $RTFTokenTypeColourNos   The RGB colour values needed to colour the individual tokens
# Returns: $RTFBuilder              The initialised RTF string builder
####################################################################################################
Function RTF-Initialise ( $RTFBuilder ) {
    # Append RTF Header 
    $RTFHeader = "{\rtf1\fbidis\ansi\ansicpg1252\deff0\deflang1033{\fonttbl{\f0\fnil\fcharset0 Lucida Console;}}" 
    [void]$RTFBuilder.Append( $RTFHeader )
    [void]$RTFBuilder.Append( "`r`n" )

    # Append RTF colour table which will contain all Powershell console colors. 
    [void]$RTFBuilder.Append( "{\colortbl ;" )

    # Generate RTF colour number for each token type. 
    $RTFColourIndex = 1 
    $RTFColourNos = @{} 
    [Enum]::GetNames( [System.Management.Automation.PSTokenType] ) | Sort-Object | ForEach-Object {
        # Extract the colours from the hex string to get RTF colour
        $TokenColour = $TokenColours[ $_ ].ToString()
        $Red         = [Convert]::ToInt32( $TokenColour.substring( 3, 2 ), 16 )
        $Green       = [Convert]::ToInt32( $TokenColour.substring( 5, 2 ), 16 )
        $Blue        = [Convert]::ToInt32( $TokenColour.substring( 7, 2 ), 16 )
        $RTFColour   = "\red$Red\green$Green\blue$Blue;" 
        If ( $RTFColourNos.Keys -notcontains $RTFColour ) {
            # This is a new colour, add to the list
            $RTFColourNos.$RTFColour = $RTFColourIndex
            [void]$RTFBuilder.Append( $RTFColour )
            $RTFTokenTypeColourNos.$_ = $RTFColourIndex 
            $RTFColourIndex ++ 
        } 
        Else { 
            $RTFTokenTypeColourNos.$_ = $RTFColourNos.$RTFColour 
        } 
    } 
    [void]$RTFBuilder.Append( '}' )
    [void]$RTFBuilder.Append( "`r`n" )

    # Append RTF document settings. 
    [void]$RTFBuilder.Append( '\viewkind4\uc1\pard\f0\fs20 ' )
    Return $RTFBuilder
}    


####################################################################################################
# Function RTF-Append-Token
#
# Generates an RTF string from the token content and colour, and appends it to the RTF
# string builder
#
# Requires: $Content and $ColourNumber - the Token content and colour reference
# Returns:  $RTFStringBuilder          - The updated RTF string builder
####################################################################################################
Function RTF-Append-Token ( $RTFStringBuilder, $Content, $ColourNumber ) { 
    $Content = $Content.Replace( "`r","" )
    $Content = $Content.Replace( '\','\\').Replace("`n","\cf1\par`r`n" ) 
    $Content = $Content.Replace( "`t",'\tab').Replace('{','\{').Replace('}','\}' )
    $RTFStringBuilder.Append( "\cf$ColourNumber $Content" )
} 


####################################################################################################
# Function HTML-Append-Token
#
# Generates an HTML string from the token content and colour, and appends it to the HTML
# string builder. Incraments the line counter when a new line is encountered.
#
# Modifies:   $HTMLBuilder       - A parent function variable.  Appending
#                                  to the string being built.
# References: $TokenColours      - To get the HTML colour needed.
# Requires:   $Content and $Type - The content and type of the token
# Returns:    $LineNumber        - The current Line Number, updated if need be.
####################################################################################################
Function HTML-Append-Token ( $LineNumber, $Content, $Type ) { 
    If ( $Type -match 'NewLine|LineContinuation' ) { 
        # Need to append a new line
        If( $Type -eq 'LineContinuation' ) { 
            [void]$HTMLBuilder.Append( '`' )
        }
        [void]$HTMLBuilder.Append( "<br />`r`n" )
        $LineNumber++ 
    } Else { 
        $Content = [System.Web.HttpUtility]::HtmlEncode( $Content )
        # Replace the spaces with HTML
        $Content = $Content.Replace( ' ', '&nbsp;' )
        $HTMLColour = $TokenColours[$Type].ToString().Replace( '#FF', '#' )
        If( $Type -match 'String|Comment' ) { 
            $Content = $Content.Replace( '`r', '' )
            $Lines = $Content -split "`n" 
            $Content = "" 
            $MultipleLines = $false 
            ForEach( $Line in $Lines ) {
                If( $MultipleLines ) {
                    $Content += "<BR />`r`n" 
                    $LineNumber++ 
                } 
                $Content += $Line
                $MultipleLines = $true 
            } 
        } 
        [void]$HTMLBuilder.Append( "<span style='color:$HTMLColour'>$Content</span>" )
    } 
    Return $LineNumber
} 


####################################################################################################
# Function HTML-For-Clipboard
#
# Insert the finished HTML script and Line Number Column strings into an HTML page
# formatted for the Windows Clipboard.
#
# The 3 lines with a "background" colour value are in order; the table, the number column
# and the cell colour. I have them all set to a light grey so they match my script pane.
# The number column also has a value "color" for the colour of the numbers.
#
# Requires: $HTMLContent  - The converted script
#           $LineNoColumn - The line numbers at the left of the page
# Returns:  $HTMLPage     - The completed HTML fomatted for the Windows Clipboard
####################################################################################################
Function HTML-For-Clipboard( $HTMLContent, $LineNoColumn ) {
 
$HTMLPage = @" 
Version:1.0 
StartHTML:0000000000 
EndHTML:0000000000 
StartFragment:0000000000 
EndFragment:0000000000 
StartSelection:0000000000 
EndSelection:0000000000 
SourceURL:file:///about:blank 
<!DOCTYPE HTML PUBLIC `"-//W3C//DTD HTML 4.0 Transitional//EN`"> 
<HTML> 
<HEAD> 
<TITLE>HTML Clipboard</TITLE> 
</HEAD> 
<BODY> 
<!--StartFragment--> 
<DIV style='font-family:Consolas,Lucida Console; font-size:10pt; 
    width:750; border:1px solid black; overflow:auto; padding:5px; background:#fafafa'> 
<TABLE BORDER='0' cellpadding='5' cellspacing='0'> 
<TBODY> 
<TR> 
    <TD VALIGN='Top'> 
<DIV style='font-family:Consolas,Lucida Console; font-size:10pt; 
    padding:5px; text-align: right; color:#4886AD; background:#fafafa'> 
__LINES__ 
</DIV> 
    </TD> 
    <TD VALIGN='Top' NOWRAP='NOWRAP'> 
<DIV style='font-family:Consolas,Lucida Console; font-size:10pt; 
    padding:5px; background:#fafafa'> 
__HTML__ 
</DIV> 
    </TD> 
</TR> 
</TBODY> 
</TABLE> 
</DIV> 
<!--EndFragment--> 
</BODY> 
</HTML> 
"@ 
    # Insert the column of line numbers
    $HTMLPage = $HTMLPage.Replace( "__LINES__", $LineNoColumn )

    $StartFragment = $HTMLPage.IndexOf( "<!--StartFragment-->" ) + "<!--StartFragment-->".Length + 2 
    $EndFragment = $HTMLPage.IndexOf( "<!--EndFragment-->" ) + $HTMLContent.Length - "__HTML__".Length 
    $StartHtml = $HTMLPage.IndexOf( "<!DOCTYPE" )
    $EndHtml = $HTMLPage.Length + $HTMLContent.Length - "__HTML__".Length 

    $HTMLPage = $HTMLPage -replace "StartHTML:0000000000", ( "StartHTML:{0:0000000000}" -f $StartHtml ) 
    $HTMLPage = $HTMLPage -replace "EndHTML:0000000000", ( "EndHTML:{0:0000000000}" -f $EndHtml )
    $HTMLPage = $HTMLPage -replace "StartFragment:0000000000", ( "StartFragment:{0:0000000000}" -f $StartFragment )
    $HTMLPage = $HTMLPage -replace "EndFragment:0000000000", ( "EndFragment:{0:0000000000}" -f $EndFragment )
    $HTMLPage = $HTMLPage -replace "StartSelection:0000000000", ( "StartSelection:{0:0000000000}" -f $StartFragment )
    $HTMLPage = $HTMLPage -replace "EndSelection:0000000000", ( "EndSelection:{0:0000000000}" -f $EndFragment )

    # Insert the content in HTML format
    $HTMLPage = $HTMLPage.Replace("__HTML__", $HTMLContent) 
    
    Return $HTMLPage 
} 

<#
.SYNOPSIS

Adds 2 menu entries to the ISE Add-Ons menu.
Copy Script to Clipboard: Copies the entire script in the current ISE tab to the clipboard.
Copy Selection to Clipboard (Ctrl-Shift-C): Copies the current selection in the current ISE tab to the clipboard.
Function is called automatically during module import.

#>
Function Add-CopyScriptToISEMenu {
    If ( $script:ModuleMenuItems.Count -eq 0 ) {
        $script:ModuleMenuItems = @(
            If ( $psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Actions -notmatch 'Copy-ScriptToClipboard' ) {
                $psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add( 'Copy Script to Clipboard', { Copy-ScriptToClipboard }, $null ),
            }
            If ( $psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Actions -notmatch 'Copy-SelectionToClipboard' ) {
                $psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add( 'Copy Selection to Clipboard', { Copy-SelectionToClipboard }, 'Ctrl+Shift+C' )
            }
            )
    }
}

<#
.SYNOPSIS

Removes the menu entries from the ISE Add-Ons menu.
Function is called automatically during module removal.

#>
Function Remove-CopyScriptFromISEMenu {
    Foreach ( $Item in $script:ModuleMenuItems ) {
        [void]$PSIse.CurrentPowerShellTab.AddOnsMenu.Submenus.Remove( $Item )
    }
    $script:ModuleMenuItems = @()
}

$OnRemoveScript = {
    # perform cleanup
    Remove-CopyScriptFromISEMenu
}

$ExecutionContext.SessionState.Module.OnRemove += $OnRemoveScript

Add-CopyScriptToISEMenu
