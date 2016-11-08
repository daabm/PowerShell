$NuGetApiKey = "e0ac57ed-978f-434a-8037-63daa19d7ea3"

Try {
  Import-Module -Name UpdateInstalledModule
  Update-InstalledModule
  }
Catch { $_ }

Import-Module -Name IseSteroids
Import-Module -Name IsePackv2

#Import-Module PowerShellISE-Preview
#Import-Module ModuleBrowser
#Enable-ModuleBrowser

$psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Clear()

#Script Browser Begin
#Version: 1.3.1
Add-Type -Path "${env:ProgramFiles(x86)}\Microsoft Corporation\Microsoft Script Browser\System.Windows.Interactivity.dll" -ErrorAction SilentlyContinue
Add-Type -Path "${env:ProgramFiles(x86)}\Microsoft Corporation\Microsoft Script Browser\ScriptBrowser.dll" -ErrorAction SilentlyContinue
Add-Type -Path "${env:ProgramFiles(x86)}\Microsoft Corporation\Microsoft Script Browser\BestPractices.dll" -ErrorAction SilentlyContinue
if ( ! $ScriptBrowser )
{
  $ScriptBrowser = $psISE.CurrentPowerShellTab.VerticalAddOnTools.Add( 'Script Browser', [ScriptExplorer.Views.MainView], $true )
}

if ( ! $ScriptAnalyzer )
{
  $ScriptAnalyzer = $psISE.CurrentPowerShellTab.VerticalAddOnTools.Add( 'Script Analyzer', [BestPractices.Views.BestPracticesView], $true )
}

$psISE.CurrentPowerShellTab.VisibleVerticalAddOnTools.SelectedAddOnTool = $scriptBrowser
#Script Browser End


##############################################################################################################
# Copy-Script.ps1
#
# The script entire contents of the currently selected editor window to system clipboard.
# The copied data can be pasted into any application that supports pasting in UnicodeText, RTF or HTML format.
# Text pasted in RTF or HTML format will be colorized.
# https://blogs.msdn.microsoft.com/powershell/2009/01/12/how-to-copy-colorized-script-from-powershell-ise/

Add-Type -AssemblyName System.Web

# Create RTF block from text using named console colors.
#
function Add-RtfBlock
{
  [CmdletBinding()]
  param
  (
    [ Parameter ( Mandatory = $true ) ] [String] $block,
    [ Parameter ( Mandatory = $true ) ] [String] $tokenColor
  )
  $colorIndex = $rtfColorMap.$tokenColor
  $block = $block.Replace( '\', '\\' ).Replace( "`r`n" , "\cf1\par`r`n" ).Replace( "`t", '\tab' ).Replace( '{', '\{' ).Replace( '}', '\}' )
  $null = $rtfBuilder.Append("\cf$colorIndex $block")
}

# Generate an HTML span and append it to HTML string builder
#
function Add-HtmlSpan
{
  param
  (
    [ Parameter( Mandatory = $true ) ] [String] $block,
    [ Parameter( Mandatory = $true ) ] [String] $tokenColor
  )
  if ( $tokenColor -eq 'NewLine' )
  {
    $null = $htmlBuilder.Append( '<br>' )
  }
  else
  {
    $block = [System.Web.HttpUtility]::HtmlEncode( $block )
    if ( -not $block.Trim() )
    {
      $block = $block.Replace( ' ', '&nbsp;' )
    }
    $htmlColor = $psise.Options.TokenColors[$tokenColor].ToString().Replace( '#FF', '#' )
    $null = $htmlBuilder.Append( "<span style='color:$htmlColor'>$block</span>" )
  }
}

function Set-TokenColor
{
  [ CmdletBinding() ]
  param
  (
    [ Parameter( Mandatory = $true, ValueFromPipeline = $true, HelpMessage = 'Data to process' ) ] [Object] $InputObject
  )
  process
  {
    $tokenColor = $psise.Options.TokenColors[$InputObject]
    $rtfColor = "\red$( $tokenColor.R )\green$( $tokenColor.G )\blue$( $tokenColor.B );"
    if ( $rtfColors.Keys -notcontains $rtfColor )
    {
      $rtfColors.$rtfColor = $rtfColorIndex
      $null = $rtfBuilder.Append( $rtfColor )
      $rtfColorMap.$InputObject = $rtfColorIndex
      $rtfColorIndex ++
    }
    else
    {
      $rtfColorMap.$InputObject = $rtfColors.$rtfColor
    }
  }
}

function Copy-Script
{
  if (-not $psise.CurrentFile )
  {
    Write-Error -Message 'No script is available for copying.'
    return
  }
    
  $text = $psise.CurrentFile.Editor.Text

  trap { break }

  # Do syntax parsing.
  $errors = $null
  $tokens = [system.management.automation.psparser]::Tokenize( $Text, [ref] $errors )

  # Set the desired font and font size
  $fontName = 'Lucida Console'
  $fontSize = 10

  # Initialize HTML builder.
  $htmlBuilder = New-Object -TypeName system.text.stringbuilder
  $null = $htmlBuilder.AppendLine( "<p style='MARGIN: 0in 10pt 0in;font-family:$fontname;font-size:$fontSize`pt'>" )

  # Initialize RTF builder.
  $rtfBuilder = New-Object -TypeName system.text.stringbuilder
  # Append RTF header
  $null = $rtfBuilder.Append( "{\rtf1\fbidis\ansi\ansicpg1252\deff0\deflang1033{\fonttbl{\f0\fnil\fcharset0 $fontName;}}" )
  $null = $rtfBuilder.Append( "`r`n" )
  # Append RTF color table which will contain all Powershell console colors.
  $null = $rtfBuilder.Append( '{\colortbl ;' )
  # Generate RTF color definitions for each token type.
  $rtfColorIndex = 1
  $rtfColors = @{}
  $rtfColorMap = @{}
  [Enum]::GetNames( [System.Management.Automation.PSTokenType] ) | Set-TokenColor
  $null = $rtfBuilder.Append( '}' )
  $null = $rtfBuilder.Append( "`r`n" )
  # Append RTF document settings.
  $null = $rtfBuilder.Append( '\viewkind4\uc1\pard\f0\fs20 ' )
    
  $position = 0
  # Iterate over the tokens and set the colors appropriately.
  foreach ( $token in $tokens )
  {
    if ( $position -lt $token.Start )
    {
      $block = $text.Substring( $position, ( $token.Start - $position) )
      $tokenColor = 'Unknown'
      Add-RtfBlock -block $block -tokenColor $tokenColor
      Add-HtmlSpan -block $block -tokenColor $tokenColor
    }
    $block = $text.Substring( $token.Start, $token.Length )
    $tokenColor = $token.Type.ToString()
    Add-RtfBlock -block $block -tokenColor $tokenColor
    Add-HtmlSpan -block $block -tokenColor $tokenColor
        
    $position = $token.Start + $token.Length
  }

  # Append HTML ending tag.
  $null = $htmlBuilder.Append( '</p>' )

  # Append RTF ending brace.
  $null = $rtfBuilder.Append( '}' )

  # Copy console screen buffer contents to clipboard in three formats - text, HTML and RTF.
  #
  $dataObject = New-Object -TypeName Windows.DataObject
  $dataObject.SetText( [string]$text, [Windows.TextDataFormat]'UnicodeText' )
  $html = $htmlBuilder.ToString()
  $dataObject.SetText( [string]$html, [Windows.TextDataFormat]'Html' )
  $rtf = $rtfBuilder.ToString()
  $dataObject.SetText( [string]$rtf, [Windows.TextDataFormat]'Rtf' )

  [Windows.Clipboard]::SetDataObject( $dataObject, $true )

}

$null = $psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add( '_Copy Script', { Copy-Script }, $null )

Import-Module ISEModuleBrowserAddon
Import-Module VariableExplorer
