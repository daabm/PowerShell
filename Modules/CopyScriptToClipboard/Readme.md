# CopyScriptToClipboard

## Index

| Command | Synopsis |
| ------- | -------- |
| [Remove-CopyScriptFromISEMenu](#Remove-CopyScriptFromISEMenu) | Removes the menu entries from the ISE Add-Ons menu. Function is called automatically during module removal. |
| [Add-CopyScriptToISEMenu](#Add-CopyScriptToISEMenu) | Adds 2 menu entries to the ISE Add-Ons menu. Copy Script to Clipboard: Copies the entire script in the current ISE tab to the clipboard. Copy Selection to Clipboard (Ctrl-Shift-C): Copies the current selection in the current ISE tab to the clipboard. Function is called automatically during module import. |
| [Copy-ScriptToClipboard](#Copy-ScriptToClipboard) | Copy-ScriptToClipboard is designed for use in PowerShell ISE. It copies the entire contents or your selection from the currently selected script pane to the system clipboard colourised for RTF and HTML, black and white for Unicode Text. |
| [Copy-SelectionToClipboard](#Copy-SelectionToClipboard) | Shortcut function for copying the current selection. Calls Copy-ScriptToClipboard -SelectedText. The associated menu item has a shortcut Ctrl-Shift-C. So you can simply type Ctrl-A, Ctrl-Shift-C to copy the complete current script. |

<a name="Remove-CopyScriptFromISEMenu"></a>
## Remove-CopyScriptFromISEMenu
### Synopsis
Removes the menu entries from the ISE Add-Ons menu.
Function is called automatically during module removal.
### Syntax
```powershell
Remove-CopyScriptFromISEMenu
```
<a name="Add-CopyScriptToISEMenu"></a>
## Add-CopyScriptToISEMenu
### Synopsis
Adds 2 menu entries to the ISE Add-Ons menu.
Copy Script to Clipboard: Copies the entire script in the current ISE tab to the clipboard.
Copy Selection to Clipboard (Ctrl-Shift-C): Copies the current selection in the current ISE tab to the clipboard.
Function is called automatically during module import.
### Syntax
```powershell
Add-CopyScriptToISEMenu
```
<a name="Copy-ScriptToClipboard"></a>
## Copy-ScriptToClipboard
### Synopsis
Copy-ScriptToClipboard is designed for use in PowerShell ISE. It copies the entire contents
or your selection from the currently selected script pane to the system clipboard
colourised for RTF and HTML, black and white for Unicode Text.
### Description
Copy-ScriptToClipboard clipboards the entire script you have active in your scripting pane.
The clipboard can then be pasted into any application that supports pasting in UnicodeText,
RTF or HTML format. When pasting in HTML format the line numbers will also be visible.
It supports passing a file into it if need be.
There is a switch allowing you to use the default script pane colours as output, not
your own selected colours.

### Syntax
```powershell
Copy-ScriptToClipboard [-Path <string>] [-DefaultColour] [<CommonParameters>]

Copy-ScriptToClipboard [-SelectedText] [-DefaultColour] [<CommonParameters>]
```
### Parameters
#### Path &lt;String&gt;
    By default, Copy-ScriptToClipboard copies the currently active tab in PowerShell ISE to the clipboard.
    You can specify a file with the path parameter to override this behavior.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### SelectedText [&lt;SwitchParameter&gt;]
    By default, the full content of the current tab will be copied. Specify this switch to copy only the current selection.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### DefaultColour [&lt;SwitchParameter&gt;]
    The colourization of RTF and HTML in the clipboard will be taken from your current ISE colour settings.
    Specify this switch to use ISE default colours.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
### Examples
#### BEISPIEL 1 
```powershell
Copy-ScriptToClipboard

```
Simply copy the complete content of the current ISE tab to the clipboard in Text, HTML and RTF format.
#### BEISPIEL 2 
```powershell
Copy-ScriptToClipboard .\Sample.ps1 -DefaultColours

```
Copy the content of Sample.ps1 to the clipboard and use ISE default colours instead of your current colour selection.
#### BEISPIEL 3 
```powershell
Copy-ScriptToClipboard -SelectedText

```
Do not copy the complete script, but the current selection only.
<a name="Copy-SelectionToClipboard"></a>
## Copy-SelectionToClipboard
### Synopsis
Shortcut function for copying the current selection. Calls Copy-ScriptToClipboard -SelectedText.
The associated menu item has a shortcut Ctrl-Shift-C. So you can simply type Ctrl-A, Ctrl-Shift-C to
copy the complete current script.
### Syntax
```powershell
Copy-SelectionToClipboard
```
<div style='font-size:small; color: #ccc'>Generated 13-10-2020 13:18</div>
