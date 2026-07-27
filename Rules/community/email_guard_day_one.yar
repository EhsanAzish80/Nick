/*
 * Nick Email Guard — conservative offline starter rules.
 *
 * These rules intentionally require several related indicators. A single
 * command, macro name, or JavaScript API is not enough to quarantine a file.
 * They provide useful day-one coverage without depending on a downloaded feed.
 */

rule nick_email_shell_dropper : email dropper macos
{
    meta:
        description = "Shell attachment downloads and prepares a payload for execution"
        author = "Nick"
        confidence = "high"
    strings:
        $download_1 = "curl -fsSL" ascii nocase
        $download_2 = "curl -sSL" ascii nocase
        $download_3 = "wget http" ascii nocase
        $execute_1 = "chmod +x" ascii nocase
        $execute_2 = "xattr -d com.apple.quarantine" ascii nocase
        $persist_1 = "/Library/LaunchAgents/" ascii nocase
        $persist_2 = "launchctl bootstrap" ascii nocase
        $shell_1 = "#!/bin/sh" ascii
        $shell_2 = "#!/bin/bash" ascii
        $shell_3 = "#!/bin/zsh" ascii
    condition:
        filesize < 2MB and
        1 of ($shell_*) and
        1 of ($download_*) and
        (1 of ($execute_*) or 1 of ($persist_*))
}

rule nick_email_applescript_dropper : email dropper macos
{
    meta:
        description = "AppleScript attachment downloads and executes a payload"
        author = "Nick"
        confidence = "high"
    strings:
        $applescript = "do shell script" ascii nocase
        $download_1 = "curl " ascii nocase
        $download_2 = "wget " ascii nocase
        $execute_1 = "chmod +x" ascii nocase
        $execute_2 = "launchctl " ascii nocase
        $execute_3 = "osascript " ascii nocase
        $hide_1 = "xattr -d com.apple.quarantine" ascii nocase
    condition:
        filesize < 2MB and
        $applescript and
        1 of ($download_*) and
        (1 of ($execute_*) or $hide_1)
}

rule nick_email_html_smuggling : email html_smuggling
{
    meta:
        description = "HTML attachment constructs and downloads a decoded binary payload"
        author = "Nick"
        confidence = "high"
    strings:
        $decode_1 = "atob(" ascii nocase
        $decode_2 = "Uint8Array" ascii nocase
        $blob = "new Blob(" ascii nocase
        $object_url = "URL.createObjectURL" ascii nocase
        $download = ".download" ascii nocase
    condition:
        filesize < 5MB and
        1 of ($decode_*) and
        $blob and
        $object_url and
        $download
}

rule nick_email_powershell_encoded_dropper : email dropper windows
{
    meta:
        description = "Attachment invokes encoded PowerShell and downloads content"
        author = "Nick"
        confidence = "high"
    strings:
        $powershell_1 = "powershell.exe" ascii wide nocase
        $powershell_2 = "powershell " ascii wide nocase
        $encoded_1 = "-EncodedCommand" ascii wide nocase
        $encoded_2 = "FromBase64String" ascii wide nocase
        $download_1 = "DownloadString" ascii wide nocase
        $download_2 = "DownloadFile" ascii wide nocase
        $download_3 = "Invoke-WebRequest" ascii wide nocase
    condition:
        filesize < 10MB and
        1 of ($powershell_*) and
        1 of ($encoded_*) and
        1 of ($download_*)
}

rule nick_email_office_macro_dropper : email macro windows
{
    meta:
        description = "Office macro attachment launches a command interpreter or script host"
        author = "Nick"
        confidence = "high"
    strings:
        $auto_1 = "AutoOpen" ascii wide nocase
        $auto_2 = "Document_Open" ascii wide nocase
        $auto_3 = "Workbook_Open" ascii wide nocase
        $shell_1 = "WScript.Shell" ascii wide nocase
        $shell_2 = "powershell" ascii wide nocase
        $shell_3 = "cmd.exe" ascii wide nocase
        $fetch_1 = "URLDownloadToFile" ascii wide nocase
        $fetch_2 = "DownloadString" ascii wide nocase
        $fetch_3 = "XMLHTTP" ascii wide nocase
    condition:
        filesize < 20MB and
        1 of ($auto_*) and
        1 of ($shell_*) and
        1 of ($fetch_*)
}
