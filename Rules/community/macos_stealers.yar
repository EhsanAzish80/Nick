// Nick YARA Rules — macOS Credential Stealers
// Detects common macOS credential and data theft patterns.

rule macos_keychain_access
{
    meta:
        description = "Detects keychain API patterns associated with credential stealers"
        severity = "HIGH"
        tags = "stealer,keychain"
    strings:
        $kc1 = "SecKeychainFindGenericPassword" ascii
        $kc2 = "SecKeychainFindInternetPassword" ascii
        $kc3 = "/Library/Keychains" ascii
    condition:
        ($kc1 or $kc2) and $kc3
}

rule macos_browser_credential_theft
{
    meta:
        description = "Detects attempts to access browser stored credentials and cookies"
        severity = "HIGH"
        tags = "stealer,browser"
    strings:
        $chrome  = "/Google/Chrome/Default/Login Data" ascii wide
        $safari  = "Cookies.binarycookies" ascii wide
        $brave   = "/BraveSoftware/Brave-Browser/Default/Login Data" ascii wide
        $firefox = "/Firefox/Profiles" ascii wide
    condition:
        2 of them
}

rule macos_screenshot_capture
{
    meta:
        description = "Detects covert screenshot capture patterns used by spyware"
        severity = "MEDIUM"
        tags = "stealer,spyware"
    strings:
        $sc1 = "CGWindowListCreateImageFromArray" ascii
        $sc2 = "CGMainDisplayID" ascii
        $sc3 = "kCGWindowImageBoundsIgnoreFraming" ascii
    condition:
        2 of them
}

rule macos_icloud_token_theft
{
    meta:
        description = "Detects access to iCloud authentication tokens"
        severity = "HIGH"
        tags = "stealer,icloud"
    strings:
        $t1 = "com.apple.account.AppleAccount" ascii
        $t2 = "com.apple.bird" ascii
        $t3 = "MMCSAuthToken" ascii
    condition:
        2 of them
}
