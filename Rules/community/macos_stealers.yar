// Nick YARA Rules — macOS credential-access behaviour
//
// class = "behavior": generic capability heuristics. They describe what a file
// *can* do, which legitimate password managers, browsers, and backup tools can
// also do. Nick weighs them with file context (location, signature, build
// tree) and never auto-blocks on them. Family-specific detections live in
// Rules/families and use class = "signature".

rule macos_keychain_access
{
    meta:
        description = "Keychain password-query APIs together with direct keychain file paths"
        class = "behavior"
        severity = "MEDIUM"
        tags = "stealer,keychain"
    strings:
        $kc1 = "SecKeychainFindGenericPassword" ascii
        $kc2 = "SecKeychainFindInternetPassword" ascii
        $kc3 = "/Library/Keychains" ascii
        $kc4 = "login.keychain-db" ascii
    condition:
        ($kc1 or $kc2) and ($kc3 or $kc4)
}

rule macos_browser_credential_theft
{
    meta:
        description = "References credential or cookie stores of many browsers at once"
        class = "behavior"
        severity = "MEDIUM"
        tags = "stealer,browser"
    strings:
        $chrome   = "Google/Chrome" ascii wide
        $brave    = "BraveSoftware/Brave-Browser" ascii wide
        $edge     = "Microsoft Edge" ascii wide
        $opera    = "com.operasoftware.Opera" ascii wide
        $vivaldi  = "Vivaldi" ascii wide
        $arc      = "Arc/User Data" ascii wide
        $firefox  = "Firefox/Profiles" ascii wide
        $safari   = "Cookies.binarycookies" ascii wide
        $login    = "Login Data" ascii wide
        $cookies  = "/Cookies" ascii wide
    condition:
        ($login or $cookies) and 4 of ($chrome, $brave, $edge, $opera, $vivaldi, $arc, $firefox, $safari)
}

rule macos_screenshot_capture
{
    meta:
        description = "Screen-capture APIs (common in screen recorders; weak evidence alone)"
        class = "behavior"
        severity = "LOW"
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
        description = "References iCloud authentication token material"
        class = "behavior"
        severity = "LOW"
        tags = "stealer,icloud"
    strings:
        $t1 = "com.apple.account.AppleAccount" ascii
        $t2 = "com.apple.bird" ascii
        $t3 = "MMCSAuthToken" ascii
    condition:
        $t3 and ($t1 or $t2)
}

rule macos_stealer_password_prompt
{
    meta:
        description = "Fake password dialog whose answer is verified with dscl (AMOS-style stealer loader); also seen in some IT enrollment scripts"
        class = "behavior"
        severity = "HIGH"
        tags = "stealer,phishing"
    strings:
        $dialog = "display dialog" ascii wide nocase
        $hidden = "with hidden answer" ascii wide nocase
        $dscl1  = "dscl . authonly" ascii wide nocase
        $dscl2  = "dscl . -authonly" ascii wide nocase
        $dscl3  = "dscl /Local/Default -authonly" ascii wide nocase
    condition:
        $dialog and $hidden and 1 of ($dscl*)
}

rule macos_stealer_credential_harvest
{
    meta:
        description = "Password prompt or verification combined with harvesting of wallets, browser, Telegram, Notes, or Keychain data (Atomic/AMOS-family behaviour)"
        class = "behavior"
        severity = "CRITICAL"
        tags = "stealer,critical"
    strings:
        $pw1 = "with hidden answer" ascii wide nocase
        $pw2 = "dscl . authonly" ascii wide nocase
        $pw3 = "-authonly" ascii wide
        $t1  = "Application Support/Exodus" ascii wide
        $t2  = "Electrum/wallets" ascii wide
        $t3  = "Coinomi" ascii wide
        $t4  = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide  // MetaMask extension ID
        $t5  = "Telegram Desktop/tdata" ascii wide
        $t6  = "NoteStore.sqlite" ascii wide
        $t7  = "login.keychain-db" ascii wide
        $t8  = "Cookies.binarycookies" ascii wide
        $t9  = "atomic/Local Storage" ascii wide
        $t10 = "Ledger Live" ascii wide
        $x1  = "ditto -c -k --sequesterRsrc" ascii wide
        $x2  = "curl -X POST" ascii wide nocase
        $x3  = "-F \"file=@" ascii wide
    condition:
        1 of ($pw*) and 4 of ($t*) and 1 of ($x*)
}
