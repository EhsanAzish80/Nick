// Nick YARA Rules — macOS Adware
// Detects browser hijacking, extension injection, and network interception.

rule macos_browser_extension_inject
{
    meta:
        description = "Detects browser extension directory modification typical of adware"
        severity = "MEDIUM"
        tags = "adware,browser"
    strings:
        $ext1 = "/Extensions/" ascii
        $ext2 = "manifest.json" ascii
        $ext3 = "content_scripts" ascii
        $ext4 = "web_accessible_resources" ascii
    condition:
        $ext1 and $ext2 and ($ext3 or $ext4)
}

rule macos_dns_hijack
{
    meta:
        description = "Detects DNS configuration modification typical of redirect adware"
        severity = "HIGH"
        tags = "adware,dns"
    strings:
        $dns1 = "/etc/resolv.conf" ascii
        $dns2 = "State:/Network/Global/DNS" ascii
        $dns3 = "SCDynamicStoreSetValue" ascii
    condition:
        2 of them
}

rule macos_launch_constraints_bypass
{
    meta:
        description = "Detects patterns targeting Launch Constraints bypass for privilege escalation"
        severity = "HIGH"
        tags = "adware,privilege"
    strings:
        $lc1 = "com.apple.private.amfi" ascii
        $lc2 = "com.apple.security.cs.allow-unsigned-executable-memory" ascii
    condition:
        any of them
}

rule macos_network_proxy_intercept
{
    meta:
        description = "Detects HTTPS proxy interception used to inject ads"
        severity = "MEDIUM"
        tags = "adware,proxy"
    strings:
        $p1 = "kCFNetworkProxiesHTTPS" ascii
        $p2 = "CFNetworkCopySystemProxySettings" ascii
        $p3 = "SecCertificateAddToKeychain" ascii
    condition:
        2 of them
}
