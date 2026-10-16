// Nick YARA Rules — macOS adware behaviour
//
// class = "behavior": see macos_stealers.yar. These capabilities are shared by
// browsers, VPNs, and proxies, so they are LOW/MEDIUM context signals only.

rule macos_browser_extension_inject
{
    meta:
        description = "Writes browser extension manifests (also every Chromium-based app)"
        class = "behavior"
        severity = "LOW"
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
        description = "Modifies system DNS configuration (also VPN clients)"
        class = "behavior"
        severity = "LOW"
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
        description = "References private AMFI entitlements that third-party code cannot legitimately hold"
        class = "behavior"
        severity = "MEDIUM"
        tags = "privilege,amfi"
    strings:
        // Note: com.apple.security.cs.allow-unsigned-executable-memory was
        // removed in 4.6 — it is a standard entitlement of every JIT/Electron app.
        $lc2 = "amfi_get_out_of_my_way" ascii
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA)
        // `com.apple.private.amfi` produced 140 benign matches in Apple binaries. `$lc2` is the
        // concrete AMFI boot-argument bypass and remains independently useful.
        and $lc2
}

rule macos_network_proxy_intercept
{
    meta:
        description = "Installs a certificate and system proxy together (ad injection pattern)"
        class = "behavior"
        severity = "LOW"
        tags = "adware,proxy"
    strings:
        $p1 = "kCFNetworkProxiesHTTPS" ascii
        $p2 = "networksetup -setsecurewebproxy" ascii nocase
        $p3 = "SecCertificateAddToKeychain" ascii
        $p4 = "add-trusted-cert" ascii
    condition:
        ($p1 or $p2) and ($p3 or $p4)
}
