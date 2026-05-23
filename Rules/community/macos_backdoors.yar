// Nick YARA Rules — macOS Backdoors & RATs
// Detects reverse shell indicators and persistence installation patterns.

rule macos_reverse_shell
{
    meta:
        description = "Detects strings associated with interactive reverse shell establishment"
        severity = "HIGH"
        tags = "backdoor,shell"
    strings:
        $sh1 = "/bin/bash -i" ascii
        $sh2 = "/bin/sh -i" ascii
        $sh3 = "mkfifo /tmp/" ascii
        $sh4 = "nc -e /bin/sh" ascii nocase
        $sh5 = "0>&1 2>&1" ascii
    condition:
        any of them
}

rule macos_launchagent_install
{
    meta:
        description = "Detects programmatic LaunchAgent installation for persistence"
        severity = "MEDIUM"
        tags = "persistence,launchagent"
    strings:
        $la1 = "Library/LaunchAgents/" ascii
        $la2 = "launchctl load" ascii
        $la3 = "RunAtLoad" ascii
        $la4 = "ProgramArguments" ascii
    condition:
        $la1 and 2 of ($la2, $la3, $la4)
}

rule macos_ptrace_antidebug
{
    meta:
        description = "Detects PT_DENY_ATTACH anti-debugging technique used by malware"
        severity = "HIGH"
        tags = "backdoor,antidebug"
    strings:
        $pd1 = "PT_DENY_ATTACH" ascii
        $pd2 = { 1F 00 00 00 1F 00 00 00 }
    condition:
        $pd1 or $pd2
}

rule macos_dylib_injection
{
    meta:
        description = "Detects DYLD environment variable abuse for code injection"
        severity = "HIGH"
        tags = "backdoor,injection"
    strings:
        $d1 = "DYLD_INSERT_LIBRARIES" ascii
        $d2 = "DYLD_FORCE_FLAT_NAMESPACE" ascii
    condition:
        $d1 and $d2
}
