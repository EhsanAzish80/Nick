// Nick YARA Rules — macOS backdoor and persistence behaviour
//
// class = "behavior": see macos_stealers.yar.

rule macos_reverse_shell
{
    meta:
        description = "Interactive shell wired to a network socket"
        class = "behavior"
        severity = "HIGH"
        tags = "backdoor,shell"
    strings:
        $sock1 = "/dev/tcp/" ascii
        $sock2 = "nc -e /bin/" ascii nocase
        $sock3 = "socat exec:" ascii nocase
        $sock4 = "mkfifo /tmp/" ascii
        $int1  = "/bin/bash -i" ascii
        $int2  = "/bin/sh -i" ascii
        $int3  = "/bin/zsh -i" ascii
        $int4  = "0>&1" ascii
        $int5  = "pty.spawn(" ascii
    condition:
        1 of ($sock*) and 1 of ($int*)
}

rule macos_launchagent_install
{
    meta:
        description = "Programmatic LaunchAgent installation for persistence"
        class = "behavior"
        severity = "MEDIUM"
        tags = "persistence,launchagent"
    strings:
        $la1 = "Library/LaunchAgents/" ascii
        $la2 = "launchctl load" ascii
        $la3 = "launchctl bootstrap" ascii
        $la4 = "RunAtLoad" ascii
        $la5 = "ProgramArguments" ascii
    condition:
        $la1 and ($la2 or $la3) and ($la4 or $la5)
}

rule macos_ptrace_antidebug
{
    meta:
        description = "Inline ptrace(PT_DENY_ATTACH) system call that bypasses libc"
        class = "behavior"
        severity = "MEDIUM"
        tags = "backdoor,antidebug"
    strings:
        // arm64: mov x0, #0x1f ; ... mov x16, #0x1a ; ... svc #0x80 (either order)
        $arm_a = { E0 03 80 D2 [0-12] 50 03 80 D2 [0-12] 01 10 00 D4 }
        $arm_b = { 50 03 80 D2 [0-12] E0 03 80 D2 [0-12] 01 10 00 D4 }
        // x86_64: mov edi, 0x1f ; ... mov eax, 0x200001a ; ... syscall
        $x64_a = { BF 1F 00 00 00 [0-16] B8 1A 00 00 02 [0-8] 0F 05 }
        $x64_b = { B8 1A 00 00 02 [0-16] BF 1F 00 00 00 [0-8] 0F 05 }
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA)
        and any of them
}

rule macos_dylib_injection
{
    meta:
        description = "DYLD environment injection strings (also present in sanitizers and dev tools)"
        class = "behavior"
        severity = "LOW"
        tags = "backdoor,injection"
    strings:
        $d1 = "DYLD_INSERT_LIBRARIES" ascii
        $d2 = "DYLD_FORCE_FLAT_NAMESPACE" ascii
    condition:
        $d1 and $d2
}
