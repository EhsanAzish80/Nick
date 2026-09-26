// Nick YARA Rules — macOS ransomware behaviour
//
// class = "behavior": see macos_stealers.yar. Real-time ransomware detection is
// behavioural (canaries, extension-change bursts) and lives in the extension.

rule macos_ransom_note
{
    meta:
        description = "Explicit ransom-note phrases embedded in a file"
        class = "behavior"
        severity = "HIGH"
        tags = "ransomware,note"
    strings:
        $n1 = "HOW_TO_DECRYPT" ascii wide nocase
        $n2 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase
        $n3 = "DECRYPT_INSTRUCTIONS" ascii wide nocase
        $n4 = "YOUR_DATA_IS_LOCKED" ascii wide nocase
        $n5 = "all your files have been encrypted" ascii wide nocase
    condition:
        any of them
}

rule macos_backup_deletion
{
    meta:
        description = "Time Machine local snapshot deletion (also used by disk cleaners)"
        class = "behavior"
        severity = "MEDIUM"
        tags = "ransomware,backup"
    strings:
        $snap1 = "deleteLocalSnapshots" ascii
        $snap2 = "tmutil deletelocalsnapshots" ascii nocase
        $snap3 = "tmutil removesnapshot" ascii nocase
        $snap4 = "tmutil disable" ascii nocase
    condition:
        any of them
}

rule macos_mass_file_rename
{
    meta:
        description = "Encryption primitives combined with ransomware-style output extensions"
        class = "behavior"
        severity = "MEDIUM"
        tags = "ransomware,encryption"
    strings:
        $ren1 = ".locked" ascii
        $ren2 = ".encrypted" ascii
        $enc1 = "CCCrypt" ascii
        $enc2 = "SecKeyEncrypt" ascii
        $enc3 = "EVP_EncryptInit" ascii
        // Crypto libraries (OpenSSL, BoringSSL) contain the strings above;
        // a victim-facing demand is what makes this ransomware-like.
        $note1 = "README_DECRYPT" ascii nocase
        $note2 = "HOW_TO_DECRYPT" ascii nocase
        $note3 = "decrypt your files" ascii nocase
        $note4 = "bitcoin" ascii nocase
    condition:
        1 of ($ren*) and 1 of ($enc*) and 1 of ($note*)
}

rule macos_shadow_copy_delete
{
    meta:
        description = "Windows shadow-copy deletion (cross-platform ransomware)"
        class = "behavior"
        severity = "HIGH"
        tags = "ransomware,vss"
    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "wmic shadowcopy delete" ascii wide nocase
    condition:
        any of them
}
