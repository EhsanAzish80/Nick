// Nick YARA Rules — macOS Ransomware
// Detects file encryption loops, ransom note patterns, and backup deletion.

rule macos_ransom_note
{
    meta:
        description = "Detects ransom note strings embedded in binaries"
        severity = "HIGH"
        tags = "ransomware,note"
    strings:
        $n1 = "HOW_TO_DECRYPT" ascii nocase
        $n2 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase
        $n3 = "DECRYPT_INSTRUCTIONS" ascii nocase
        $n4 = "bitcoin" ascii nocase
        $n5 = "YOUR_DATA_IS_LOCKED" ascii nocase
    condition:
        any of ($n1, $n2, $n3, $n5) or (2 of them)
}

rule macos_backup_deletion
{
    meta:
        description = "Detects Time Machine and local snapshot deletion used by ransomware"
        severity = "HIGH"
        tags = "ransomware,backup"
    strings:
        $snap1 = "deleteLocalSnapshots" ascii
        $snap2 = "tmutil deletelocalsnapshots" ascii
        $snap3 = "tmutil removesnapshot" ascii
    condition:
        any of them
}

rule macos_mass_file_rename
{
    meta:
        description = "Detects bulk file rename patterns combined with encryption indicatores"
        severity = "HIGH"
        tags = "ransomware,encryption"
    strings:
        $ren1 = "moveItemAtURL" ascii
        $ren2 = ".locked" ascii
        $ren3 = ".encrypted" ascii
        $enc1 = "CCCrypt" ascii
        $enc2 = "SecKeyEncrypt" ascii
    condition:
        ($ren1 or $ren2 or $ren3) and ($enc1 or $enc2)
}

rule macos_shadow_copy_delete
{
    meta:
        description = "Detects deletion of VSS shadow copies (cross-platform ransomware)"
        severity = "HIGH"
        tags = "ransomware,vss"
    strings:
        $vss1 = "vssadmin delete shadows" ascii nocase
        $vss2 = "wmic shadowcopy delete" ascii nocase
    condition:
        any of them
}
