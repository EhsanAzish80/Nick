// Nick bundled family signatures — https://github.com/Neo23x0/signature-base
//
// Retrieved through YARA Forge release 20260920 (https://github.com/YARAHQ/yara-forge)
// and selected by Scripts/import_family_rules.py.
//
// License: DRL-1.1 (https://github.com/SigmaHQ/Detection-Rule-License). Full text: Rules/families/LICENSES/neo23x0.txt
// Rule authorship and references are preserved in each rule's metadata.

rule SIGNATURE_BASE_APT_MAL_Macos_NK_3CX_Malicious_Samples_Mar23_1 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_mal_3cx_compromise_mar23.yar#L168-L184"
		license = "DRL-1.1"
		description = "Detects malicious macOS application related to 3CX compromise (decrypted payload)"
		author = "Florian Roth (Nextron Systems)"
		id = "ff39e577-7063-5025-bead-68394a86c87c"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_mal_3cx_compromise_mar23.yar#L168-L184"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb"
		hash = "ac99602999bf9823f221372378f95baa4fc68929bac3a10e8d9a107ec8074eca"
		hash = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"
		logic_hash = "c2733c2f7dcca82e5a0b2301777fb54853d04dfa893bcf88ecbec34d37e1a38a"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "20230313064152Z0"
		$s2 = "Developer ID Application: 3CX (33CF4654HL)"

	condition:
		( uint16( 0 ) == 0xfeca or uint16( 0 ) == 0xfacf or uint32( 0 ) == 0xbebafeca ) and all of them
}

rule SIGNATURE_BASE_APT_MAL_Macos_NK_3CX_DYLIB_Mar23_1
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_mal_3cx_compromise_mar23.yar#L188-L214"
		license = "DRL-1.1"
		description = "Detects malicious DYLIB files related to 3CX compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "a19904d3-9b2d-561f-b734-20bf09584fa7"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_mal_3cx_compromise_mar23.yar#L188-L214"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		hash = "fee4f9dabc094df24d83ec1a8c4e4ff573e5d9973caa676f58086c99561382d7"
		logic_hash = "e52c76de1e995cc7084ddb390b60f4bc66e5bdf89aaa28ef3fd70578ed3145a6"
		score = 80
		quality = 85
		tags = ""

	strings:
		$xc1 = { 37 15 00 13 16 16 1B 55 4F 54 4A 5A 52 2D 13 14 
               1E 15 0D 09 5A 34 2E 5A 4B 4A 54 4A 41 5A 2D 13
               14 4C 4E 41 5A 02 4C 4E 53 5A 3B 0A 0A 16 1F 2D
               1F 18 31 13 0E 55 4F 49 4D 54 49 4C 5A 52 31 32
               2E 37 36 56 5A 16 13 11 1F 5A 3D 1F 19 11 15 53
               5A 39 12 08 15 17 1F 55 4B 4A 42 54 4A 54 4F 49
               4F 43 54 4B 48 42 5A 29 1B 1C 1B 08 13 55 4F 49
               4D 54 49 4C 7A }
		$xc2 = { 41 49 19 02 25 1b 0f 0e 12 25 0e 15 11 1f 14 25 19 15 14 0e 1f 14 0e 47 5f 09 41 25 25 0e 0f 0e 17 1b 47 }
		$xc3 = { 55 29 03 09 0e 1f 17 55 36 13 18 08 1b 08 03 55 39 15 08 1f 29 1f 08 0c 13 19 1f 09 55 29 03 09 0e 1f 17 2c 1f 08 09 13 15 14 54 0a 16 13 09 0e }

	condition:
		1 of them
}

rule SIGNATURE_BASE_MAL_3Cxdesktopapp_Macos_Backdoor_Mar23 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_mal_3cx_compromise_mar23.yar#L251-L275"
		license = "DRL-1.1"
		description = "Detects 3CXDesktopApp MacOS Backdoor component"
		author = "X__Junior (Nextron Systems)"
		id = "80046c8e-0c2a-5885-b140-a6084f48160d"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2023/03/30/3cx-supply-chain-compromise-leads-to-iconic-incident/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_mal_3cx_compromise_mar23.yar#L251-L275"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		logic_hash = "777a0a29c376f3697021dd627e716c31bda7933c5f40a8fe79b80e3cea46ce43"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$sa1 = "%s/.main_storage" ascii fullword
		$sa2 = "%s/UpdateAgent" ascii fullword
		$op1 = { 31 C0 41 80 34 06 ?? 48 FF C0 48 83 F8 ?? 75 ?? BE ?? ?? ?? ?? BA ?? ?? ?? ?? 4C 89 F7 48 89 D9 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 89 F7 5B 41 5E 41 5F E9 ?? ?? ?? ?? 5B 41 5E 41 5F C3}
		$op2 = { 0F 11 84 24 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 31 C0 80 B4 04 ?? ?? ?? ?? ?? 48 FF C0}

	condition:
		(( uint16( 0 ) == 0xfeca or uint16( 0 ) == 0xfacf or uint32( 0 ) == 0xbebafeca ) and filesize < 6MB and ( ( 1 of ( $sa* ) and 1 of ( $op* ) ) or all of ( $sa* ) ) ) or ( all of ( $op* ) )
}

rule SIGNATURE_BASE_APT_MAL_NK_3CX_Macos_Elextron_App_Mar23_1 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_mal_3cx_compromise_mar23.yar#L306-L328"
		license = "DRL-1.1"
		description = "Detects macOS malware used in the 3CX incident"
		author = "Florian Roth (Nextron Systems)"
		id = "7a3755d4-37e5-5d3b-93aa-34edb557f2d5"
		date = "2023-03-31"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_mal_3cx_compromise_mar23.yar#L306-L328"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"
		hash = "f7ba7f9bf608128894196cf7314f68b78d2a6df10718c8e0cd64dbe3b86bc730"
		logic_hash = "00dd28c3edd94e04e35ee9e3a43c30b5a0a1ad21ec8ecf2099bbeb9de2fca8d0"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "com.apple.security.cs.allow-unsigned-executable-memory" ascii
		$a2 = "com.electron.3cx-desktop-app" ascii fullword
		$s1 = "s8T/RXMlALbXfowom9qk15FgtdI=" ascii
		$s2 = "o8NQKPJE6voVZUIGtXihq7lp0cY=" ascii

	condition:
		uint16( 0 ) == 0xfacf and filesize < 400KB and ( all of ( $a* ) and 1 of ( $s* ) )
}

rule SIGNATURE_BASE_MAL_3Cxdesktopapp_Macos_Updateagent_Mar23 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_mal_3cx_compromise_mar23.yar#L330-L354"
		license = "DRL-1.1"
		description = "Detects 3CXDesktopApp MacOS UpdateAgent backdoor component"
		author = "Florian Roth (Nextron Systems)"
		id = "596eb6d0-f96f-5106-ae67-9372d238e4cf"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://twitter.com/patrickwardle/status/1641692164303515653?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_mal_3cx_compromise_mar23.yar#L330-L354"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "9e9a5f8d86356796162cee881c843cde9eaedfb3"
		logic_hash = "0818a8f0b59a9baaefaa0b505f8261e0e0df283e79da8e95dc71e9afdca224ab"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "/3CX Desktop App/.main_storage" ascii
		$x1 = ";3cx_auth_token_content=%s;__tutma=true"
		$s1 = "\"url\": \"https://"
		$s3 = "/dev/null"
		$s4 = "\"AccountName\": \""

	condition:
		uint16( 0 ) == 0xfeca and filesize < 6MB and ( 1 of ( $x* ) or ( $a1 and all of ( $s* ) ) ) or all of them
}

rule SIGNATURE_BASE_APT_MAL_APT27_Rshell_Jul24 : MALWARE RSHELL___SYSUPDATE FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_apt27_rshell.yar#L2-L41"
		license = "DRL-1.1"
		description = "YARA rule to detect RSHELL of APT27"
		author = "Bundesamt fuer Verfassungsschutz, modified by Florian Roth"
		id = "67c8ac4e-8e2f-5cca-90cb-5d5fdf6f86b5"
		date = "2024-07-11"
		modified = "2024-12-12"
		reference = "https://x.com/bfv_bund/status/1811364839656185985?s=12&t=C0_T_re0wRP_NfKa27Xw9w"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_apt27_rshell.yar#L2-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "0433edfad648e1e29be54101abaded690302dc7e49ad916cfbbddf99b3ade12c"
		hash = "10bb89fdf25c88d3c5623e8d68573124c9a42549750014e3675e2ca342aeba4a"
		hash = "2603e1f61363451891c97b0c4ce8acfbfb680d3df4282f9d151ecce3a5679616"
		hash = "70dac42491f8f19568a5d7b1d10b29f732a88d75e7f2bfa07b23202bacadf56f"
		hash = "b988a6583ce40f07e5fc8e890ae2b1c84a93db8a2e3ca8769241b94bea332a7a"
		hash = "c4fe1e56f601d411e2385352606524fb8bbf773bc2ba14889a8de605c2d14da0"
		hash = "c787144d285fcca8a542f7a5525a37bcd089b39068b9a4db7fe3554ee6c08301"
		hash = "ddaa4d23e4651a517fffbd29f0924607ba6b6253171144da5e49237afe91666b"
		logic_hash = "be5f6281d722bd07e53acd459c794fe3ae870a05ed8979de4c28d357110617bd"
		score = 75
		quality = 85
		tags = "MALWARE, RSHELL / SYSUPDATE, FILE"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		malware = "RSHELL / SYSUPDATE"

	strings:
		$a1 = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%" ascii
		$a2 = "/proc/self/exe" ascii
		$s1 = "HISTFILE" ascii fullword
		$s2 = "/tmp/guid" ascii fullword
		$sop1 = { e8 ?? ?? ?? ?? c7 43 04 00 00 00 00 8b 3b 85 ff 7e 2? e8 ?? ?? 0? 00 85 c0 7e 0? }
		$sop2 = { c7 43 04 00 00 00 00 8b 3b 85 ff 7e 2? e8 ?? ?? 0? 00 85 c0 7e 0? f7 d8 }

	condition:
		( uint32be( 0 ) == 0x7f454c46 or ( uint32be( 0 ) == 0xcafebabe and uint32be( 4 ) < 0x20 ) or uint32( 0 ) == 0xfeedface or uint32( 0 ) == 0xfeedfacf ) and filesize < 2MB and all of ( $a* ) and 2 of ( $s* ) or 3 of ( $s* )
}

rule SIGNATURE_BASE_MAL_RANSOM_LNX_Macos_Lockbit_Apr23_1 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/mal_lockbit_lnx_macos_apr23.yar#L2-L41"
		license = "DRL-1.1"
		description = "Detects LockBit ransomware samples for Linux and macOS"
		author = "Florian Roth"
		id = "c01cb907-7d30-5487-b908-51f69ddb914c"
		date = "2023-04-15"
		modified = "2023-12-05"
		reference = "https://twitter.com/malwrhunterteam/status/1647384505550876675?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/mal_lockbit_lnx_macos_apr23.yar#L2-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "0a2bffa0a30ec609d80591eef1d0994d8b37ab1f6a6bad7260d9d435067fb48e"
		hash = "9ebcbaf3c9e2bbce6b2331238ab584f95f7ced326ca4aba2ddcc8aa8ee964f66"
		hash = "a405d034c01a357a89c9988ffe8a46a165915df18fd297469b2bcaaf97578442"
		hash = "c9cac06c9093e9026c169adc3650b018d29c8b209e3ec511bbe34cbe1638a0d8"
		hash = "dc3d08480f5e18062a0643f9c4319e5c3f55a2e7e93cd8eddd5e0c02634df7cf"
		hash = "e77124c2e9b691dbe41d83672d3636411aaebc0aff9a300111a90017420ff096"
		hash = "0be6f1e927f973df35dad6fc661048236d46879ad59f824233d757ec6e722bde"
		hash = "3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"
		logic_hash = "6d838e8b207b97d7c335dc4066de2c6dc87f7adc9cac31742677edbe85386cf7"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "restore-my-files.txt" ascii fullword
		$s1 = "ntuser.dat.log" ascii fullword
		$s2 = "bootsect.bak" ascii fullword
		$s3 = "autorun.inf" ascii fullword
		$s4 = "lockbit" ascii fullword
		$xc1 = { 33 38 36 00 63 6D 64 00 61 6E 69 00 61 64 76 00 6D 73 69 00 6D 73 70 00 63 6F 6D 00 6E 6C 73 }
		$xc2 = { 6E 74 6C 64 72 00 6E 74 75 73 65 72 2E 64 61 74 2E 6C 6F 67 00 62 6F 6F 74 73 65 63 74 2E 62 61 6B }
		$xc3 = { 76 6D 2E 73 74 61 74 73 2E 76 6D 2E 76 5F 66 72 65 65 5F 63 6F 75 6E 74 00 61 2B 00 2F 2A }
		$op1 = { 84 e5 f0 00 f0 e7 10 40 2d e9 2e 10 a0 e3 00 40 a0 e1 ?? fe ff }
		$op2 = { 00 90 a0 e3 40 20 58 e2 3f 80 08 e2 3f 30 c2 e3 09 20 98 e1 08 20 9d }
		$op3 = { 2d e9 01 70 43 e2 07 00 13 e1 01 60 a0 e1 08 d0 4d e2 02 40 }

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16( 0 ) == 0xfeca or uint16( 0 ) == 0xfacf or uint32( 0 ) == 0xbebafeca ) and ( 1 of ( $x* ) or 3 of them ) or 2 of ( $x* ) or 5 of them
}

rule SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/mal_lockbit_lnx_macos_apr23.yar#L43-L67"
		license = "DRL-1.1"
		description = "Detects indicators found in LockBit ransomware"
		author = "Florian Roth"
		id = "75dc8b95-16f0-5170-a7d6-fc10bb778348"
		date = "2023-04-17"
		modified = "2023-12-05"
		reference = "https://objective-see.org/blog/blog_0x75.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/mal_lockbit_lnx_macos_apr23.yar#L43-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		logic_hash = "cd5bffa5571abfd1446b065d26c8c23f00fe1376d505af539c6f37356014a86f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$xe1 = "-i '/path/to/crypt'" xor
		$xe2 = "http://lockbit" xor
		$s1 = "idelayinmin" ascii
		$s2 = "bVMDKmode" ascii
		$s3 = "bSelfRemove" ascii
		$s4 = "iSpotMaximum" ascii
		$fp1 = "<html"

	condition:
		(1 of ( $x* ) or 4 of them ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_MAL_RANSOM_Lockbit_Locker_LOG_Apr23_1
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/mal_lockbit_lnx_macos_apr23.yar#L69-L84"
		license = "DRL-1.1"
		description = "Detects indicators found in LockBit ransomware log files"
		author = "Florian Roth"
		id = "aa0a2393-e5a2-5151-8afb-91a9bb922179"
		date = "2023-04-17"
		modified = "2023-12-05"
		reference = "https://objective-see.org/blog/blog_0x75.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/mal_lockbit_lnx_macos_apr23.yar#L69-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		logic_hash = "d5f96e601150209382d3f6458863bc79768beb99b587aa8d9ba37cb2c11ef634"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = " is encrypted. Checksum after encryption "
		$s2 = "~~~~~Hardware~~~~"
		$s3 = "[+] Add directory to encrypt:"
		$s4 = "][+] Launch parameters: "

	condition:
		2 of them
}

rule SIGNATURE_BASE_MAL_RANSOM_Lockbit_Forensicartifacts_Apr23_1
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/mal_lockbit_lnx_macos_apr23.yar#L86-L101"
		license = "DRL-1.1"
		description = "Detects forensic artifacts found in LockBit intrusions"
		author = "Florian Roth"
		id = "e716030c-ee78-51dc-919c-cf59e93da976"
		date = "2023-04-17"
		modified = "2023-12-05"
		reference = "https://objective-see.org/blog/blog_0x75.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/mal_lockbit_lnx_macos_apr23.yar#L86-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		logic_hash = "81021f8c9aed17c007d7329a598c644a706fa9750818c8974984eefcba8d06c2"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = "/tmp/locker.log" ascii fullword
		$x2 = "Executable=LockBit/locker_" ascii
		$xc1 = { 54 6F 72 20 42 72 6F 77 73 65 72 20 4C 69 6E 6B 73 3A 0D 0A 68 74 74 70 3A 2F 2F 6C 6F 63 6B 62 69 74 }

	condition:
		1 of ( $x* )
}

rule SIGNATURE_BASE_APT_Equation_Group_Op_Triangulation_Triangledb_Implant_Jun23_1 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_eqgrp_triangulation_jun23.yar#L2-L18"
		license = "DRL-1.1"
		description = "Detects TriangleDB implant found being used in Operation Triangulation on iOS devices (maybe also used on macOS systems)"
		author = "Florian Roth"
		id = "d81a5103-41c8-5dba-a560-8fb5514f6c0a"
		date = "2023-06-21"
		modified = "2023-12-05"
		reference = "https://securelist.com/triangledb-triangulation-implant/110050/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_eqgrp_triangulation_jun23.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		logic_hash = "486b19ddb8b182dbba882359f7eb416735e76f9cda5aea1b290fb5c6b44960c5"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "unmungeHexString" ascii fullword
		$s2 = "CRPwrInfo" ascii fullword
		$s3 = "CRConfig" ascii fullword
		$s4 = "CRXConfigureDBServer" ascii fullword

	condition:
		( uint16( 0 ) == 0xfacf and filesize < 30MB and $s1 and 2 of them ) or all of them
}

rule SIGNATURE_BASE_MAL_Sindoor_Decryptor_Aug25 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_apt36_operation_sindoor.yar#L38-L63"
		license = "DRL-1.1"
		description = "Detects AES decryptor used by Sindoor dropper related to APT 36"
		author = "Pezier Pierre-Henri"
		id = "3c0c5217-b125-51a3-8129-30af5f0c7263"
		date = "2025-08-29"
		modified = "2026-05-15"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_apt36_operation_sindoor.yar#L38-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "9a1adb50bb08f5a28160802c8f315749b15c9009f25aa6718c7752471db3bb4b"
		logic_hash = "4172fd9aee39a1a0681483f6dada6394debc62149a588ab4807e3016a823bed3"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Go build"
		$s2 = "main.rc4EncryptDecrypt"
		$s3 = "main.processFile"
		$s4 = "main.deriveKeyAES"
		$s5 = "use RC4 instead of AES"

	condition:
		filesize < 100MB and ( uint16( 0 ) == 0x5a4d or uint32be( 0 ) == 0x7f454c46 or ( uint32be( 0 ) == 0xcafebabe and uint32be( 4 ) < 0x20 ) or uint32( 0 ) == 0xfeedface or uint32( 0 ) == 0xfeedfacf ) and all of them
}

rule SIGNATURE_BASE_MAL_Sindoor_Downloader_Aug25 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_apt36_operation_sindoor.yar#L65-L90"
		license = "DRL-1.1"
		description = "Detects Sindoor downloader related to APT 36"
		author = "Pezier Pierre-Henri"
		id = "c1188abc-2bea-5cbc-a39d-9690626c0821"
		date = "2025-08-29"
		modified = "2026-05-15"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_apt36_operation_sindoor.yar#L65-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "38b6b93a536cbab5c289fe542656d8817d7c1217ad75c7f367b15c65d96a21d4"
		logic_hash = "c55be65cd077cb04b625636dffcb02af74efa06bb49da734c8616da233a34d1a"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Go build"
		$s2 = "main.downloadFile.deferwrap"
		$s3 = "main.decrypt"
		$s4 = "main.HiddenHome"
		$s5 = "main.RealCheck"

	condition:
		filesize < 100MB and ( uint16( 0 ) == 0x5a4d or uint32be( 0 ) == 0x7f454c46 or ( uint32be( 0 ) == 0xcafebabe and uint32be( 4 ) < 0x20 ) or uint32( 0 ) == 0xfeedface or uint32( 0 ) == 0xfeedfacf ) and all of them
}

rule SIGNATURE_BASE_EXT_APT32_Osx_Backdoor_Loader : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_apt32.yar#L22-L49"
		license = "DRL-1.1"
		description = "Detects APT32 backdoor loader on OSX"
		author = "Facebook"
		id = "ac313bd8-bf15-5b72-b651-35015f71dd90"
		date = "2021-02-25"
		modified = "2023-12-05"
		reference = "https://about.fb.com/news/2020/12/taking-action-against-hackers-in-bangladesh-and-vietnam/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_apt32.yar#L22-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "768510fa9eb807bba9c3dcb3c7f87b771e20fa3d81247539e9ea4349205e39eb"
		logic_hash = "26964f95a9298b838e06fb9d7f739c8b87a976d8da7fb08416e952d26e84b84e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = { 00 D2 44 8A 04 0F 44 88 C0 C0 E8 07 08 D0 88 44 0F FF 48 FF C1 48 83 F9 10 44 88 C2 }
		$a2 = { 41 0F 10 04 07 0F 57 84 05 A0 FE FF FF 41 0F 11 04 07 48 83 C0 10 48 83 F8 10 75 }
		$e1 = { CA CF 3E F2 DA 43 E6 D1  D5 6C D4 23 3A AE F1 B2 }
		$e2 = "MlkHVdRbOkra9s+G65MAoLga340t3+zj/u8LPfP3hig="
		$e3 = { 5A 69 98 0E 6C 4B 5C 69  7E 19 34 3B C3 07 CA 13 }
		$e4 = "1Sib4HfPuRQjpxIpECnxxTPiu3FXOFAHMx/+9MEVv9M+h1ngV7T5WUP3b0zsg0Qd"
		$e5 = "_ArchaeologistCodeine"
		$e6 = "_PlayerAberadurtheIncomprehensible"

	condition:
		(( uint32( 0 ) == 0xfeedface or uint32be( 0 ) == 0xfeedface ) or ( uint32( 0 ) == 0xfeedfacf or uint32be( 0 ) == 0xfeedfacf ) ) and ( 2 of ( $e* ) or all of ( $a* ) )
}

rule SIGNATURE_BASE_MAL_OSX_Fancybear_Agent_Jul18_1 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_fancybear_osxagent.yar#L1-L20"
		license = "DRL-1.1"
		description = "Detects FancyBear Agent for OSX"
		author = "Florian Roth (Nextron Systems)"
		id = "ae717f70-7196-561a-916f-1598ab38c77a"
		date = "2018-07-15"
		modified = "2023-12-05"
		reference = "https://twitter.com/DrunkBinary/status/1018448895054098432"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_fancybear_osxagent.yar#L1-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "d3be93f6ce59b522ff951cef9d59ef347081ffe33d4203cd5b5df0aaa9721aa2"
		logic_hash = "099235424f22f3591a891726ea0c13ebf831fae0456ab1b6baba329c090a9535"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "/Users/kazak/Desktop/" ascii
		$s1 = "launchctl load -w ~/Library/LaunchAgents/com.apple.updates.plist" fullword ascii
		$s2 = "mkdir -p /Users/Shared/.local/ &> /dev/null" fullword ascii
		$s3 = "chmod 755 /Users/Shared/start.sh" fullword ascii
		$s4 = "chmod 755 %s/%s &> /dev/null" fullword ascii
		$s6 = "chmod 755 /Users/Shared/.local/kextd" fullword ascii

	condition:
		uint16( 0 ) == 0xfacf and filesize < 3000KB and ( 1 of ( $x* ) and 4 of them )
}

rule SIGNATURE_BASE_OSX_Backdoor_Evilosx : FILE
{
	meta:
		class = "behavior"
		severity = "MEDIUM"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_osx_evilosx.yar#L1-L34"
		license = "DRL-1.1"
		description = "EvilOSX MacOS/OSX backdoor"
		author = "John Lambert @JohnLaTwC"
		id = "6940e355-53d2-51e3-afd0-13303a311e9a"
		date = "2018-02-23"
		modified = "2023-12-05"
		reference = "https://github.com/Marten4n6/EvilOSX, https://twitter.com/JohnLaTwC/status/966139336436498432"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_osx_evilosx.yar#L1-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "89e5b8208daf85f549d9b7df8e2a062e47f15a5b08462a4224f73c0a6223972a"
		logic_hash = "393abf7cf74f8d079049cf8f0bdb3a79bf16185c80c43b823e19b67a9031aef6"
		score = 75
		quality = 60
		tags = "FILE"

	strings:
		$h1 = "#!/usr/bin/env"
		$s0 = "import base64" fullword ascii
		$s1 = "b64decode" fullword ascii
		$x0 = "EvilOSX" fullword ascii
		$x1 = "get_launch_agent_directory" fullword ascii
		$enc_x0 = /(AHYAaQBsAE8AUwBYA|dmlsT1NY|RQB2AGkAbABPAFMAWA|RXZpbE9TW|UAdgBpAGwATwBTAFgA|V2aWxPU1)/ ascii
		$enc_x1 = /(AGUAdABfAGwAYQB1AG4AYwBoAF8AYQBnAGUAbgB0AF8AZABpAHIAZQBjAHQAbwByAHkA|cAZQB0AF8AbABhAHUAbgBjAGgAXwBhAGcAZQBuAHQAXwBkAGkAcgBlAGMAdABvAHIAeQ|dldF9sYXVuY2hfYWdlbnRfZGlyZWN0b3J5|Z2V0X2xhdW5jaF9hZ2VudF9kaXJlY3Rvcn|ZwBlAHQAXwBsAGEAdQBuAGMAaABfAGEAZwBlAG4AdABfAGQAaQByAGUAYwB0AG8AcgB5A|ZXRfbGF1bmNoX2FnZW50X2RpcmVjdG9ye)/ ascii

	condition:
		uint32( 0 ) == 0x752f2123 and $h1 at 0 and filesize < 30KB and all of ( $s* ) and 1 of ( $x* ) or 1 of ( $enc_x* )
}

rule SIGNATURE_BASE_OSX_Backdoor_Bella : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_osx_backdoor_bella.yar#L2-L42"
		license = "DRL-1.1"
		description = "Bella MacOS/OSX backdoor"
		author = "John Lambert @JohnLaTwC"
		id = "d2a994f9-acff-5de4-8f70-453b5d4d7947"
		date = "2018-02-23"
		modified = "2023-12-05"
		reference = "https://twitter.com/JohnLaTwC/status/911998777182924801"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_osx_backdoor_bella.yar#L2-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "4288a81779a492b5b02bad6e90b2fa6212fa5f8ee87cc5ec9286ab523fc02446 cec7be2126d388707907b4f9d681121fd1e3ca9f828c029b02340ab1331a5524 e1cf136be50c4486ae8f5e408af80b90229f3027511b4beed69495a042af95be"
		logic_hash = "c2fa72072decd850698fbaaa9c2a6687cdf64e6bac068ff52a97963053db4339"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$h1 = "#!/usr/bin/env"
		$s0 = "subprocess" fullword ascii
		$s1 = "import sys" fullword ascii
		$s2 = "shutil" fullword ascii
		$p0 = "create_bella_helpers" fullword ascii
		$p1 = "is_there_SUID_shell" fullword ascii
		$p2 = "BELLA IS NOW RUNNING" fullword ascii
		$p3 = "SELECT * FROM bella WHERE id" fullword ascii
		$subpart1_a = "inject_payloads" fullword ascii
		$subpart1_b = "check_if_payloads" fullword ascii
		$subpart1_c = "updateDB" fullword ascii
		$subpart2_a = "appleIDPhishHelp" fullword ascii
		$subpart2_b = "appleIDPhish" fullword ascii
		$subpart2_c = "iTunes" fullword ascii

	condition:
		uint32( 0 ) == 0x752f2123 and $h1 at 0 and filesize < 120KB and @s0 [ 1 ] < 100 and @s1 [ 1 ] < 100 and @s2 [ 1 ] < 100 and 1 of ( $p* ) or all of ( $subpart1_* ) or all of ( $subpart2_* )
}

rule SIGNATURE_BASE_Persistence_Agent_Macos : FILE
{
	meta:
		class = "behavior"
		severity = "MEDIUM"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_osx_pyagent_persistence.yar#L1-L40"
		license = "DRL-1.1"
		description = "Detects a Python agent that establishes persistence on macOS"
		author = "John Lambert @JohnLaTwC"
		id = "9c69af3c-ee85-58ac-8b78-66760addc117"
		date = "2018-02-24"
		modified = "2023-12-05"
		reference = "https://ghostbin.com/paste/mz5nf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/gen_osx_pyagent_persistence.yar#L1-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "4288a81779a492b5b02bad6e90b2fa6212fa5f8ee87cc5ec9286ab523fc02446 cec7be2126d388707907b4f9d681121fd1e3ca9f828c029b02340ab1331a5524 e1cf136be50c4486ae8f5e408af80b90229f3027511b4beed69495a042af95be"
		logic_hash = "2613fcb32cbdbb24df6c48fcb5d16549783e50246d2cdb8c473375644dd88254"
		score = 75
		quality = 58
		tags = "FILE"

	strings:
		$h1 = "#!/usr/bin/env python"
		$s_1 = "<plist" ascii fullword
		$s_2 = "ProgramArguments" ascii fullword
		$s_3 = "Library" ascii fullword
		$sinterval_1 = "StartInterval" ascii fullword
		$sinterval_2 = "RunAtLoad" ascii fullword
		$e_1 = /(AHAAbABpAHMAdA|cGxpc3|PABwAGwAaQBzAHQA|PHBsaXN0|wAcABsAGkAcwB0A|xwbGlzd)/ ascii
		$e_2 = /(AAcgBvAGcAcgBhAG0AQQByAGcAdQBtAGUAbgB0AHMA|AHIAbwBnAHIAYQBtAEEAcgBnAHUAbQBlAG4AdABzA|Byb2dyYW1Bcmd1bWVudH|cm9ncmFtQXJndW1lbnRz|UAByAG8AZwByAGEAbQBBAHIAZwB1AG0AZQBuAHQAcw|UHJvZ3JhbUFyZ3VtZW50c)/ ascii
		$e_4 = /(AGkAYgByAGEAcgB5A|aWJyYXJ5|TABpAGIAcgBhAHIAeQ|TGlicmFye|wAaQBiAHIAYQByAHkA|xpYnJhcn)/ ascii
		$einterval_a = /(AHQAYQByAHQASQBuAHQAZQByAHYAYQBsA|dGFydEludGVydmFs|MAdABhAHIAdABJAG4AdABlAHIAdgBhAGwA|N0YXJ0SW50ZXJ2YW|U3RhcnRJbnRlcnZhb|UwB0AGEAcgB0AEkAbgB0AGUAcgB2AGEAbA)/ ascii
		$einterval_b = /(AHUAbgBBAHQATABvAGEAZA|dW5BdExvYW|IAdQBuAEEAdABMAG8AYQBkA|J1bkF0TG9hZ|UgB1AG4AQQB0AEwAbwBhAGQA|UnVuQXRMb2Fk)/ ascii

	condition:
		uint32( 0 ) == 0x752f2123 and $h1 at 0 and filesize < 120KB and ( ( all of ( $s_* ) and 1 of ( $sinterval* ) ) or ( all of ( $e_* ) and 1 of ( $einterval* ) ) )
}

rule SIGNATURE_BASE_Snaketurla_Malware_May17_1 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_snaketurla_osx.yar#L11-L25"
		license = "DRL-1.1"
		description = "Detects Snake / Turla Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "ddbbd602-b7f0-5e14-be0f-0c84bb22ddeb"
		date = "2017-05-04"
		modified = "2023-01-06"
		reference = "https://goo.gl/QaOh4V"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_snaketurla_osx.yar#L11-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "5b7792a16c6b7978fca389882c6aeeb2c792352076bf6a064e7b8b90eace8060"
		logic_hash = "12b18c9e03f1a471541de2fb3ecc6b90a13910ca299a9b7d2bad9dd11f881506"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "/Users/vlad/Desktop/install/install/" ascii

	condition:
		( uint16( 0 ) == 0xfacf and filesize < 200KB and all of them )
}

rule SIGNATURE_BASE_Snaketurla_Malware_May17_2 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_snaketurla_osx.yar#L27-L42"
		license = "DRL-1.1"
		description = "Detects Snake / Turla Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "b3e94016-591c-5e39-b5e7-328e0761e535"
		date = "2017-05-04"
		modified = "2023-12-05"
		reference = "https://goo.gl/QaOh4V"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_snaketurla_osx.yar#L27-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "b8ee4556dc09b28826359b98343a4e00680971a6f8c6602747bd5d723d26eaea"
		logic_hash = "35bd8650afbc515ecd1cef393fd75f9b77a1e31111612227f0f4557fe8b312a7"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "b_openssl: oops - number of mutexes is 0" fullword ascii
		$s2 = "networksetup -get%sproxy Ethernet" fullword ascii
		$s3 = "012A04DECBC441e49C527B2798F54CA7LOG_NAMED_PIPE_NAME" fullword ascii

	condition:
		( uint16( 0 ) == 0xfacf and filesize < 6000KB and all of them )
}

rule SIGNATURE_BASE_Snaketurla_Malware_May17_4 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_snaketurla_osx.yar#L44-L57"
		license = "DRL-1.1"
		description = "Detects Snake / Turla Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "797dedd6-a13e-529f-bae4-4043294672c4"
		date = "2017-05-04"
		modified = "2023-12-05"
		reference = "https://goo.gl/QaOh4V"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_snaketurla_osx.yar#L44-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		hash = "d5ea79632a1a67abbf9fb1c2813b899c90a5fb9442966ed4f530e92715087ee2"
		logic_hash = "7b6aac2313ea7dae572114e92ad0b5437c5be2542853de3b184bef780faee68b"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Install Adobe Flash Player.app/com.adobe.updatePK" fullword ascii

	condition:
		( uint16( 0 ) == 0x4b50 and filesize < 5000KB and all of them )
}

rule SIGNATURE_BASE_Snaketurla_Installd_SH : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_snaketurla_osx.yar#L59-L72"
		license = "DRL-1.1"
		description = "Detects Snake / Turla Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "65a97c0d-5c69-5e58-9a18-10e5684bc218"
		date = "2017-05-04"
		modified = "2023-12-05"
		reference = "https://goo.gl/QaOh4V"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_snaketurla_osx.yar#L59-L72"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		logic_hash = "5b16107434951ddb212996909d53dfbcdae74ed13df6690ce3f6c74258ab4670"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "PIDS=`ps cax | grep installdp" ascii
		$s2 = "${SCRIPT_DIR}/installdp ${FILE}" ascii

	condition:
		( uint16( 0 ) == 0x2123 and filesize < 20KB and all of them )
}

rule SIGNATURE_BASE_Snaketurla_Install_SH : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_snaketurla_osx.yar#L74-L87"
		license = "DRL-1.1"
		description = "Detects Snake / Turla Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "68775c54-46f8-5d44-ba63-6726d2bb8016"
		date = "2017-05-04"
		modified = "2023-12-05"
		reference = "https://goo.gl/QaOh4V"
		source_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/yara/apt_snaketurla_osx.yar#L74-L87"
		license_url = "https://github.com/Neo23x0/signature-base/blob/94a1c48d7ab499879287ff611dfe7f9c56376030/LICENSE"
		logic_hash = "019d20ca6632759cf01962d336c22831edc64b6927d8b27d026b76eb118fce02"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "${TARGET_PATH}/installd.sh" ascii
		$s2 = "$TARGET_PATH2/com.adobe.update.plist" ascii

	condition:
		( uint16( 0 ) == 0x2123 and filesize < 20KB and all of them )
}
