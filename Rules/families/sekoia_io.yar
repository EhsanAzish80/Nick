// Nick bundled family signatures — https://github.com/SEKOIA-IO/Community
//
// Retrieved through YARA Forge release 20260920 (https://github.com/YARAHQ/yara-forge)
// and selected by Scripts/import_family_rules.py.
//
// License: DRL-1.1 (https://github.com/SigmaHQ/Detection-Rule-License). Full text: Rules/families/LICENSES/sekoia_io.txt
// Rule authorship and references are preserved in each rule's metadata.

rule SEKOIA_Implant_Mac_Rustbucket : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/implant_mac_rustbucket.yar#L1-L21"
		license = "DRL-1.1"
		description = "Detect the RustBucket malware"
		author = "Sekoia.io"
		id = "fcbb745d-7f56-4c51-9db5-427da22a0c68"
		date = "2023-04-24"
		modified = "2024-12-19"
		reference = "https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/implant_mac_rustbucket.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		hash = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
		logic_hash = "ab7bc706b0d3f0dcd739ffe7f8153ba7377892143d8d53ce1591519ffe4ae84f"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "/Users/hero/"
		$ = "PATHIpv6Ipv4Bodyslotpath"
		$macho_magic = {CF FA ED FE}
		$java_magic = {CA FE BA BE}

	condition:
		($macho_magic at 0 or $java_magic at 0 ) and all of them
}

rule SEKOIA_Implant_Macos_Geacon : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/implant_macos_geacon.yar#L1-L35"
		license = "DRL-1.1"
		description = "Finds Geacon samples based on specific strings"
		author = "Sekoia.io"
		id = "a7784bfa-66a7-47df-b88b-d98217d8cca5"
		date = "2024-01-11"
		modified = "2024-12-19"
		reference = "https://www.sentinelone.com/blog/geacon-brings-cobalt-strike-capabilities-to-macos-threat-actors/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/implant_macos_geacon.yar#L1-L35"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "284574d185d3777a373f4a19e0870eec5245fb8ea5ebd6124bc281f8c74e0998"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$gea01 = "geacon/config.init" ascii
		$gea02 = "geacon_pro-master/config/config.go" ascii
		$gea03 = "geacon_plus-main/config/config.go" ascii
		$gea04 = "command type %d is not support by geacon now" ascii
		$gea05 = "main/sysinfo.GeaconID" ascii
		$str01 = "command.StealToken" ascii
		$str02 = "command.MakeToken" ascii
		$str03 = "command/misc.go" ascii
		$str04 = "config/c2profile.go" ascii
		$str05 = "crypt.AesCBCDecrypt" ascii
		$str06 = "packet.File_Browse" ascii
		$str07 = "packet.FirstBlood" ascii
		$str08 = "packet.ParseCommandShell" ascii
		$str09 = "packet.ParseCommandUpload" ascii
		$str10 = "packet.PushResult" ascii
		$str11 = "sysinfo.GetComputerName" ascii
		$str12 = "sysinfo.IsOSX64" ascii
		$str13 = "util..inittask" ascii

	condition:
		uint32( 0 ) == 0xFEEDFACF and ( ( 1 of ( $gea* ) and 2 of ( $str* ) ) or 8 of ( $str* ) )
}

rule SEKOIA_Apt_Kimsuky_Toddlershark_Obfuscated : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_kimsuky_toddlershark_obfuscated.yar#L1-L18"
		license = "DRL-1.1"
		description = "Detects obfuscated version of Kimsuky TODDLERSHARK vbs malware"
		author = "Sekoia.io"
		id = "9ab82466-4f38-4597-b75b-13252e180c70"
		date = "2024-03-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_kimsuky_toddlershark_obfuscated.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "5f067ce32e7fee5cf481d82bb98f4ae10bd7187078bc111b08fc58d043954152"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = { 3a 20 [3-10] 20 3d 20 22 [3-30] 22 3a }
		$s2 = { 45 78 65 63 75 74 65 28  [3-15] 28 22 }
		$s3 = { 50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 [3-15] 28 42 79 56 61 6c 20 [3-15] 29 3a }
		$s4 = "& Chr(\"&H\" & Mid("

	condition:
		#s4== 1 and #s3 == 1 and #s2 == 1 and #s1 > 20 and filesize < 1MB
}

rule SEKOIA_Dropper_Mac_Lazarus_Manuscrypt : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/dropper_mac_lazarus_manuscrypt.yar#L1-L21"
		license = "DRL-1.1"
		description = "MacOS Manuscrypt dropped by TraderTraitor"
		author = "Sekoia.io"
		id = "6138bd0c-1fcf-4586-b2b6-29955c7d6266"
		date = "2022-04-19"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/dropper_mac_lazarus_manuscrypt.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		hash = "dced1acbbe11db2b9e7ae44a617f3c12d6613a8188f6a1ece0451e4cd4205156"
		hash = "9d9dda39af17a37d92b429b68f4a8fc0a76e93ff1bd03f06258c51b73eb40efa"
		logic_hash = "dbe75a34f91906fc275c04af0fc068923993bab37a7574b3fe38733d87f31835"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "networksetup -getwebproxy '%s'" ascii
		$ = "Cookie: _ga=%s%02d%d%d%02d%s" ascii
		$ = "networksetup -listallnetworkservices" ascii
		$ = "gid=%s%02d%d%03d%s" ascii

	condition:
		uint32( 0 ) == 0xFEEDFACF and all of them
}

rule SEKOIA_Implant_Any_Sliver : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/implant_any_sliver.yar#L1-L28"
		license = "DRL-1.1"
		description = "Rule which detects any Sliver implant PE/Dlls/ELFs/MAC-O."
		author = "Sekoia.io"
		id = "4b16f28a-2048-4044-8620-8e7a1651f2b1"
		date = "2021-11-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/implant_any_sliver.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "c7a2790fd13de0476cfe16ef26b2d4c8775f4f453d076c78975e2c372f03322c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.1"
		classification = "TLP:CLEAR"

	strings:
		$s1 = ").GetActiveC2" ascii
		$s2 = ").GetVersion" ascii
		$s3 = ").GetReconnectInterval" ascii
		$s4 = ").GetProxyURL" ascii
		$s5 = ").GetPollInterval" ascii

	condition:
		( uint16be( 0 ) == 0x4d5a or uint32be( 0 ) == 0x7f454c46 or uint32be( 0 ) == 0xcffaedfe ) and ( true and filesize < 11MB and filesize > 7MB ) and ( all of ( $s* ) )
}

rule SEKOIA_Downloader_Mac_Rustbucket_Swiftloader
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/downloader_mac_rustbucket_swiftloader.yar#L1-L19"
		license = "DRL-1.1"
		description = "Detect the file com.EdoneViewer in the new version of RustBucker 2023-10"
		author = "Sekoia.io"
		id = "bdbc95db-5d58-4c96-91f9-34b653e67f50"
		date = "2023-12-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/downloader_mac_rustbucket_swiftloader.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		hash = "7c5bf60787bfd076c8806eaa4f1185f5b9fda69008376624ab3d17f207eb16a4"
		hash = "bc90adde92bd47b4de7d384e5b20c1a1791d603629bd0fcba4b550fb35e93216"
		hash = "c9a7b42c7b29ca948160f95f017e9e9ae781f3b981ecf6edbac943e52c63ffc8"
		logic_hash = "acb5b88f8af53cd3d83de0fd6c3049ce017f038dc7c8b31f70e65e60bf713dfb"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "/Users/ghost/Desktop/EdoneViewer/EdoneViewer/"
		$ = "EdoneViewerApp.swift"

	condition:
		1 of them
}

rule SEKOIA_Implant_Any_Sliver_Not_Stripped : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/implant_any_sliver_not_stripped.yar#L1-L24"
		license = "DRL-1.1"
		description = "Rule which detects non stripped Sliver PE/Dlls/ELFs/MAC-O."
		author = "Sekoia.io"
		id = "35543c7c-c39b-4f96-b37c-1d27736e40fc"
		date = "2021-11-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/implant_any_sliver_not_stripped.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "5240f3ea1fb421697eeb12eb17d0b31c036b53f39c3a590473d87065b5d28e3e"
		score = 75
		quality = 80
		tags = "FILE"
		modification_date = "2021-12-22"
		version = "1.1"
		classification = "TLP:CLEAR"

	strings:
		$a1 = "github.com/bishopfox/sliver/implant/sliver/"

	condition:
		( uint16be( 0 ) == 0x4d5a or uint32be( 0 ) == 0x7f454c46 or uint32be( 0 ) == 0xcffaedfe ) and filesize < 11MB and filesize > 8MB and #a1 > 200
}

rule SEKOIA_Apt_Kimsuky_Toddlershark_Strings : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_kimsuky_toddlershark_strings.yar#L1-L20"
		license = "DRL-1.1"
		description = "Detects Kimsuky TODDLERSHARK vbs malware"
		author = "Sekoia.io"
		id = "2db1a424-9e83-4168-8ebf-d3b415b6a576"
		date = "2024-03-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_kimsuky_toddlershark_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "dee9d03f498437dd6d8399975cd91ec44307067ac4642b9ff31df1a6d6b10468"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "On Error Resume Next"
		$ = ".open \"POST\", \"http"
		$ = ".setRequestHeader"
		$ = ".send"
		$ = "Execute("
		$ = ".responseText)"

	condition:
		all of them and filesize < 450
}

rule SEKOIA_Apt_Luckymouse_Rshell_Strings : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_luckymouse_rshell_strings.yar#L1-L26"
		license = "DRL-1.1"
		description = "Detects LuckyMouse RShell Mach-O implant"
		author = "Sekoia.io"
		id = "89f18013-ea3e-440f-821e-cef102a43b7b"
		date = "2022-08-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_luckymouse_rshell_strings.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "ffca47856d4c4d83312220cff23c0a556be0e675d59ac009c2f74fc0e39cb816"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = { 64 69 72 00 70 61 74 68
        00 64 6F 77 6E 00 72 65
        61 64 00 75 70 6C 6F 61
        64 00 77 72 69 74 65 00
        64 65 6C }
		$ = { 6C 6F 67 69 6E 00 68 6F
        73 74 6E 61 6D 65 00 6C
        61 6E 00 75 73 65 72 6E
        61 6D 65 00 76 65 72 73
        69 6F 6E }

	condition:
		( uint32be( 0 ) == 0xCFFAEDFE or uint16be( 0 ) == 0x4d5a ) and filesize < 300KB and all of them
}

rule SEKOIA_Apt_Cloudmensis_Downloader_Strings : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_cloudmensis_downloader_strings.yar#L1-L20"
		license = "DRL-1.1"
		description = "Detects CloudMensis downloader"
		author = "Sekoia.io"
		id = "450cfa42-7b56-4d93-afe2-9cf5c1049217"
		date = "2022-07-26"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_cloudmensis_downloader_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "9532530f9b6c39d64611354f5d3c95e7c8b9ebf917ab797c162c3b51945db1fc"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "https://api.pcloud.com/getfilelink?path=%@&forcedownload=1"
		$ = "python -c 'import os; print(os.confstr(65538))'"
		$ = "getCmdResult:"
		$ = "[pCloud DownloadFile:]"

	condition:
		uint32be( 0 ) == 0xcafebabe and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Luckymouse_Rshell_Strings_All_Platform : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_luckymouse_rshell_strings_all_platform.yar#L1-L20"
		license = "DRL-1.1"
		description = "Detects LuckyMouse RShell Mach-O implant"
		author = "Sekoia.io"
		id = "e79a5ee1-96b3-4643-ab11-0b1095e96488"
		date = "2022-08-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_luckymouse_rshell_strings_all_platform.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "ef923b6633a2b7dfa645a31c7c2d0e00872ebad6ec7748568c2b306c29b6b29b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = { 6C 6F 67 69 6E 00 68 6F
        73 74 6E 61 6D 65 00 6C
        61 6E 00 75 73 65 72 6E
        61 6D 65 00 76 65 72 73
        69 6F 6E }

	condition:
		filesize < 1MB and all of them
}

rule SEKOIA_Apt_Cloudmensis_Spyagent_Strings : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_cloudmensis_spyagent_strings.yar#L1-L21"
		license = "DRL-1.1"
		description = "Detects CloudMensis SpyAgent"
		author = "Sekoia.io"
		id = "c2df8373-6698-4b23-9d77-8e7968bd69f0"
		date = "2022-07-26"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt_cloudmensis_spyagent_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "ad858b1b78fb4ac6efee093b11fde14956d63bc6b300ef37bf1f2a3356cf4402"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "[control_thread loop_DirStructure:]"
		$ = "[screen_keylog getScreenShotData]"
		$ = "[screen_keylog loop_usb]"
		$ = "[Management UploadFilebyPath:destination:]"
		$ = "[control_thread loop_pwd:]"

	condition:
		uint32be( 0 ) == 0xcafebabe and filesize < 2MB and all of them
}

rule SEKOIA_Downloader_Mac_Rustbucket : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/downloader_mac_rustbucket.yar#L1-L31"
		license = "DRL-1.1"
		description = "RustBucket fake PDF reader"
		author = "Sekoia.io"
		id = "5a003b68-ad9a-47f9-b157-dd898181dac2"
		date = "2023-04-24"
		modified = "2024-12-19"
		reference = "https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/downloader_mac_rustbucket.yar#L1-L31"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		hash = "38106b043ede31a66596299f17254d3f23cbe1f983674bf9ead5006e0f0bf880"
		hash = "bea33fb3205319868784c028418411ee796d6ee3dfe9309f143e7e8106116a49"
		hash = "7981ebf35b5eff8be2f3849c8f3085b9cec10d9759ff4d3afd46990520de0407"
		hash = "e74e8cdf887ae2de25590c55cb52dad66f0135ad4a1df224155f772554ea970c"
		logic_hash = "1b9e9a3f4fb4804eb94ab8d3573781d67f96d180b258cfc10be384eec44509ed"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$down_exec1 = "_down_update_run" nocase
		$down_exec2 = "downAndExec" nocase
		$encrypt1 = "_encrypt_pdf"
		$encrypt2 = "_encrypt_data"
		$error_msg1 = "_alertErr"
		$error_msg2 = "_show_error_msg"
		$view_pdf1 = "-[PEPWindow view_pdf:]"
		$view_pdf2 = "-[PEPWindow viewPDF:]"
		$macho_magic = {CF FA ED FE}
		$java_magic = {CA FE BA BE}

	condition:
		($macho_magic at 0 or $java_magic at 0 ) and 5 of them and filesize > 50KB
}

rule SEKOIA_Downloader_Mac_Smooth_Operator : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/downloader_mac_smooth_operator.yar#L1-L16"
		license = "DRL-1.1"
		description = "Detect the Smooth_Operator malware"
		author = "Sekoia.io"
		id = "c132b3f0-f536-4a66-bcf8-2a95c258c414"
		date = "2023-07-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/downloader_mac_smooth_operator.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "031f766d6ab7d94ed7ba4324d4bdfa3fbc11986fba35487a88a1ee3aba090c82"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "%s/.main_storage"
		$ = "%s/UpdateAgent"

	condition:
		uint32be( 0 ) == 0xcafebabe and all of them
}

rule SEKOIA_Implant_Mac_Smoothoperator_Update_Agent : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/implant_mac_smoothoperator_update_agent.yar#L1-L18"
		license = "DRL-1.1"
		description = "UpdateAgent payload delivered by SmoothOperator during the 3CX supply chain attack"
		author = "Sekoia.io"
		id = "45a1d0d9-083b-4b4a-b53c-e5d86f804f01"
		date = "2023-07-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/implant_mac_smoothoperator_update_agent.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "d5a0d87ac810097983df92ab1b1ff9775093b0aaaf551a74ff6fe5149dbd3a21"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "3CX Desktop App/.main_storage"
		$ = "3CX Desktop App/config.json"
		$ = "3cx_auth_token_content=%s"
		$ = "3cx_auth_id=%s"

	condition:
		uint32be( 0 ) == 0xcffaedfe and 2 of them
}

rule SEKOIA_Apt37_Rokrat_Macho
{
	meta:
		class = "behavior"
		severity = "MEDIUM"
		source = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt37_rokrat_macho.yar#L1-L21"
		license = "DRL-1.1"
		description = "Detects Public key of Macho samples of RokRAT"
		author = "Sekoia.io"
		id = "c54fb9ae-85fa-4c36-bab9-6c6d989262ba"
		date = "2022-09-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/yara_rules/apt37_rokrat_macho.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/fa3a9630ef9ce484fb1b945480a43f989e6865d4/LICENSE.md"
		logic_hash = "526dc4594db099ed8090a673e761f84f6dd7ce860e380214e4d3f1ec08fc2345"
		score = 75
		quality = 66
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = { 4D 49 49 42 49 6A 41 4E 42 67 6B 71 68 6B 69 47 39 77 30 42 41 51 45 46 41 41 4F 43 41 51 38 41 4D 49 49 42 43 67 4B 43 41 51 45 41 73 47 52 59 53 45 56 76 77 6D 66 42 46 4E 42 6A 4F 7A 2B 51}
		$s2 = {70 61 78 35 72 7A 57 66 2F 4C 54 2F 79 46 55 51 41 31 7A 72 41 31 6E 6A 6A 79 49 48 72 7A 70 68 67 63 39 74 67 47 48 73 2F 37 74 73 57 70 38 65 35 64 4C 6B 41 59 73 56 47 68 57 41 50 73 6A 79}
		$s3 = {31 67 78 30 64 72 62 64 4D 6A 6C 54 62 42 59 54 79 45 67 35 50 67 79 2F 35 4D 73 45 4E 44 64 6E 73 43 52 57 72 32 33 5A 61 4F 45 4C 76 48 48 56 56 38 43 4D 43 38 46 75 34 57 62 61 7A 38 30 4C}
		$s4 = {47 68 67 38 69 73 56 50 45 48 43 38 48 2F 79 47 74 6A 48 50 59 46 56 65 36 6C 77 56 72 2F 4D 58 6F 4B 63 70 78 31 33 53 31 4B 38 6E 6D 44 51 4E 41 68 4D 70 54 31 61 4C 61 47 2F 36 51 69 6A 68}
		$s5 = {57 34 50 2F 52 46 51 71 2B 46 64 69 61 33 66 46 65 68 50 67 35 44 74 59 44 39 30 72 53 33 73 64 46 4B 6D 6A 39 4E 36 4D 4F 30 2F 57 41 56 64 5A 7A 47 75 45 58 44 35 33 4C 48 7A 39 65 5A 77 52}
		$s6 = {39 59 38 37 38 36 6E 56 44 72 6C 6D 61 35 59 43 4B 70 71 55 5A 35 63 34 36 77 57 33 67 59 57 69 33 73 59 2B 56 53 33 62 32 46 64 41 4B 43 4A 68 54 66 43 79 38 32 41 55 47 71 50 53 56 66 4C 61}
		$s7 = {6D 51 49 44 41 51 41 42}

	condition:
		all of them
}
