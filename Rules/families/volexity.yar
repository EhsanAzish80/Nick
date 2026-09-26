// Nick bundled family signatures — https://github.com/volexity/threat-intel
//
// Retrieved through YARA Forge release 20260920 (https://github.com/YARAHQ/yara-forge)
// and selected by Scripts/import_family_rules.py.
//
// License: BSD-2-Clause (https://opensource.org/license/bsd-2-clause). Full text: Rules/families/LICENSES/volexity.txt
// Rule authorship and references are preserved in each rule's metadata.

rule VOLEXITY_Apt_Malware_Macos_Gimmick : STORMBAMBOO FILE MEMORY
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/2022/2022-03-22 GIMMICK/indicators/yara.yar#L1-L59"
		license = "BSD-2-Clause"
		description = "Detects the macOS port of the GIMMICK malware."
		author = "threatintel@volexity.com"
		id = "3d485788-4aab-511b-a49e-5dc09d1950a9"
		date = "2021-10-18"
		modified = "2024-08-02"
		reference = "https://www.volexity.com/blog/2022/03/22/storm-cloud-on-the-horizon-gimmick-malware-strikes-at-macos/"
		source_url = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/2022/2022-03-22 GIMMICK/indicators/yara.yar#L1-L59"
		license_url = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/LICENSE.txt"
		hash = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
		logic_hash = "00fba9df2212874a45d44b3d098a7b76c97fcd53ff083c76b784d2b510a4a467"
		score = 75
		quality = 78
		tags = "STORMBAMBOO, FILE, MEMORY"
		os = "darwin"
		os_arch = "all"
		scan_context = "file,memory"
		rule_id = 6022
		version = 8

	strings:
		$s1 = "http://cgi1.apnic.net/cgi-bin/my-ip.php --connect-timeout 10 -m 20" wide ascii
		$json1 = "base_json" ascii wide
		$json2 = "down_json" ascii wide
		$json3 = "upload_json" ascii wide
		$json4 = "termin_json" ascii wide
		$json5 = "request_json" ascii wide
		$json6 = "online_json" ascii wide
		$json7 = "work_json" ascii wide
		$msg1 = "bash_pid: %d, FDS_CHILD: %d, FDS_PARENT: %d" ascii wide
		$msg2 = "pid %d is dead" ascii wide
		$msg3 = "exit with code %d" ascii wide
		$msg4 = "recv signal %d" ascii wide
		$cmd1 = "ReadCmdQueue" ascii wide
		$cmd2 = "read_cmd_server_timer" ascii wide
		$cmd3 = "enableProxys" ascii wide
		$cmd4 = "result_block" ascii wide
		$cmd5 = "createDirLock" ascii wide
		$cmd6 = "proxyLock" ascii wide
		$cmd7 = "createDirTmpItem" ascii wide
		$cmd8 = "dowfileLock" ascii wide
		$cmd9 = "downFileTmpItem" ascii wide
		$cmd10 = "filePathTmpItem" ascii wide
		$cmd11 = "uploadItems" ascii wide
		$cmd12 = "downItems" ascii wide
		$cmd13 = "failUploadItems" ascii wide
		$cmd14 = "failDownItems" ascii wide
		$cmd15 = "downloadCmds" ascii wide
		$cmd16 = "uploadFiles" ascii wide
		$cmd17 = "bash callback...." ascii wide

	condition:
		$s1 or 5 of ( $json* ) or 3 of ( $msg* ) or 9 of ( $cmd* )
}

rule VOLEXITY_Apt_Malware_Macos_Reloadext_Installer : STORMBAMBOO FILE MEMORY
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/2024/2024-08-02 StormBamboo/rules.yar#L37-L62"
		license = "BSD-2-Clause"
		description = "Detect the RELOADEXT installer."
		author = "threatintel@volexity.com"
		id = "c65ea2b5-ab98-5693-92ea-05c0f1ea1e5b"
		date = "2024-02-23"
		modified = "2024-08-02"
		reference = "TIB-20240227"
		source_url = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/2024/2024-08-02 StormBamboo/rules.yar#L37-L62"
		license_url = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/LICENSE.txt"
		hash = "07e3b067dc5e5de377ce4a5eff3ccd4e6a2f1d7a47c23fe06b1ededa7aed1ab3"
		logic_hash = "8688796839202d95ded15e10262a7a7c7cbbae4a332b60305402e5984005d452"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		os = "darwin"
		os_arch = "all"
		scan_context = "file,memory"
		rule_id = 10281
		version = 2

	strings:
		$str1 = "/CustomPlug1n/"
		$str2 = "Chrome NOT installed."
		$str3 = "-f force kill Chrome"
		$str4 = "/*} &&cp -rf ${"

	condition:
		3 of them
}

rule VOLEXITY_Apt_Malware_Macos_Vpnclient_Cc_Oct23 : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/2024/2024-02-13 CharmingCypress/rules.yar#L246-L272"
		license = "BSD-2-Clause"
		description = "Detection for fake macOS VPN client used by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "e0957936-dc6e-5de6-bb23-d0ef61655029"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/2024/2024-02-13 CharmingCypress/rules.yar#L246-L272"
		license_url = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/LICENSE.txt"
		hash = "11f0e38d9cf6e78f32fb2d3376badd47189b5c4456937cf382b8a574dc0d262d"
		hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
		logic_hash = "da5e9be752648b072a9aaeed884b8e1729a14841e33ed6633a0aaae1f11bd139"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		os = "darwin,linux"
		os_arch = "all"
		scan_context = "file,memory"
		rule_id = 9770
		version = 3

	strings:
		$s1 = "networksetup -setsocksfirewallproxystate wi-fi off" ascii
		$s2 = "networksetup -setsocksfirewallproxy wi-fi ___serverAdd___ ___portNum___; networksetup -setsocksfirewallproxystate wi-fi on" ascii
		$s3 = "New file imported successfully." ascii
		$s4 = "Error in importing the File." ascii

	condition:
		2 of ( $s* )
}

rule VOLEXITY_Apt_Mac_Iconic : UTA0040
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/2023/2023-03-30 3CX/indicators/rules.yar#L32-L50"
		license = "BSD-2-Clause"
		description = "Detects the MACOS version of the ICONIC loader."
		author = "threatintel@volexity.com"
		id = "6d702ed3-e5b9-5324-a06b-507c9231cc00"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/2023/2023-03-30 3CX/indicators/rules.yar#L32-L50"
		license_url = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/LICENSE.txt"
		hash = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		logic_hash = "7b689c3931632b01869ac2f21a1edca0a5ca9007299fe7cd16962d6866c27558"
		score = 75
		quality = 80
		tags = "UTA0040"
		memory_suitable = 1

	strings:
		$str1 = "3CX Desktop App" xor(0x01-0xff)
		$str2 = "__tutma=" xor(0x01-0xff)
		$str3 = "Mozilla/5.0" xor(0x01-0xff)

	condition:
		all of them
}

rule VOLEXITY_Apt_Malware_Any_Macma_A : STORMBAMBOO FILE MEMORY
{
	meta:
		class = "behavior"
		severity = "MEDIUM"
		source = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/2024/2024-08-02 StormBamboo/rules.yar#L63-L111"
		license = "BSD-2-Clause"
		description = "Detects variants of the MACMA backdoor, variants of MACMA have been discovered for macOS and android."
		author = "threatintel@volexity.com"
		id = "6ab45af1-41e5-53fc-9297-e2bc07ebf797"
		date = "2021-11-12"
		modified = "2024-08-02"
		reference = "https://blog.google/threat-analysis-group/analyzing-watering-hole-campaign-using-macos-exploits/"
		source_url = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/2024/2024-08-02 StormBamboo/rules.yar#L63-L111"
		license_url = "https://github.com/volexity/threat-intel/blob/f340f93e4ca5c749342da331900aad2bfc377caf/LICENSE.txt"
		hash = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"
		hash = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
		hash = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
		hash = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
		logic_hash = "7ebaff9fddf6491d6b1ed9ab14c1b87dc8df850536e55aa723d625a593b33ed7"
		score = 75
		quality = 53
		tags = "STORMBAMBOO, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		report1 = "TIB-20231221"
		report2 = "TIB-20240227"
		scan_context = "file,memory"
		rule_id = 6114
		version = 9

	strings:
		$magic1 = "curl -o %s http://cgi1.apnic.net/cgi-bin/my-ip.php" fullword ascii
		$magic2 = "[FST%d]: WhyUserCancel UNKNOW: %d" fullword ascii
		$magic3 = "[FST%d]: wait C2 prepare ready TIMEOUT, fd: %d" fullword ascii
		$magic4 = "[FST%d]: wait C2 ack file content TIMEOUT, fd: %d" fullword ascii
		$magic5 = "[FST%d]: TIMER_CHECK_CANCEL WhyUserCancel UNKNOW: %d" fullword ascii
		$magic6 = "[FST%d]: encrypt file info key=%s, crc v1=0x%p, v2=0x%p" fullword ascii
		$s1 = "auto bbbbbaaend:%d path %s" fullword ascii
		$s2 = "0keyboardRecirderStopv" fullword ascii
		$s3 = "curl begin..." fullword ascii
		$s4 = "curl over!" fullword ascii
		$s5 = "kAgent fail" fullword ascii
		$s6 = "put !!!!" fullword ascii
		$s7 = "vret!!!!!! %d" fullword ascii
		$s8 = "save Setting Success" fullword ascii
		$s9 = "Start Filesyste Search." fullword ascii
		$s10 = "./SearchFileTool" fullword ascii
		$s11 = "put unknow exception in MonitorQueue" fullword ascii
		$s12 = "./netcfg2.ini" fullword ascii
		$s13 = ".killchecker_" fullword ascii
		$s14 = "./param.ini" fullword ascii

	condition:
		any of ( $magic* ) or 7 of ( $s* )
}
