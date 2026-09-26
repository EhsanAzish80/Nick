// Nick bundled family signatures — https://github.com/ditekshen/detection
//
// Retrieved through YARA Forge release 20260920 (https://github.com/YARAHQ/yara-forge)
// and selected by Scripts/import_family_rules.py.
//
// License: BSD-2-Clause (https://opensource.org/license/bsd-2-clause). Full text: Rules/families/LICENSES/ditekshen.txt
// Rule authorship and references are preserved in each rule's metadata.

rule DITEKSHEN_MALWARE_Osx_Macsearch : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3071-L3092"
		license = "BSD-2-Clause"
		description = "Detects MacSearch adware"
		author = "ditekSHen"
		id = "facdf05c-5ee4-54c6-9ca3-01978af2b6e6"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3071-L3092"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "973b7215fc8d04685a46d05b53b4092e7b81ed0d64d6982b534f2b89d0a59443"
		score = 75
		quality = 71
		tags = "FILE"

	strings:
		$s1 = "open -a safari" ascii
		$s2 = "/INDownloader" ascii
		$s3 = "/safefinder" ascii
		$s4 = "/INEncryptor" ascii
		$s5 = "/INInstallerFlow" ascii
		$s6 = "/INConfiguration" ascii
		$s7 = "/INChromeAndFFSetter" ascii
		$s8 = "/INSafariSetter" ascii
		$s9 = "/bin/launchctl" fullword ascii
		$s10 = "/usr/bin/csrutil" fullword ascii
		$s11 = "_Tt%cSs%zu%.*s%s" fullword ascii
		$s12 = "_Tt%c%zu%.*s%zu%.*s%s" fullword ascii
		$s13 = "/macap/safefinder_Obf/safefinder/" ascii
		$s14 = "/safefinder.build/Release/macsearch.build/" ascii

	condition:
		uint16( 0 ) == 0xfacf and 10 of them
}

rule DITEKSHEN_MALWARE_Osx_AMCPCVARK : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3114-L3139"
		license = "BSD-2-Clause"
		description = "Detects OSX TechyUtils/PCVARK adware"
		author = "ditekSHen"
		id = "1378364b-db10-5194-98f8-5347504a92e6"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3114-L3139"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "b18a9f578af98feb5107d9ef85850457ba5921ab58af7b097a815e3af74f05f7"
		score = 75
		quality = 75
		tags = "FILE"
		clamav_sig = "MALWARE.Osx.Adware.AMC-PCVARK-TechyUtils"

	strings:
		$s1 = "Mac Auto Fixer.app" fullword ascii
		$s2 = "com.techyutil.macautofixer" fullword ascii
		$s3 = "com.findApp.findApp" ascii
		$s4 = "Library/Preferences/%@.plist" fullword ascii
		$s5 = "Library/%@/%@" fullword ascii
		$s6 = "Library/Application Support/%@/%@" fullword ascii
		$s7 = "sleep 3; rm -rf \"%@\"" fullword ascii
		$s8 = "Silently calling url: %@" ascii
		$cnc1 = "cloudfront.net/getdetails" ascii
		$cnc2 = "trk.entiretrack.com/trackerwcfsrv/tracker.svc/trackOffersAccepted/?" ascii
		$cnc3 = "pxl=%@&x-count=1&utm_source=%@&lpid=0&utm_content=&utm_term=&x-base=&utm_medium=%@&utm_publisher=%@&offerpxl=&x-fetch=1&utm_campaign=@&affiliateid=&x-at=&btnid=" ascii
		$x1 = "mafsysinfo" fullword ascii
		$x2 = "MAF4497_MAF4399_MAF2204" ascii
		$developerid = "Developer ID Application: Rahul Gahlot (RZ74UYT742)" ascii

	condition:
		uint16( 0 ) == 0xfacf and ( 6 of ( $s* ) or 2 of ( $cnc* ) or all of ( $x* ) or $developerid )
}

rule DITEKSHEN_MALWARE_Osx_Windtrail : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3189-L3206"
		license = "BSD-2-Clause"
		description = "Detects WindTrail OSX trojan"
		author = "ditekSHen"
		id = "abf7cd20-b37d-5d0a-8f3f-f4e491965713"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3189-L3206"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "291f919cb1e8c4b33960dd3f2c842b9efec04852bd5661543e3ee60bc0fc5ba6"
		score = 75
		quality = 73
		tags = "FILE"
		clamav_sig = "MALWARE.Osx.Trojan.WindTrail"

	strings:
		$s1 = "m_ComputerName_UserName" fullword ascii
		$s2 = "m_uploadURL" fullword ascii
		$s3 = "m_logString" fullword ascii
		$s4 = "GenrateDeviceName" fullword ascii
		$s5 = "open -a" fullword ascii
		$s6 = "AESEncryptFile:toFile:usingPassphrase:error:" fullword ascii
		$s7 = "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:" fullword ascii
		$s8 = "_kLSSharedFileListSessionLoginItems" fullword ascii
		$developerid = "Developer ID Application: warren portman (95RKE2AA8F)" ascii

	condition:
		uint16( 0 ) == 0xfacf and ( all of ( $s* ) or $developerid )
}

rule DITEKSHEN_MALWARE_Osx_Techyutils : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3208-L3224"
		license = "BSD-2-Clause"
		description = "Detects TechyUtils OSX packages"
		author = "ditekSHen"
		id = "59fd4165-987f-5b68-9341-d78184b25a1c"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3208-L3224"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "071c67cace09dd66233bd4c4dd78c32d0f39f7e38dc06ec62e09fef67762d098"
		score = 75
		quality = 73
		tags = "FILE"
		clamav_sig = "MALWARE.Osx.Trojan.TechyUtils"

	strings:
		$s1 = "__ZL58__arclite_NSMutableDictionary__" ascii
		$s2 = "__ZL46__arclite_NSDictionary_" ascii
		$s3 = "<key>com.apple.security.get-task-allow</key>" fullword ascii
		$s4 = "/productprice.svc/GetCountryCode" ascii
		$s5 = "@_pthread_mutex_lock" fullword ascii
		$s6 = "_mh_execute_header" fullword ascii
		$s7 = "/Users/prasoon/Documents/" ascii
		$developerid = "Developer ID Application: Techyutils Software Private Limited (VS9Q8BRRRJ)" ascii

	condition:
		uint16( 0 ) == 0xfacf and ( all of ( $s* ) or $developerid )
}

rule DITEKSHEN_MALWARE_Multi_POOLRAT : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L11822-L11839"
		license = "BSD-2-Clause"
		description = "Detects POOLRAT"
		author = "ditekshen"
		id = "5831b479-592d-591b-88b4-73102fe4b6ec"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L11822-L11839"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "efc5881975e97583188d43a8a6b0eb59bb7103664897cc0f88ddc4d2376bd842"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "MALWARE.Osx.Trojan.POOLRAT"
		clamav2 = "MALWARE.Linux.Trojan.POOLRAT"

	strings:
		$s1 = "MSG_CmdP" ascii
		$s2 = "MSG_WriteConfigP" ascii
		$s3 = "MSG_SecureDelP" ascii
		$s4 = "ConnectToProxyP" ascii
		$s5 = "MSG_KeepConP" ascii
		$s6 = "MSG_SleepP" ascii
		$s7 = "MSG_TestP" ascii
		$s8 = "MSG_SetPathP" ascii

	condition:
		( uint16( 0 ) == 0x457f or uint16( 0 ) == 0xfacf or uint16( 0 ) == 0xfeca ) and 7 of them
}

rule DITEKSHEN_MALWARE_Multi_Pondrat : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L11841-L11858"
		license = "BSD-2-Clause"
		description = "Detects PondRAT"
		author = "ditekshen"
		id = "cb8cca87-6b5e-5984-8a73-9f800b262d77"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L11841-L11858"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "affa35f789725d3a8cea8dc95744c4e771690fde5f73936d0806a8c9f72fdb2e"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "MALWARE.Osx.Trojan.PondRAT"
		clamav2 = "MALWARE.Linux.Trojan.PondRAT"

	strings:
		$s1 = "MsgDown" ascii
		$s2 = "MsgUp" ascii
		$s3 = "MsgRun" ascii
		$s4 = "MsgCmd" ascii
		$s5 = "CryptPayload" ascii
		$s6 = "RecvPayload" ascii
		$s7 = "csleepi" ascii
		$s8 = "FConnectProxy" ascii

	condition:
		( uint16( 0 ) == 0x457f or uint16( 0 ) == 0xfacf or uint16( 0 ) == 0xfeca ) and 7 of them
}

rule DITEKSHEN_MALWARE_Osx_Genieo : FILE
{
	meta:
		class = "behavior"
		severity = "MEDIUM"
		source = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3094-L3112"
		license = "BSD-2-Clause"
		description = "Detects LinqurySearch/Genieo adware"
		author = "ditekSHen"
		id = "ac44eefd-bf1c-5d4b-bcd4-9a5d394ac1d3"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3094-L3112"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "951dc8539435a52d9eea00b3fdaf98cf618c03867066819f2f9244165e57c675"
		score = 75
		quality = 50
		tags = "FILE"
		clamav_sig = "MALWARE.Osx.Trojan.Genieo"

	strings:
		$s1 = "<key>com.apple.security.get-task-allow</key>" fullword ascii
		$s2 = "U1QQFXAfCxAfRUNCH1JZXh9" ascii
		$s3 = "XVFTQ1VRQlNYH" ascii
		$s4 = "dF9HXlxfUVQQVUJCX0IQHRB" ascii
		$s5 = "Value:forHTTPHeaderField:" ascii
		$s6 = "postContent:::" fullword ascii
		$s7 = "postLog:" fullword ascii
		$s8 = "initWithBase64EncodedString:options:" fullword ascii
		$s9 = "do shell script \"%@\" with administrator privileges" fullword ascii
		$s10 = /LinqurySearch-[a-f0-9]{40,}/

	condition:
		uint16( 0 ) == 0xfacf and 6 of them
}

rule DITEKSHEN_MALWARE_Osx_Realtimespy : FILE
{
	meta:
		class = "behavior"
		severity = "MEDIUM"
		source = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3141-L3166"
		license = "BSD-2-Clause"
		description = "Detects macOS RealtimeSpy monitoring app"
		author = "ditekSHen"
		id = "6485abf3-896c-54cd-ad84-7bd86456e47b"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3141-L3166"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "4ef2e1b8d34962cd3eab23f401b764b38b8332233aa2ae91b218af499d8ab8ff"
		score = 75
		quality = 57
		tags = "FILE"
		clamav_sig = "MALWARE.Osx.Trojan.RealtimeSpy"

	strings:
		$x1 = "SPYAGENT4HASHCIPHER" fullword ascii
		$x2 = ":username:password:acctid:compUser:compName:" ascii
		$x3 = ":username:password:acctid:compName:" ascii
		$x4 = "://www.realtime-spy-mac.com/" ascii
		$x5 = "/Users/spytech/" ascii
		$x6 = "shell script \"touch /private/var/db/.AccessibilityAPIEnabled\" password \"pwd\" with administrator privileges" ascii
		$x7 = "Content-Disposition: form-data; name=\"raptor_" ascii
		$c1 = "_OBJC_CLASS_$_LocationLogger" fullword ascii
		$c2 = "_OBJC_CLASS_$_MonitoringFunctions" fullword ascii
		$c3 = "_OBJC_CLASS_$_ProcessLogger" fullword ascii
		$c4 = "_OBJC_CLASS_$_RealtimeLoggingFunctions" fullword ascii
		$c5 = "_OBJC_CLASS_$_Realtime_SpyAppDelegate" fullword ascii
		$c6 = "_OBJC_CLASS_$_ScreenshotLogger" fullword ascii
		$c7 = "_OBJC_CLASS_$_Uploader" fullword ascii
		$c8 = "_OBJC_CLASS_$_UsageLogger" fullword ascii
		$c9 = "_OBJC_CLASS_$_WebsiteLogger" fullword ascii

	condition:
		uint16( 0 ) == 0xfacf and ( 2 of ( $x* ) or 2 of ( $c* ) )
}
