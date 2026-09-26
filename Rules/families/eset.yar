// Nick bundled family signatures — https://github.com/eset/malware-ioc
//
// Retrieved through YARA Forge release 20260920 (https://github.com/YARAHQ/yara-forge)
// and selected by Scripts/import_family_rules.py.
//
// License: BSD-2-Clause (https://opensource.org/license/bsd-2-clause). Full text: Rules/families/LICENSES/eset.txt
// Rule authorship and references are preserved in each rule's metadata.

rule ESET_Keydnap_Downloader
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/eset/malware-ioc/blob/17baf44964a77368e9149f4f593eb098beddf1c5/keydnap/keydnap.yar#L33-L49"
		license = "BSD-2-Clause"
		description = "OSX/Keydnap Downloader"
		author = "Marc-Etienne M.Léveillé"
		id = "2b21007a-b143-5538-8777-ba35448d00aa"
		date = "2016-07-06"
		modified = "2016-07-06"
		reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
		source_url = "https://github.com/eset/malware-ioc/blob/17baf44964a77368e9149f4f593eb098beddf1c5/keydnap/keydnap.yar#L33-L49"
		license_url = "https://github.com/eset/malware-ioc/blob/17baf44964a77368e9149f4f593eb098beddf1c5/LICENSE"
		logic_hash = "71c8885193a92fa9c71055c37e629a54d50070cf6820b9216a824ecc4db2ce3c"
		score = 75
		quality = 80
		tags = ""
		version = "1"

	strings:
		$ = "icloudsyncd"
		$ = "killall Terminal"
		$ = "open %s"

	condition:
		2 of them
}

rule ESET_Keydnap_Backdoor_Packer
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/eset/malware-ioc/blob/17baf44964a77368e9149f4f593eb098beddf1c5/keydnap/keydnap.yar#L51-L67"
		license = "BSD-2-Clause"
		description = "OSX/Keydnap packed backdoor"
		author = "Marc-Etienne M.Léveillé"
		id = "f29ad5af-bc86-5764-9451-5a8363788c4e"
		date = "2016-07-06"
		modified = "2016-07-06"
		reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
		source_url = "https://github.com/eset/malware-ioc/blob/17baf44964a77368e9149f4f593eb098beddf1c5/keydnap/keydnap.yar#L51-L67"
		license_url = "https://github.com/eset/malware-ioc/blob/17baf44964a77368e9149f4f593eb098beddf1c5/LICENSE"
		logic_hash = "b1740bf38376be81d3b42306c2ce81f578c0b5c9db804f063836bf98f57ed147"
		score = 75
		quality = 80
		tags = ""
		version = "1"

	strings:
		$upx_string = "This file is packed with the UPX"
		$packer_magic = "ASS7"
		$upx_magic = "UPX!"

	condition:
		$upx_string and $packer_magic and not $upx_magic
}

rule ESET_Keydnap_Backdoor
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/eset/malware-ioc/blob/17baf44964a77368e9149f4f593eb098beddf1c5/keydnap/keydnap.yar#L69-L86"
		license = "BSD-2-Clause"
		description = "Unpacked OSX/Keydnap backdoor"
		author = "Marc-Etienne M.Léveillé"
		id = "099c1796-6237-5ec1-ba25-cd5feca79865"
		date = "2016-07-06"
		modified = "2016-07-06"
		reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
		source_url = "https://github.com/eset/malware-ioc/blob/17baf44964a77368e9149f4f593eb098beddf1c5/keydnap/keydnap.yar#L69-L86"
		license_url = "https://github.com/eset/malware-ioc/blob/17baf44964a77368e9149f4f593eb098beddf1c5/LICENSE"
		logic_hash = "fa209577a562ef9088d3ad3df3fbc0edda96f09d19177842f0ddea42c658f530"
		score = 75
		quality = 80
		tags = ""
		version = "1"

	strings:
		$ = "api/osx/get_task"
		$ = "api/osx/cmd_executed"
		$ = "Loader-"
		$ = "u2RLhh+!LGd9p8!ZtuKcN"
		$ = "com.apple.iCloud.sync.daemon"

	condition:
		2 of them
}
