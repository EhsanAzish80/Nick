// Nick bundled family signatures — https://github.com/mandiant/red_team_tool_countermeasures/
//
// Retrieved through YARA Forge release 20260920 (https://github.com/YARAHQ/yara-forge)
// and selected by Scripts/import_family_rules.py.
//
// License: BSD-2-Clause (https://opensource.org/license/bsd-2-clause). Full text: Rules/families/LICENSES/mandiant.txt
// Rule authorship and references are preserved in each rule's metadata.

rule FIREEYE_RT_APT_Backdoor_Macos_GORAT_1 : FILE
{
	meta:
		class = "signature"
		severity = "HIGH"
		source = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE (Gorat)/production/yara/APT_Backdoor_MacOS_GORAT_1.yar#L4-L19"
		license = "BSD-2-Clause"
		description = "This rule is looking for specific strings associated with network activity found within the MacOS generated variant of GORAT"
		author = "FireEye"
		id = "4646eadb-7acf-582f-9ad6-00f012ceed8a"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE (Gorat)/production/yara/APT_Backdoor_MacOS_GORAT_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "68acf11f5e456744262ff31beae58526"
		logic_hash = "2df5f87d44968670511880d21ad184779d0561c7c426a5d6426bcefd0904a9b7"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$s1 = "SID1=%s" ascii wide
		$s2 = "http/http.dylib" ascii wide
		$s3 = "Mozilla/" ascii wide
		$s4 = "User-Agent" ascii wide
		$s5 = "Cookie" ascii wide

	condition:
		(( uint32( 0 ) == 0xBEBAFECA ) or ( uint32( 0 ) == 0xFEEDFACE ) or ( uint32( 0 ) == 0xFEEDFACF ) or ( uint32( 0 ) == 0xCEFAEDFE ) ) and all of them
}
