// Nick bundled family signatures — https://github.com/advanced-threat-research/Yara-Rules/
//
// Retrieved through YARA Forge release 20260920 (https://github.com/YARAHQ/yara-forge)
// and selected by Scripts/import_family_rules.py.
//
// License: Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0). Full text: Rules/families/LICENSES/advanced_threat_research.txt
// Rule authorship and references are preserved in each rule's metadata.

rule TRELLIX_ARC_MALW_Thiefquest : KEYLOGGER BACKDOOR RANSOMWARE FILE
{
	meta:
		class = "behavior"
		severity = "MEDIUM"
		source = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/ransomware/RANSOM_thiefquest.yar#L1-L46"
		license = "Apache-2.0"
		description = "Rule to detect the Evilquest/ThiefQuest malware"
		author = "McAfee ATR Team"
		id = "09b074f7-6899-574d-a7d6-4414509aaa78"
		date = "2020-07-09"
		modified = "2020-10-12"
		reference = "https://www.bleepingcomputer.com/news/security/thiefquest-ransomware-is-a-file-stealing-mac-wiper-in-disguise/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/ransomware/RANSOM_thiefquest.yar#L1-L46"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "5a024ffabefa6082031dccdb1e74a7fec9f60f257cd0b1ab0f698ba2a5baca6b"
		logic_hash = "d40a466b12188d545d3fbe2c9d7e3685dde1250ae1f25df2a72cdf93c470ae25"
		score = 75
		quality = 68
		tags = "KEYLOGGER, BACKDOOR, RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "keylogger, backdoor, ransomware"
		actor_type = "Cybercrime"
		malware_family = "Ransom:OSX/ThiefQuest"

	strings:
		$pattern_0 = { 01c1 48 83c102 48 }
		$pattern_1 = { 8c1471 80c1c1 98 1c8c }
		$pattern_2 = { d8974f0dc89a 9f c9 9adf70cd595390 }
		$pattern_3 = { d897c56f028c 2393a0a42e92 8ea2c27affc2 f8 }
		$pattern_4 = { 477006 baa6a1cb82 ae f9 e8???????? d8a32bd0d519 }
		$pattern_5 = { d898ab5c757b 2f f26f 5d }
		$pattern_6 = { bc007a846b 2b54adaf 93 35eddf38e6 cdd0 b246 }
		$pattern_7 = { ae 49b00e 01d1 45da611b 44839db656691674 }
		$pattern_8 = { 01c1 48 83c101 48 }
		$pattern_9 = { 6be3c6 5c 99 ae ed bf370e2f47 }
		$pattern_10 = { fd d7 43bd18fd6f06 7937 fa }
		$pattern_11 = { 01c2 48 83c201 bf01000000 }
		$pattern_12 = { d89825ed4469 29f1 5c e12d }
		$pattern_13 = { d8992062f7f9 73ff 90 085fc6 }
		$pattern_14 = { 01c1 6689ca 668995cefeffff e9???????? }
		$pattern_15 = { 01c1 41 89c8 44 }
		$pattern_16 = { d89935c487a7 bcdffa587c be6cadbb3c 185fc4 }
		$pattern_17 = { 01c1 48 8b75a8 48 }
		$pattern_18 = { 0000 48 8945f8 e9???????? }
		$pattern_19 = { d89959d6472d a2???????? 3525c7eec9 95 }
		$pattern_20 = { 01c2 48 83c203 bf01000000 }
		$pattern_21 = { 4a7888 ab 23e7 cf 11f3 }
		$pattern_22 = { d8982fbf222d 49 92 1d25b42bba }
		$pattern_23 = { e2d7 8437 6b4696d9 92 9d a6 }

	condition:
		7 of them and filesize < 124322606
}
