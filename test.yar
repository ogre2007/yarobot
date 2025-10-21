/*
   YARA Rule Set
   Author: test
   Date: 2025-10-22
   Identifier: test
   Reference: test
   License: test
*/

/* Global Rule -------------------------------------------------------------- */
/* Will be evaluated first, speeds up scanning process, remove at will */

global private rule gen_characteristics {
	condition:
		uint16(0) == 0x5a4d and filesize < 6000KB
}

/* Rule Set ----------------------------------------------------------------- */

rule data_binary {
	meta:
		description = "test - file binary"
		author = "test"
		reference = "test"
		date = "2025-10-22"
		hash1 = "06b664dfe476c87bd25b7329a41e3a9722689675278d443aff28113f6e3f13d3"
	strings:
		$x1 = "Fatal internal error. Please consider filing a bug report at https://github.com/clap-rs/clap/issuesC:\\Users\\User\\.cargo\\registry" ascii  /*, signing_certificates, drive, exe_extensions, network_keywords, connection_keywords, system_keywords, credentials, missed_user_profiles, drives, string_parts, directory, extensions_generic, , ,  / score: 33 /*/
		$x2 = "C:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\clap_builder-4.5.42\\src\\builder\\command.rs" ascii fullword /*, drive, system_keywords, credentials, missed_user_profiles, drives, string_parts, directory, protocol_keywords, , ,  / score: 23 /*/
		$x3 = "VCRUNTIME140.dll" ascii fullword /*, exe_extensions, programming, pe_exe, file, special_strings, extensions_generic, , ,  / score: 22 /*/
		$x4 = "C:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\clap_builder-4.5.42\\src\\output\\help_template.rs" ascii fullword /*, temp_and_recycler, drive, system_keywords, credentials, missed_user_profiles, drives, string_parts, directory, , ,  / score: 22 /*/
		$x5 = "{all-args}{after-help}namebinversionauthorauthor-with-newlineauthor-sectionaboutabout-with-newlineabout-sectionusage-headingusag" ascii  /*, connection_keywords, credentials, special_strings, string_parts, protocol_keywords, compiler, , ,  / score: 21 /*/
		$x6 = "is_nonoverlapping: `size_of::<T>() * count` overflows a usizeC:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f" ascii  /*, signing_certificates, drive, system_keywords, credentials, missed_user_profiles, drives, suspicious_words2, directory, , ,  / score: 21 /*/
		$x7 = "is_nonoverlapping: `size_of::<T>() * count` overflows a usizeconsole is detachedC:\\Users\\User\\.cargo\\registry\\src\\index.crates.i" ascii  /*, signing_certificates, drive, system_keywords, credentials, missed_user_profiles, drives, suspicious_words2, directory, , ,  / score: 21 /*/
		$x8 = "unsafe precondition(s) violated: slice::get_unchecked requires that the index is within the sliceC:\\Users\\User\\.cargo\\registry\\s" ascii  /*, drive, system_keywords, credentials, missed_user_profiles, drives, directory, protocol_keywords, , ,  / score: 20 /*/
		$x9 = "C:\\Users\\User\v\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\clap_builder-4.5.42\\src\\output\\usage.rs" ascii fullword /*, drive, system_keywords, credentials, missed_user_profiles, drives, special_strings, directory, , ,  / score: 20 /*/
		$x10 = "internal error: entered unreachable codeC:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\clap_builder-4.5.42\\s" ascii  /*, signing_certificates, drive, connection_keywords, system_keywords, credentials, missed_user_profiles, drives, directory, , ,  / score: 20 /*/

	condition:
		uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*)
}

