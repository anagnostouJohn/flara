rule Yara_contacts
{
meta:
	date = "2019-04-30"
	hash_md5 = "c91a67ba609c0dce5db9ea6982923abd"
	hash_md5 = "c94219afaa0c16e69de5024b6f12e8023a864080abd08004fe2aab5bbd2827a9"
	sample_filetype = ""
strings:
	$string0 = "n.benias@cd.mil.gr"
	$string1 = "i.bronis@cd.mil.gr"
condition:
	 1 of them  and (filesize > 0KB and filesize < 4KB) 
}
