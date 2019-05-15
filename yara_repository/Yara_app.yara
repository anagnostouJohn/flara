rule Yara_app
{
meta:
	date = "2019-05-14"
	hash_md5 = "3007d8af3ffab998d623d4da22463770"
	hash_sha256 = "4f1f94c3983c074e6f6f7e1c9df20ce2d2779186d5d135cab43d9a2a9c74f385"
	sample_filetype = "cpl exe dll"
strings:
	$string0 = "gr@rTrj2/"
	$string1 = "B e(OeB"
	$string2 = "October" wide
	$string3 = "LxDs>R"
	$string4 = "tempfile)"
	$string5 = ".CRT$XPZ"
	$string6 = "S(Uigw8ch"
	$string7 = "k8BiLR4"
	$string8 = "C:)TIu"
	$string9 = "UHEUL%TR"
	$string10 = "e4dlWE"
	$string11 = "7$7,747<7D7L7T7\\7d7l7t7"
	$string12 = "h)7M)R"
	$string13 = "@f$IQI"
	$string14 = "E3YVYE"
condition:
	 all of them and uint16(0) == 0x5A4D and (filesize > 4762KB and filesize < 4766KB) 
}
