rule Yara_1
{
meta:
	date = "2019-04-30"
	hash_md5 = "19c3da049070c5c28cb6c412589f5066"
	hash_md5 = "ba0bbed772c6207f9a815cbffb02a75f948b1ec60f6fa935e3d90e2b81677cb3"
	sample_filetype = "mpg jfif mp3 mpeg jpg jpeg jpe"
strings:
	$string0 = "3.]:NRPa}"
	$string1 = "NZLHLZnbbn"
	$string2 = "AqAa,B"
	$string3 = "ICC_PROFILE"
	$string4 = "$Qt,To"
	$string5 = "h76r{l>"
	$string6 = "\\Q\\;9;"
	$string7 = "nms-TgKBcCN5xCPVCvkD"
	$string8 = "rNpzXz"
	$string9 = "Q@q 0P"
	$string10 = "l':{5[B"
	$string11 = "BE80K "
	$string12 = "pTgnx["
	$string13 = "6Photoshop 3.0"
	$string14 = "KITB4J"
condition:
	 all of them   
}
