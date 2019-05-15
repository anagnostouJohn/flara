rule Yara_WdfCoInstaller01009
{
meta:
	date = "2019-05-11"
	hash_md5 = "67d93100d27d76909edc22dfc2cddd10"
	hash_sha256 = "dbffb023b7ddf449010743de92c46fd34cb3461bef8cae2e084487d8a4b9bc05"
	sample_filetype = "cpl exe dll"
strings:
	$string0 = "f8_Kk7"
	$string1 = "zl.{L3"
	$string2 = ":}sV9v"
	$string3 = "TUUUUUUUUhP"
	$string4 = "error(%d) %s" wide
	$string5 = "BootApplication: could not open service %s, error %s" wide
	$string6 = "2Yg/D%S"
	$string7 = "@m<THu"
	$string8 = ":\\E6jy"
	$string9 = "9rIEYa"
	$string10 = "30]X;y"
	$string11 = "VerifyVersionInfoW"
	$string12 = "v)wkkG"
	$string13 = "kRdA%v9"
	$string14 = "QueryServiceConfigW"
condition:
	 all of them   
}
