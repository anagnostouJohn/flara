rule Yara_tests
{
meta:
	date = "2019-05-11"
	hash_md5 = "2fed1c88ae4ff51e33290db1f4964495"
	hash_sha256 = "6f284e705530884f370164a5cbb3e27ebd9f58593b01a43cd1799102678431a2"
	sample_filetype = ""
strings:
	$string0 = "25504446"
	$string1 = "dwe path /log/file.txt some lergerg ergergines /log/var/file2.txt wefwe fwef wef  eberbeb"
	$string2 = "             "
	$string3 = "__________________________________________"
	$string4 = " re.findall(regexp, r"
	$string5 = " print(int(x/1024))"
	$string6 = "[A-Z0-9._%"
	$string7 = "wefwef192.1f68.320.165f3f3 gv ger retb  ege e ge  erg e101.0.1.10erg erg erg g re"
	$string8 = "1111AAAAaa1aaa1HKEY_CURRENT_USERaaa"
	$string9 = "C:\\Users\\john\\Desktop\\workSpace\\yara_cr\\z.zip"
	$string10 = " domain..."
	$string11 = ":[A-Z0-9-]"
	$string12 = "[\\\\/])"
	$string13 = "password"
	$string14 = "         x"
condition:
	 all of them   
}
