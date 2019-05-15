rule Yara_test
{
meta:
	date = "2019-05-11"
	hash_md5 = "4b26e810448141b3238895373c87f55d"
	hash_sha256 = "92615ac285680c0eb98fa943b296cfaa0e19301f4e1ef4763a45d89697abdb7f"
	sample_filetype = ""
strings:
	$string0 = ";3S1T]"
	$string1 = "_MEIPASS2"
	$string2 = "n7yHi-"
	$string3 = "6jI.]VV6$"
	$string4 = "fCt[<W"
	$string5 = "3Dd33XHQi"
	$string6 = "x9q0qH"
	$string7 = "t,@)xo"
	$string8 = "9jW0}%"
	$string9 = "[jMYZQ"
	$string10 = "bZo)}k"
	$string11 = "k2BQkIf"
	$string12 = "KFyWTU7"
	$string13 = "FAx7RN"
	$string14 = "$HypYkf"
condition:
	 all of them   
}
