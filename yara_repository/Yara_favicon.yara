rule Yara_favicon
{
meta:
	date = "2019-05-11"
	hash_md5 = "efd1b449ced8d3be3bfb57d33db548d7"
	hash_sha256 = "64696e75fb59a96f14b8bf0d3b93ac45328980e3b602c34d0eb153e84ade4482"
	sample_filetype = "ico mpeg mpg mov spl"
strings:
condition:
	 all of them   
}
