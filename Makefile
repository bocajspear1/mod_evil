all:
	apxs -c mod_evil.c
	cp .libs/mod_evil.so ./
	strip mod_evil.so
	md5sum mod_evil.so > mod_evil_hashes.txt
	sha1sum mod_evil.so >> mod_evil_hashes.txt
	sha256sum mod_evil.so >> mod_evil_hashes.txt