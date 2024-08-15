rule Blowfish_p_array_BE
{	meta:
		author = "spelissier"
		description = "Blowfish pArray big endian"
		date = "2024-08"
		reference="https://datatracker.ietf.org/doc/html/draft-schneier-blowfish-00"
	strings:
		$c0 = { 243f6a88 }
		$c2 = { 85a308d3 }
		$c3 = { 13198a2e }
		$c4 = { 03707344 }
		$c5 = { a4093822 }
		$c6 = { 299f31d0 }
		$c7 = { 082efa98 }
		$c8 = { ec4e6c89 }
		$c9 = { 452821e6 }
		$c10 = { 38d01377 }
		$c11 = { be5466cf }
		$c12 = { 34e90c6c }
		$c13 = { c0ac29b7 }
		$c14 = { c97c50dd }
		$c15 = { 3f84d5b5 }
		$c16 = { b5470917 }
		$c17 = { 9216d5d9 }
		$c18 = { 8979fb1b }
	condition:
		4 of them
}

rule Blowfish_p_array_LE
{	meta:
		author = "spelissier"
		description = "Blowfish pArray little endian"
		date = "2024-08"
		reference="https://datatracker.ietf.org/doc/html/draft-schneier-blowfish-00"
	strings:
		$c0 = { 886a3f24 }
		$c1 = { d308a385 }
		$c2 = { 2e8a1913 }
		$c3 = { 44737003 }
		$c4 = { 223809a4 }
		$c5 = { d0319f29 }
		$c6 = { 98fa2e08 }
		$c7 = { 896c4eec }
		$c8 = { e6212845 }
		$c9 = { 7713d038 }
		$c10 = { cf6654be }
		$c11 = { 6c0ce934 }
		$c12 = { b729acc0 }
		$c13 = { dd507cc9 }
		$c14 = { b5d5843f }
		$c15 = { 170947b5 }
		$c16 = { d9d51692 }
		$c17 = { 1bfb7989 }
	condition:
		4 of them
}


rule SM4_SBox
{	meta:
		author = "spelissier"
		description = "SM4 SBox"
		date = "2022-05"
		reference="https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10#section-6.2.3"
	strings:
		$c0 = { D6 90 E9 FE CC E1 3D B7 16 B6 14 C2 28 FB 2C 05 }
	condition:
		$c0
}

rule SM4_FK
{	meta:
		author = "spelissier"
		description = "SM4 Familiy key FK"
		date = "2022-05"
		reference="https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10#section-7.3.1"
	strings:
		$c0 = { C6 BA B1 A3 50 33 AA 56 97 91 7D 67 DC 22 70 B2 }
	condition:
		$c0
}

rule SM4_CK
{	meta:
		author = "spelissier"
		description = "SM4 Constant Key CK"
		date = "2022-05"
		reference="https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10#section-7.3.2"
	strings:
		$c0 = { 15 0E 07 00 31 2A 23 1C 4D 46 3F 38 69 62 5B 54 }
	condition:
		$c0
}