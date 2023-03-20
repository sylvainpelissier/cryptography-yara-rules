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