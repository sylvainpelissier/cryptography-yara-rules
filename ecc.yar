rule Curve25519 {
	meta:
		author = "spelissier"
		description = "Basepoint and coefficients"
		date = "2023-03"
		reference= "https://www.rfc-editor.org/rfc/rfc7748.html#page-8"
	strings:
		$basepoint = {09 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		$coefficient1 = {41 db 01 00} // The constant a24
		$coefficient2 = {42 db 01 00} // Go language uses a24 + 1
	condition:
		$basepoint and ($coefficient1 or $coefficient2)
}

rule ecc_order {
    meta:
		author = "spelissier"
		description = "Look for known Elliptic curve orders"
		date = "2021-07"
		version = "0.2"
	strings:
		$secp192k1 = { FF FF FF FF FF FF FF FF FF FF FF FE 26 F2 FC 17 0F 69 46 6A 74 DE FD 8D}
		$secp192r1 = { FF FF FF FF FF FF FF FF FF FF FF FF 99 DE F8 36 14 6B C9 B1 B4 D2 28 31}
		$secp224k1 = { 01 00 00 00 00 00 00 00 00 00 00 00 00 00 01 DC E8 D2 EC 61 84 CA F0 A9 71 76 9F B1 F7}
		$secp224r1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF 16 A2 E0 B8 F0 3E 13 DD 29 45 5C 5C 2A 3D}
		$secp256k1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE BA AE DC E6 AF 48 A0 3B BF D2 5E 8C D0 36 41 41 }
		$prime256v1 = { FF FF FF FF 00 00 00 00 FF FF FF FF FF FF FF FF BC E6 FA AD A7 17 9E 84 F3 B9 CA C2 FC 63 25 51 }
		$secp384r1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF C7 63 4D 81 F4 37 2D DF 58 1A 0D B2 48 B0 A7 7A EC EC 19 6A CC C5 29 73 }
		$bls12_381_r = { 01 00 00 00 FF FF FF FF FE 5B FE FF 02 A4 BD 53 05 D8 A1 09 08 D8 39 33 48 7D 9D 29 53 A7 ED 73}
	condition:
		any of them
}