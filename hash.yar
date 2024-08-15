rule MD5_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for MD5 constants"
		date = "2014-01"
		version = "0.2"
	strings:
		// Init constants
		$c0 = { 67452301 }
		$c1 = { efcdab89 }
		$c2 = { 98badcfe }
		$c3 = { 10325476 }
		$c4 = { 01234567 }
		$c5 = { 89ABCDEF }
		$c6 = { FEDCBA98 }
		$c7 = { 76543210 }
		// Round 2
		$c8 = { F4D50d87 }
		$c9 = { 78A46AD7 }
	condition:
		5 of them
}

rule SHA1_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for SHA1 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
		//added by _pusher_ 2016-07 - last round
		$c10 = { D6C162CA }
	condition:
		5 of them
}

rule SHA2_BLAKE2_IVs {
	meta:
		author = "spelissier"
		description = "Look for SHA2/BLAKE2/Argon2 IVs"
		date = "2019-12"
		version = "0.1"
	strings:
		$c0 = { 67 e6 09 6a }
		$c1 = { 85 ae 67 bb }
		$c2 = { 72 f3 6e 3c }
		$c3 = { 3a f5 4f a5 }
		$c4 = { 7f 52 0e 51 }
		$c5 = { 8c 68 05 9b }
		$c6 = { ab d9 83 1f }
		$c7 = { 19 cd e0 5b }

	condition:
		all of them
}

rule SHA256_Initial_values {
    meta:
		author = "spelissier"
		description = "SHA2 initial values H(0) from NIST.FIPS.180-4"
		date = "2024-08"
		version = "0.1"
	strings:
		$c0 = { 6a09e667 }
        $c1 = { bb67ae85 }
        $c2 = { 3c6ef372 }
        $c3 = { a54ff53a }
        $c4 = { 510e527f }
        $c5 = { 9b05688c }
        $c6 = { 1f83d9ab }
        $c7 = { 5be0cd19 }
	condition:
		all of them
}

rule SHA512_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for SHA384/SHA512 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 428a2f98 }
		$c1 = { 982f8a42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { b5c0fbcf }
		$c5 = { cffbc0b5 }
		$c6 = { e9b5dba5 }
		$c7 = { a5dbb5e9 }
		$c8 = { d728ae22 }
		$c9 = { 22ae28d7 }
	condition:
		5 of them
}

rule SHA3_constants {
	meta:
		author = "spelissier"
		description = "SHA-3 (Keccak) round constants"
		date = "2020-04"
		version = "0.1"
	strings:
		$c0  = { 0080008000000080 }
		$c1  = { 0a00008000000080 }
		$c2  = { 8080000000000080 }
		$c3  = { 8b00000000000080 }
		$c4  = { 8280000000000000 }
		$c5  = { 8980000000000080 }
		$c6  = { 0880008000000080 }
		$c7  = { 0980008000000000 }
		$c8  = { 0280000000000080 }
		$c9  = { 0a00008000000000 }
		$c10 = { 0380000000000080 }
		$c11 = { 8b80000000000000 }
		$c12 = { 0100008000000000 }
		$c13 = { 0a80000000000000 }
		$c14 = { 0980000000000080 }
		$c15 = { 8000000000000080 }
		$c16 = { 8800000000000000 }
		$c17 = { 8b80008000000000 }
		$c18 = { 8a00000000000000 }
		$c19 = { 8180008000000080 }
		$c20 = { 0100000000000000 }
		$c21 = { 8a80000000000080 }
	condition:
		10 of them
}

rule SHA3_interleaved {
	meta:
		author = "spelissier"
		description = "SHA-3 (Keccak) interleaved round constants"
		date = "2020-04"
		version = "0.1"
	strings:
		$c0  = { 010000008b800000 }
		$c1  = { 0000000081000080 }
		$c2  = { 0000000088000080 }
		$c3  = { 000000000b000000 }
		$c4  = { 0100000000800000 }
		$c5  = { 010000008b000000 }
		$c6  = { 0100000082800000 }
		$c7  = { 0000000003800000 }
		$c8  = { 010000008a000080 }
		$c9  = { 0000000082800080 }
		$c10 = { 0000000003800080 }
		$c11 = { 000000008b000080 }
		$c12 = { 0000000083000000 }
		$c13 = { 000000000a000000 }
		$c14 = { 0000000080800080 }
		$c15 = { 0100000082000080 }
		$c16 = { 010000000b000080 }
		$c17 = { 0100000088800080 }
		$c18 = { 0000000008000080 }
		$c19 = { 0100000000000000 }
		$c20 = { 0000000089000000 }
		$c21 = { 0100000081000080 }
	condition:
		10 of them
}

rule SipHash_big_endian_constants {
    meta:
		author = "spelissier"
		description = "Look for SipHash constants in big endian"
		date = "2020-07"
		reference = "https://131002.net/siphash/siphash.pdf#page=6"
	strings:
		$c0 = "uespemos"
		$c1 = "modnarod"
		$c2 = "arenegyl"
		$c3 = "setybdet"
	condition:
		2 of them
}