rule Chacha_128_constant {
    meta:
		author = "spelissier"
		description = "Look for 128-bit key Chacha stream cipher constant"
		date = "2019-12"
		reference = "https://www.ecrypt.eu.org/stream/salsa20pf.html"
	strings:
		$c0 = "expand 16-byte k"
	condition:
		$c0
}

rule Chacha_256_constant {
    meta:
		author = "spelissier"
		description = "Look for 256-bit key Chacha stream cipher constant"
		date = "2019-12"
		reference = "https://tools.ietf.org/html/rfc8439#page-8"
	strings:
		$c = "expand 32-byte k"
		$split_64_1 = "expand 3"
		$split_64_2 = "2-byte k"
        $split_32_1 = "expa"
		$split_32_2 = "nd 3"
        $split_32_3 = "2-by"
		$split_32_4 = "te k"
	condition:
		$c or ( 2 of ($split_64_*)) or ( 4 of ($split_32_*))
}

rule Sosemanuk_constants
{	meta:
		author = "spelissier"
		description = "Sosemanuk constants"
		date = "2023-03"
		reference="https://www.ecrypt.eu.org/stream/p3ciphers/sosemanuk/sosemanuk_p3.pdf"
	strings:
		$sosemanuk_pi = { 07 53 65 54}
		$present_phi = { B9 79 37 9E }
	condition:
		$sosemanuk_pi and $present_phi
}

rule Sosemanuk_encrypt_tables
{
    meta:
        author = "Theo Letailleur, Synacktiv"
		description = "Sosemanuk tables"
		date = "2023-03"
    strings:
        // Multiplication by alpha: alpha * x = T32(x << 8) ^ mul_a[x >> 24]
        $sosemanuk_encrypt_mul_a = {
            00 00 00 00 E1 9F CF 13 6B 97 37 26 8A 08 F8 35 D6 87 6E 4C 37 18 A1 5F BD 10 59 
            6A 5C 8F 96 79 05 A7 DC 98 E4 38 13 8B 6E 30 EB BE 8F AF 24 AD D3 20 B2 D4 32 BF 
            7D C7 B8 B7 85 F2 59 28 4A E1 0A E7 11 99 EB 78 DE 8A 61 70 26 BF 80 EF E9 AC DC 
            60 7F D5 3D FF B0 C6 B7 F7 48 F3 56 68 87 E0 0F 40 CD 01 EE DF 02 12 64 D7 FA 27 
            85 48 35 34 D9 C7 A3 4D 38 58 6C 5E B2 50 94 6B 53 CF 5B 78
        }
        // DWORD array version
        $sosemanuk_encrypt_mul_a_4byte_array_le = {
            00 00 00 00 13 CF 9F E1 26 37 97 6B 35 F8 08 8A 4C 6E 87 D6 5F A1 18 37 6A 59 10 
            BD 79 96 8F 5C 98 DC A7 05 8B 13 38 E4 BE EB 30 6E AD 24 AF 8F D4 B2 20 D3 C7 7D 
            BF 32 F2 85 B7 B8 E1 4A 28 59 99 11 E7 0A 8A DE 78 EB BF 26 70 61 AC E9 EF 80 D5 
            7F 60 DC C6 B0 FF 3D F3 48 F7 B7 E0 87 68 56 01 CD 40 0F 12 02 DF EE 27 FA D7 64 
            34 35 48 85 4D A3 C7 D9 5E 6C 58 38 6B 94 50 B2 78 5B CF 53
        }
        // Multiplication by 1/alpha: 1/alpha * x = (x >> 8) ^ mul_ia[x & 0xFF]
        $sosemanuk_encrypt_mul_ia = {
            00 00 00 00 18 0F 40 CD 30 1E 80 33 28 11 C0 FE 60 3C A9 66 78 33 E9 AB 50 22 29 
            55 48 2D 69 98 C0 78 FB CC D8 77 BB 01 F0 66 7B FF E8 69 3B 32 A0 44 52 AA B8 4B 
            12 67 90 5A D2 99 88 55 92 54 29 F0 5F 31 31 FF 1F FC 19 EE DF 02 01 E1 9F CF 49 
            CC F6 57 51 C3 B6 9A 79 D2 76 64 61 DD 36 A9 E9 88 A4 FD F1 87 E4 30 D9 96 24 CE 
            C1 99 64 03 89 B4 0D 9B 91 BB 4D 56 B9 AA 8D A8 A1 A5 CD 65
        }
        // DWORD array version
        $sosemanuk_encrypt_kk_mul_ia_4byte_array_le = {
            00 00 00 00 CD 40 0F 18 33 80 1E 30 FE C0 11 28 66 A9 3C 60 AB E9 33 78 55 29 22 
            50 98 69 2D 48 CC FB 78 C0 01 BB 77 D8 FF 7B 66 F0 32 3B 69 E8 AA 52 44 A0 67 12 
            4B B8 99 D2 5A 90 54 92 55 88 31 5F F0 29 FC 1F FF 31 02 DF EE 19 CF 9F E1 01 57 
            F6 CC 49 9A B6 C3 51 64 76 D2 79 A9 36 DD 61 FD A4 88 E9 30 E4 87 F1 CE 24 96 D9 
            03 64 99 C1 9B 0D B4 89 56 4D BB 91 A8 8D AA B9 65 CD A5 A1
        }
    condition:
        1 of ($sosemanuk_encrypt_*)
}
