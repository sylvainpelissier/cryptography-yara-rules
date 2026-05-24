rule MLDSA_44_Constants {
    meta:
        description = "Detects the constants q and gamma2 of ML-DSA-44"
        author = "spelissier"
        date = "2026-05-22"
        
    strings:
		$gamma2 = { 00 74 01 00}
        $q = { 01 e0 7f 00}
    condition:
		all of them
}

rule MLDSA_65_87_Constants {
    meta:
        description = "Detects the constants q and gamma2 of ML-DSA-65 and ML-DSA-87"
        author = "spelissier"
        date = "2026-05-22"
    strings:
		$gamma2 = { 00 ff 03 00}
        $q = { 01 e0 7f 00}
	condition:
		all of them
}

rule MLDSA_Dilithium_NTT_zetas_LE
{
    meta:
        description = "Detects the beginning of ML-DSA NTT zeta table in little endian form"
        author = "spelissier"
        date = "2026-05-22"
        reference = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#page=61"
    strings:
        // 32-bit values, little-endian
        $zetas_le_1 = { 02 5e 49 00 }
        $zetas_le_2 = { 67 75 39 00 } 
        $zetas_le_3 = { 69 65 39 00 }
        $zetas_le_4 = { 2b 06 4f 00 }
        $zetas_le_5 = { 73 df 53 00 }
        $zetas_le_6 = { 33 e0 4f 00 } 
        $zetas_le_7 = { 6b 06 4f 00 }
        $zetas_le_8 = { ae b1 76 00 }
        
    condition:
        4 of them
}

rule MLDSA_Dilithium_NTT_zetas_montgomery_LE
{
    meta:
        description = "Detects the beginning of ML-DSA NTT zeta table in little endian in Montgomery form"
        author = "spelissier"
        date = "2026-05-22"
        reference = "https://github.com/openssl/openssl/blob/83ef5622a64d34885a7d6da866accf2281879c7d/crypto/ml_dsa/ml_dsa_ntt.c#L80"
    strings:
        // 32-bit values, little-endian
        $zetas_le_1 = { f7 64 00 00 } 
        $zetas_le_2 = { 02 31 d8 ff } 
        $zetas_le_3 = { 03 15 f8 ff }
        $zetas_le_4 = { 44 9e 03 00 } 
        $zetas_le_7 = { 25 1e 07 00 }
        $zetas_le_8 = { 2b de 1b 00 }
        $zetas_le_9 = { 2b e9 23 00 }
    condition:
        4 of them
}

rule MLDSA_Dilithium_NTT_zetas_montgomery_BE
{
    meta:
        description = "Detects the beginning of ML-DSA NTT zeta table in big endian"
        author = "spelissier"
        date = "2026-05-22"

    strings:
        // 32 values, big-endian 
        $zetas_be_1 = { 00 00 64 f7 } 
        $zetas_be_2 = { ff d8 31 02 } 
        $zetas_be_3 = { ff f8 15 03 }
        $zetas_be_4 = { 00 03 93 44 }
        $zetas_le_7 = { 00 07 1e 25 }
        $zetas_le_8 = { 00 1b de 2b }
        $zetas_le_9 = { 00 23 e9 2b }
    condition:
        4 of them
}
           