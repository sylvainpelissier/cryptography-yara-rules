rule Curve25519 {
	meta:
		author = "spelissier"
		description = "Basepoint and coefficients"
		date = "2023-03"
	strings:
		$basepoint = {09 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		$coefficient1 = {41 db 01 00}
		$coefficient2 = {42 db 01 00}
	condition:
		$basepoint and ($coefficient1 or $coefficient2)
}
