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
