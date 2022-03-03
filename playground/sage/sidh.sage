
# https://sike.org/files/SIDH-spec.pdf, p.20 (23)
p = 0x0002341F271773446CFC5FD681C520567BC65C783158AEA3FDC1767AE2FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
e2 = 0x000000D8
e3 = 0x00000089
xQ20 = 0x0000C7461738340EFCF09CE388F666EB38F7F3AFD42DC0B664D9F461F31AA2EDC6B4AB71BD42F4D7C058E13F64B237EF7DDD2ABC0DEB0C6C
xQ21 = 0x000025DE37157F50D75D320DD0682AB4A67E471586FBC2D31AA32E6957FA2B2614C4CD40A1E27283EAAF4272AE517847197432E2D61C85F5
yQ20 = 0x0001D407B70B01E4AEE172EDF491F4EF32144F03F5E054CEF9FDE5A35EFA3642A11817905ED0D4F193F31124264924A5F64EFE14B6EC97E5
yQ21 = 0x0000E7DEC8C32F50A4E735A839DCDB89FE0763A184C525F7B7D0EBC0E84E9D83E9AC53A572A25D19E1464B509D97272AE761657B4765B3D6
xP20 = 0x00003CCFC5E1F050030363E6920A0F7A4C6C71E63DE63A0E6475AF621995705F7C84500CB2BB61E950E19EAB8661D25C4A50ED279646CB48
xP21 = 0x0001AD1C1CAE7840EDDA6D8A924520F60E573D3B9DFAC6D189941CB22326D284A8816CC4249410FE80D68047D823C97D705246F869E3EA50
yP20 = 0x0001AB066B84949582E3F66688452B9255E72A017C45B148D719D9A63CDB7BE6F48C812E33B68161D5AB3A0A36906F04A6A6957E6F4FB2E0
yP21 = 0x0000FD87F67EA576CE97FF65BF9F4F7688C4C752DCE9F8BD2B36AD66E04249AAF8337C01E6E4E1A844267BA1A1887B433729E1DD90C7DD2F
xR20 = 0x0000F37AB34BA0CEAD94F43CDC50DE06AD19C67CE4928346E829CB92580DA84D7C36506A2516696BBE3AEB523AD7172A6D239513C5FD2516
xR21 = 0x000196CA2ED06A657E90A73543F3902C208F410895B49CF84CD89BE9ED6E4EE7E8DF90B05F3FDB8BDFE489D1B3558E987013F9806036C5AC
xQ30 = 0x00012E84D7652558E694BF84C1FBDAAF99B83B4266C32EC65B10457BCAF94C63EB063681E8B1E7398C0B241C19B9665FDB9E1406DA3D3846
xQ31 = 0x00000000
yQ30 = 0x00000000
yQ31 = 0x0000EBAAA6C731271673BEECE467FD5ED9CC29AB564BDED7BDEAA86DD1E0FDDF399EDCC9B49C829EF53C7D7A35C3A0745D73C424FB4A5FD2
xP30 = 0x00008664865EA7D816F03B31E223C26D406A2C6CD0C3D667466056AAE85895EC37368BFC009DFAFCB3D97E639F65E9E45F46573B0637B7A9
xP31 = 0x00000000
yP30 = 0x00006AE515593E73976091978DFBD70BDA0DD6BCAEEBFDD4FB1E748DDD9ED3FDCF679726C67A3B2CC12B39805B32B612E058A4280764443B
yP31 = 0x00000000
xR30 = 0x0001CD28597256D4FFE7E002E87870752A8F8A64A1CC78B5A2122074783F51B4FDE90E89C48ED91A8F4A0CCBACBFA7F51A89CE518A52B76C
xR31 = 0x000147073290D78DD0CC8420B1188187D1A49DBFA24F26AAD46B2D9BB547DBB6F63A760ECB0C2B20BE52FB77BD2776C3D14BCBC404736AE4

assert p.is_prime(), "p is not prime"

# F_{p^2}, with "i" as the imaginary element (i^2 + 1 = 0)
Fp2.<i> = GF(p^2, modulus=x^2 + 1)

# y^2 = x^3 + 6*x^2 + x
E = EllipticCurve(Fp2, [0, 6, 0, 1, 0])

order = E.order()

print(E)

# Curve is supersingular
assert order == (p + 1)**2, "Curve is not supersingular"
# Curve has two subgroups of size 2**e2 and 3**e3
assert order % 2**e2 == 0 and order % 3**e3 == 0, "Unexpected order"
# Curve has correct starting j-invariant
assert E.j_invariant() == 287496, "Unexpected j-invariant"

# Alice's basis points
Q2 = E(xQ20 + i*xQ21, yQ20 + i*yQ21)
P2 = E(xP20 + i*xP21, yP20 + i*yP21)
R2 = Q2 - P2

assert xR20 + i*xR21 == R2[0], "xR2 != (Q2-P2)[0]"

# Bob's basis points
Q3 = E(xQ30 + i*xQ31, yQ30 + i*yQ31)
P3 = E(xP30 + i*xP31, yP30 + i*yP31)
R3 = Q3 - P3

assert xR30 + i*xR31 == R3[0], "xR3 != (Q3-P3)[0]"

# Compute guesses
P_ord4 = []
for k in range(4):
    guess = (2**214)*(P2 + k*Q2)
    assert guess.order() == 4
    assert not guess in P_ord4
    P_ord4 += [guess]

assert (2**214)*(P2 + 4*Q2) in P_ord4, "(2**214)*(P2 + 4*Q2) is not in pre-computed guesses"

# Alice's secret key (little-endian)
KEY = "000102030405060708090A0B0C0D0E0F101112131415161718191A"
sk = int(''.join([KEY[2*i:2*(i+1)] for i in range(len(KEY)//2)][::-1]), 16)

# Alice's secret generator R
print("Computing R = P + [sk]Q...")
R = P2 + sk*Q2

print("\tR->X[0]=" + hex(R[0].polynomial()[0])[2:])
print("\tR->X[1]=" + hex(R[0].polynomial()[1])[2:])

print("\tR->Y[0]=" + hex(R[1].polynomial()[0])[2:])
print("\tR->Y[1]=" + hex(R[1].polynomial()[1])[2:])

print("\tR->Z[0]=" + hex(R[2].polynomial()[0])[2:])
print("\tR->Z[1]=" + hex(R[2].polynomial()[1])[2:])

# Checks if first 4-isogeny is in guesses
print("Computing [2^214]R... ", end="")
kerR = (2**214)*R

assert kerR.order() == 4, "KerR is not of order 4"
assert kerR in P_ord4, "KerR is not in pre-computed guesses"

print("could have been guessed!")