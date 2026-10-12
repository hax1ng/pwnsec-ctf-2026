#!/usr/bin/env sage
# gap-gap solver: Coppersmith-recover the 30 hidden digits of d, then
# factor the structured RSA modulus and decrypt. Defaults hold the live
# instance tuple; pass a capture file to solve another instance.

import re
import sys

from Crypto.Util.number import long_to_bytes

N = 17668783236117152126485520467381256749713800338617774162102315727072334513530974092444263508885081786780174120287011946678632446389866217953988953155080281513690341686636339616426230464681760338926816665120476574579728096674877360540222394397985852678043378301517687303217499142036938641711854881074061154894533855328481832536929088561481554266312683291429096396256314359395263518429524009085373545278988556614040421459307411586939139929249807686943968245350292302963982562138136143166910518100799275468812185078034322295178161039079957298341919003536597027926850870944628630710133642645390134290086920833786595018139
e = 1659125864185605799196693195656882928175046949306715117297591466215331373121887405974690730352123915395097969769652642830246016519559054040164973579715044750687693014603666325819879017973303582379121436454933806004991352812659121510250502232733013786716940265861991487930907028900089872183305011753076247175717082603952150857126465832250194416395963690194800573470592432070414681005542014443067325349824289589530656102309851452708984399
c = 116676012577912273669167633022885965805151223885893283036913393725711009179075511856813239031938868172420413849711384593839861109865500976999408307678458972374914737442015941064664285340902387484134537121497861448919345856184707445072726081847495192575012174254357654221374748819993554493924020479866929527105000638905748625761168343349853886919024370119198488510799556611135494889781073209533637269720422420174671618289253767609643640718632476498187707175448663530266600404655359870962253094569443060365264048066637573542004921282850414941225341649936268221360766925037370163155004076063741454321656425477310389269

prefix = 93561958556505568031598881410780016108913853954
suffix = 61501251584271136576288777262606558999703562879

# Optionally solve another captured server instance.
if len(sys.argv) > 1:
    capture = open(sys.argv[1]).read()
    values = dict(re.findall(r"^(N|e|c) = (\d+)$", capture, re.MULTILINE))
    N, e, c = (Integer(values[name]) for name in ("N", "e", "c"))
    leak = re.search(r"d_leak = '(\d+)\*+(\d+)'", capture)
    prefix, suffix = map(Integer, leak.groups())

B = 10^47
d0 = prefix * 10^77 + suffix

# For the real private exponent d=d0+B*x,
#     e*d - 1 = k*lambda and lambda=2*g*a*b.
# Thus (e*d-1)/2 vanishes modulo the 600-bit prime g, which is a
# factor of (N-1)/2 because N-1=2*g*(2*g*a*b+a+b).
M = (N - 1) // 2
R.<x> = PolynomialRing(Zmod(M))
f = (e * d0 - 1) // 2 + (e * B // 2) * x
f = f * inverse_mod(Integer(f.leading_coefficient()), M)

print("[*] Recovering the 30 missing decimal digits with Coppersmith...")
roots = f.small_roots(X=10^30, beta=0.292, epsilon=0.02)
if not roots:
    raise RuntimeError("Coppersmith found no root")

middle = Integer(roots[0])
d = Integer(d0 + B * middle)
shared = gcd(Integer(e*d - 1), Integer(N - 1))
g = shared // 2
assert g.nbits() == 600 and is_prime(g)
print(f"[+] middle = {middle:030d}")
print(f"[+] d = {d}")
print(f"[+] g = {g}")

# N-1=2*g*h.  Since h=lambda+(a+b), recover a+b from the known lambda,
# then solve t^2-(a+b)t+ab=0 to obtain a and b.
h = (N - 1) // (2*g)

# gcd(e*d-1,N-1)=2*g.  The quotient still contains the unknown multiplier k,
# so recover lambda using k.  Because h-lambda=a+b is tiny (~425 bits),
# e*d/k is an exceptionally accurate rational approximation to h; equivalently
# k is the nearest integer to e*d/h.
k = Integer(round(QQ(e*d) / h))
assert (e*d - 1) % k == 0
lam = (e*d - 1) // k
s = h - lam
ab = lam // (2*g)
Delta = s^2 - 4*ab
sqrt_Delta = Integer(Delta).isqrt()
assert sqrt_Delta^2 == Delta
a = (s + sqrt_Delta) // 2
b = (s - sqrt_Delta) // 2
p = 2*g*a + 1
q = 2*g*b + 1
assert is_prime(p) and is_prime(q)
assert p*q == N
assert lcm(p - 1, q - 1) == lam
assert (e*d) % lam == 1

m = power_mod(c, d, N)
assert power_mod(m, e, N) == c
flag = long_to_bytes(int(m))
print(f"[+] p = {p}")
print(f"[+] q = {q}")
print("[+] factorization, private exponent, and re-encryption assertions passed")
print(f"[+] flag = {flag!r}")
