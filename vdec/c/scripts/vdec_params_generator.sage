import mpmath as mp
from mpmath import mpf, nstr
import sys

# Alice
q = 2**60  # fhe ciphertext modulus (same as proof modulus)
delta_m =  2048 # 
t_inf =  5 # infinity norm of plaintext space
#noise_dim = 1 * 12288 # number ctxts (64) * fhe_dimension
noise_dim = 12288 * 64

# Bob
#Bprime = 4                  # set linf norm bound.; this is needed by alpha4; alpha4 is needed by gamma4
#Bprime = q / (2 * delta_m * t_inf) - 1/2
Bprime = 2**15

# cannot print more than 822
mp.mp.prec = 512
prec = 8  # precision for nstr


verbose = 1
code = 1

assert len(sys.argv) == 2
params_file = sys.argv[1]

load("codegen.sage")


# bound B
def Bound_():
    global stdev2
    global m2
    global d
    global eta
    global D
    global kmsis
    global gamma
    return stdev2 * mp.sqrt(2 * m2 * d) + mpf(eta) * 2 ** (D-1) * mp.sqrt(kmsis*d) + (gamma * mp.sqrt(kmsis * d))/mpf(2)


# bound B1
def Bound1():
    global stdev1
    global m1
    global d
    # XXX compare B1 page 150 [1]
    return mpf(2) * stdev1 * mp.sqrt(2 * m1 * d)


# bound B2
def Bound2():
    return mpf(2) * Bound_()


# bound B on the extracted MSIS solution
def Bound():
    global eta
    return 4 * mpf(eta) * mp.sqrt(Bound1() ** 2 + Bound2() ** 2)


# constants, dont change
KAPPA = 100    # security param, bit security
# KAPPA = 128    # security param, bit security
DELTA128 = 1.0044  # root hermite factor for 128-bit security
# number of irreducible factors of X^d + 1 modulo each q_i,  q_i = 2l+1 (mod 4l)
L = 2
T = 1.64  # for KAPPA=128
NADDS = 128  # chose P big enough for this many additions

# default values rejection sampling
rejs1 = 1
rejs2 = 1
gamma1 = 10
gamma2 = 10
gamma4 = 5

load(params_file)

assert rejs1 == 1
assert rejs2 == 1  # XXX add bimodal option
gamma1= mpf(gamma1)
gamma2= mpf(gamma2)
gamma4 = mpf(gamma4)

# X^d + 1 mod q1,q2 must split into L=2 irreductible factors.
# q1, q2 odd primes, q1, q2 = 2L+1 mod 4L, q1 < q2

alpha = mpf(alpha)

if d not in [64, 128]:
    err("d not in [64,128]")
log2d = log(d, 2)

n_div = 1  # number of divisors of q
if 'log2q1' in globals():
    if log2q1 >= log2q:
        err("log(q1) > log(q) = log (q1 * q2)")
    n_div = 2
else:
    log2q1 = log2q

alpha4 = 1
#if nprime > 0 and Bprime > 0:
approx_proof = 1
Bprime = mpf(Bprime)
alpha4 = Bprime
#elif nprime != 0 or Bprime != 0:  # either both > 0, or both == 0
#    err("Invalid approximate proof params")


# number of repetitions for boosting soundness, we assume lambda is even
lmbda = 2 * ceil(KAPPA/(2*log2q1))

# lext fixed for quad-eval proof
lext = lmbda/2 + 1  # fixed for quad-eval-proof


D = 0       # dropping low-order bits of t_A
gamma = 0   # dropping low-order bits of w

# challenge space
if d == 64 and L == 2 and log2q1 >= 4:
    omega = 8
    eta = 140
    Csize = 2 ** 129
elif d == 128 and L == 2 and log2q1 >= 4:
    omega = 2
    eta = 59
    Csize = 2 ** 147
else:
    err("challenge space undefined")

# sample from [-omega,omega] <=> sample from [0,2*omega] - omega
omega_bits = ceil(log(2*omega+1, 2))

# standard deviations for standard rejection sampling
stdev1 = gamma1 * mpf(eta) * alpha
stdev2 = mpf(0)  # set later (depends on length of randomness s2)

# standard deviations for bimodal rejection sampling
stdev4 = gamma4 * mp.sqrt(337) * alpha4 * mp.sqrt(noise_dim)

# XXX
stdev1 = round_stdev(stdev1)
gamma1 = stdev1 / (mpf(eta) * alpha)

stdev4 = round_stdev(stdev4)
gamma4 = stdev4 / (mp.sqrt(337) * alpha4)
# XXX

if gamma1 <= 0:
    err("gamma1 is negative")
if gamma2 <= 0:
    err("gamma2 is negative")


nu = 1      # randomness vector s2 with coefficients between -nu and nu
kmlwe = 0           # MLWE dim, to be determined
easy_mlwe_dim = 0   # lower bound for MLWE dim
hard_mlwe_dim = 64  # guess for upper bound for MLWE dim
# find upper actual bound (and possibly improve lower bound)
while True:
    delta_mlwe = get_delta_mlwe(nu, hard_mlwe_dim, d, 2 ** log2q)
    if delta_mlwe <= DELTA128:
        #print(f"MLWE dim {hard_mlwe_dim}: hard")
        break
    #print(f"MLWE dim {hard_mlwe_dim}: easy")
    easy_mlwe_dim = hard_mlwe_dim
    hard_mlwe_dim *= 2
# binary search for smallest MLWE dimension that is still hard
while True:
    kmlwe = (easy_mlwe_dim + hard_mlwe_dim) / 2
    delta_mlwe = get_delta_mlwe(nu, kmlwe, d, 2 ** log2q)
    if delta_mlwe <= DELTA128:
      #  print(f"MLWE dim {kmlwe} : hard")
        hard_mlwe_dim = kmlwe
    else:
       # print(f"MLWE dim {kmlwe} : easy")
        easy_mlwe_dim = kmlwe
    if hard_mlwe_dim == easy_mlwe_dim + 1:
        kmlwe = hard_mlwe_dim
        #print(f"found MLWE dim : {kmlwe}")
        break


# Find an appropriate Module-SIS dimension
kmsis = 0   # dimension of the MSIS problem
while True:
    kmsis += 1
    m2 = kmlwe + kmsis + l + lmbda / 2 + 1
    stdev2 = gamma2 * mpf(eta) * mpf(nu) * mp.sqrt(m2 * d)
    stdev2 = round_stdev(stdev2)  # XXX
    gamma2 = stdev2 / (mpf(eta) * mpf(nu) * mp.sqrt(m2 * d))  # XXX
    #print(f"d {d}")
    #print(f"2^log2q {2^log2q}")
    #print(f"kmsis {kmsis}")
    #print(f"Bound {Bound()}")
    #print(f"delta {get_delta_msis(Bound(), kmsis, d, 2 ** log2q)}")
    if get_delta_msis(Bound(), kmsis, d, 2 ** log2q) < DELTA128 and Bound() < 2 ** log2q:
        break

# Find the largest possible gamma which makes the MSIS solution still small.
gamma = 2 ** log2q
while True:       # searching for right gamma
    gamma /= 2
    if get_delta_msis(Bound(), kmsis, d, 2 ** log2q) < DELTA128 and Bound() < 2 ** log2q:
        break

# Find exact values for q, q1, gamma and m:
done = false
# q1 = 2L+1 mod 4L
q1 = ceil((2 ** log2q1)/(4*L)) * 4*L + 2*L+1
q1 -= 4*L
while done == False:
    q1 += 4*L
    while is_prime(q1) == False:
        q1 += 4*L
    if n_div == 1:
        q = q1
    elif n_div == 2:
        # q2 = 2L+1 mod 4L
        q2 = ceil((2 ** log2q)/(4*L*q1)) * 4*L + 2*L + 1
        while is_prime(q2) == False:
            q2 += 4*L
        q = q1 * q2
    else:
        assert n_div == 1 or n_div == 2
    Div_q = divisors(q-1)
    for i in Div_q:
        # find a divisor which is close to gamma
        if gamma*4/5 < i and i <= gamma and is_even(i):
            gamma = i
            done = True
m = (q-1) / gamma

# Check q,q1,q2
if n_div == 2:
    if q1.divides(q) == False:
        err("q1 is not a divisor of q")
    q2 = q / q1
    if q1 <= 3 or is_prime(q1) == False:
        err("q1 is not an odd prime")
    if q2 <= 3 or is_prime(q2) == False:
        err("q2 is not an odd prime")
    if not q1 < q2:
        err("q1 is not less than q2")
    if q1 % (4*L) != 2*L+1:
        err(f"q1 != {2*L+1} mod {4*L}")
    if q2 % (4*L) != 2*L+1:
        err(f"q2 != {2*L+1} mod {4*L}")
elif n_div == 1:
    if q <= 3 or is_prime(q) == False:
        err("q is not an odd prime")
    if q % (4*L) != 2*L+1:
        err(f"q != {2*L+1} mod {4*L}")
else:
    assert n_div == 1 or n_div == 2


# Find the largest possible D which makes the MSIS solution small
D = log2q
while True:
    D -= 1
    if get_delta_msis(Bound(), kmsis, d, q) < DELTA128 and Bound() < 2 ** log2q and 2 ** (D-1)*omega*d < gamma:
        break

# update MLWE root hermite factor with exact q
delta_mlwe = get_delta_mlwe(nu, kmlwe, d, q)

M1 = std_gamma2M(gamma1)
M2 = std_gamma2M(gamma2)
M4 = bim_gamma2M(gamma4)
approx_proof = 1
rate = M1 * M2 * ((1-approx_proof) + approx_proof*M4)

printv(f"auto-generated by lnp-quad-eval-codegen.sage from {params_file}.")
printv(f"")

# check completeness conditions ([1], theorem 5.2.17)
if not (m1 * d >= 5*KAPPA and m2 * d >= 5*KAPPA):
    err("protocol not complete")
ecorr = 1 - 1/(M1*M2)
printv(
    f"protocol is statistically complete with correctness error >= 1 - 2^({floor(log(1-ecorr, 2))})")

# check simulatability conditions ([1], theorem 5.2.18)
if not (kmlwe >= 0 and kmlwe == m2 - kmsis - l - lmbda/2 - 1):
    err("protocol not simulatable")
printv(
    f"protocol is simulatable under MLWE({kmlwe},{kmsis+l+lmbda/2+1},[-{nu},{nu}])")  # XXX extended MLWE - yes because stdev 2 is bimodal?

# check knowledge-soundness conditions ([1], theorem 5.2.4)

eknow = mpf(2)/mpf(Csize) + q1 ** (-d/L) + q1 ** (-lmbda)
printv(
    f"protocol is knowledge-sound with knowledge error <= 2^({nstr(mp.ceil(mp.log(eknow,2)),prec)})")

# print params
printv(f"")
printv(f"Ring")
printv(f"degree d = {d}")
printv(f"modulus q = {q}, log(q) ~ {nstr(mp.log(q,2),prec)}")
if n_div == 1:
    printv(f"factors q = q1")
if n_div == 2:
    printv(f"modulus factors q = q1 * q2")
    printv(f"q1 = {q1}, log(q1) ~ {nstr(mp.log(q1,2),prec)}")
    printv(f"q2 = {q1}, log(q2) ~ {nstr(mplog(q2,2),prec)}")
else:
    assert n_div == 1 or n_div == 2
printv(f"")
printv(f"Compression")
printv(f"D = {D}")
printv(f"gamma = {gamma}, log(gamma) ~ {nstr(mp.log(gamma,2),prec)}")
printv(f"m = (q-1)/gamma = {m}, log(m) ~ {nstr(mp.log(m,2),prec)}")
printv(f"")
printv(f"Dimensions of secrets")
printv(f"s1: m1 = {m1}")
printv(f"m: l = {l}")
printv(f"s2: m2 = {m2}")
printv(f"")
printv(f"Size of secrets")
printv(f"l2(s1) <= alpha = {nstr(alpha,prec)}")
printv(f"m unbounded")
printv(f"s2 uniform in [-nu,nu] = [{-nu},{nu}]")
printv(f"")
printv(f"Challenge space")
printv(
    f"c uniform in [-omega,omega] = [{-omega},{omega}], o(c)=c, sqrt(l1(o(c)*c)) <= eta = {eta}")  # XXX square root or 2*k-th root ?
printv(f"")
printv(f"Standard deviations")
printv(
    f"stdev1 = {stdev1}, log(stdev1/1.55) = {mp.log(stdev1/mpf(1.55),2)}")
printv(
    f"stdev2 = {stdev2}, log(stdev2/1.55) = {mp.log(stdev2/mpf(1.55),2)}")
printv(
    f"stdev4 = {stdev4}, log(stdev4/1.55) = {mp.log(stdev4/mpf(1.55),2)}")
printv(f"")
printv(f"Repetition rate")
printv(f"M1 = {nstr(M1,prec)}")
printv(f"M2 = {nstr(M2,prec)}")
printv(f"M4 = {nstr(M4,prec)}")
printv(f"total = {nstr(rate, prec)}")
printv(f"")
printv(f"Security")
printv(f"MSIS dimension: {kmsis}")
printv(
    f"MSIS root hermite factor: {nstr(get_delta_msis(Bound(), kmsis, d, q), prec)}")
printv(f"MLWE dimension: {kmlwe}")
printv(f"MLWE root hermite factor: {nstr(mpf(delta_mlwe), prec)}")
printv(f"")

log2stdev1 = int(mp.log(stdev1/mpf(1.55), 2))
log2stdev2 = int(mp.log(stdev2/mpf(1.55), 2))
log2stdev4 = int(mp.log(stdev4/mpf(1.55), 2))

q_nlimbs = int2limbs(q, -1)[1]
if m % 2 == 0:
    mby2 = m / 2
else:
    mby2 = 0

minP = min_P(d, q, NADDS)
moduli = moduli_list(nbit, d, minP)[0]
assert prod(moduli) >= minP
nmoduli = len(moduli)

Bz4 = floor((T*stdev4*sqrt(256)) ** 2)
#Bz4 = floor(sqrt(2*KAPPA)*stdev4)

out = ""
out += f"""
#include "../lazer/lazer.h"
{int_t(f"{name}_q", q)}
{int_t(f"{name}_qminus1", q - 1)}
{int_t(f"{name}_m", m, q_nlimbs)}
{int_t(f"{name}_mby2", mby2, q_nlimbs)}
{int_t(f"{name}_gamma", gamma, q_nlimbs)}
{int_t(f"{name}_gammaby2", gamma / 2, q_nlimbs)}
{int_t(f"{name}_pow2D", 2^D, q_nlimbs)}
{int_t(f"{name}_pow2Dby2", 2^D / 2, q_nlimbs)}
{int_t(f"{name}_Bsq", floor(Bound_()^2), 2*q_nlimbs)}
{int_t(f"{name}_scM1", int(mp.nint(mpf(2^128) * M1)))}
{int_t(f"{name}_scM2", int(mp.nint(mpf(2^128) * M2)))}
{int_t(f"{name}_scM4", int(mp.nint(mpf(2^128) * M4)))}
{int_t(f"{name}_stdev1sq", int(mp.nint(stdev1^2)), 2*q_nlimbs)}
{int_t(f"{name}_stdev2sq", int(mp.nint(stdev2^2)), 2*q_nlimbs)}
{int_t(f"{name}_stdev4sq", int(mp.nint(stdev4^2)), 2*q_nlimbs)}
{int_t(f"{name}_inv2", redc(inverse_mod(2, q), q))}
{int_t(f"{name}_inv4", redc(inverse_mod(4, q), q))}
{int_t(f"{name}_Bz4", Bz4, 2*q_nlimbs)}
static const polyring_t {name}_ring = {{{{{name}_q, {d}, {ceil(log(q-1,2))}, {log2d}, moduli_d{d}, {nmoduli}, {name}_inv2}}}};
static const dcompress_params_t {name}_dcomp = {{{{ {name}_q, {name}_qminus1, {name}_m, {name}_mby2, {name}_gamma, {name}_gammaby2, {name}_pow2D, {name}_pow2Dby2, {D}, {m % 2}, {ceil(log(m,2))} }}}};
static const abdlop_params_t {name}_quad_eval = {{{{ {name}_ring, {name}_dcomp, {m1}, {m2}, {l}, {lext}, {kmsis}, {name}_Bsq, {nu}, {omega}, {omega_bits}, {eta}, {rejs1}, {log2stdev1}, {name}_scM1, {name}_stdev1sq, {rejs2}, {log2stdev2}, {name}_scM2, {name}_stdev2sq}}}};
static const abdlop_params_t {name}_quad_many = {{{{ {name}_ring, {name}_dcomp, {m1}, {m2}, {l+lmbda/2}, {1}, {kmsis}, {name}_Bsq, {nu}, {omega}, {omega_bits}, {eta}, {rejs1}, {log2stdev1}, {name}_scM1, {name}_stdev1sq, {rejs2}, {log2stdev2}, {name}_scM2, {name}_stdev2sq}}}};
static const lnp_quad_eval_params_t {name} = {{{{ {name}_quad_eval, {name}_quad_many, {lmbda}, {name}_inv4, {log2stdev4}, {name}_scM4, {name}_stdev4sq, {name}_Bz4}}}};
"""

printc(out)

sys.exit(int(0))

# [1] Lattice-Based Zero-Knowledge Proofs Under a Few Dozen Kilobytes XXX
# https://doi.org/10.3929/ethz-b-000574844
