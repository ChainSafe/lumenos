import sys

sizeof_limb = 8
suffix_limb = "UL"

R = 2 ** 64  # montgomery modulus (hard-coded, dont change)
max_proofsystem_modulus = 2 ** 256 - 1
max_adds = 1024  # max adds/subs in crt domain
nbit = 50 # XXX  # bit-length of moduli


# Print if verbose == 1.
def printv(x):
    global verbose
    if verbose == 1:
        print(f"// {x}")


# Print if code == 1.
def printc(x):
    global code
    if code == 1:
        print(x)


# codegen: sage list of integers to array of integers
def intlist2intarray(list):
    return str(list).replace('[', '{').replace(']', '}')


# codegen: sage list of strings to array of pointers
def strlist2ptrarray(list):
    return str(list).replace('[', '{').replace(']', '}').replace("'", "")


# codegen: sage integer to arrays of limbs
# optionally 0-padd to nlimbs
def int2limbs(z, nlimbs=-1):
    global suffix_limb
    global sizeof_limb
    if z == 0:
        list = [0]
        array = intlist2intarray(list)
        neg = 0
        return array, len(list), neg
    if z < 0:
        z = -z
        neg = 1
    else:
        neg = 0
    list = []
    while z != 0:
        q = int(z / (2 ** (8 * sizeof_limb)))
        r = z - q * (2 ** (8 * sizeof_limb))
        list = list + [r]
        z = q
    if nlimbs != -1:
        assert (nlimbs > 0 and nlimbs >= len(list))
        while len(list) < nlimbs:
            list += [0]

    list = [f"{x}{suffix_limb}" for x in list]
    array = str(list).replace("'", "").replace('[', '{').replace(']', '}')
    return array, len(list), neg


# codegen: sage int to int_t
# optionally 0-padd to nlimbs
def int_t(name, val, nlimbs=-1):
    limbs, nlimbs, neg = int2limbs(val, nlimbs)
    out = f"static const limb_t {name}_limbs[] = {limbs};\n"
    out += f"static const int_t {name} = {{{{(limb_t *){name}_limbs, {nlimbs}, {neg}}}}};"
    return out


# First: for d a power of 2, return a list of primes in decreasing order.
# Each prime p has nbit bits (or less) and p = 1 mod 2*d. The product
# of the primes is greater than prodmin.
# Second: return a list of bit-lengths where the i-th position is the
# bit-length of ints that can be represented modulo the product
# of elements 0 to i of the prime list.
# Third: return a list of inverses where the i-th position is the
# inverse of the product of elements 0 to i-1 of the prime list
# modulp element i of the prime list.
def moduli_list(nbit, d, prodmin):
    l = []
    l2 = []
    l3 = []
    prod = 1
    # first candidate i greatest number less than or equal to
    # 2^nbits-1 that is congruent to 1 mod 2*d.
    cand = floor((2 ** nbit - 2) / (2 * d)) * (2 * d) + 1
    while prod < prodmin:
        assert "not enough primes" and cand > 2
        if is_prime(cand):
            prime = cand
            l = l + [prime]
            l3 = l3 + [redc(Mod(1/prod, prime), prime)]
            prod *= prime
            l2 = l2 + [floor(log(prod-1, 2))]
        cand -= 2 * d
    printv(f"{nbit} bit moduli for degree {d}: {l}")
    printv(f"bit length of products: {l2}")
    printv(f"inverses: {l3}")
    return l, l2, l3


# Return minimum modulus P to lift to from a smaller modulus
# q such that sum of nadds products of two polynomials in Rq
# does not wrap.
def min_P(d, q, nadds):
    return (q - 1) ** 2 * d * nadds + 1


# For prime p, reduce z mod p and return centered representation
# in [-(p-1)/2,(p-1)/2].
def redc(z, p):
    z = int(int(z) % int(p))
    if z > (p-1)/2:
        z = z - p
    if z < -(p-1)/2:
        z = z + p
    return z


# For even p, reduce z mod p and return centered representation
# in [-p/2,p/2).
def redc_even(z, p):
    z = int(int(z) % int(p))
    if z >= p/2:
        z = z - p
    if z < -p/2:
        z = z + p
    return z


# For prime p, return centered representation of r*r % p.
def mont_redr(r, p):
    r = redc((r*r) % p, p)
    printv(f"montgomery mul param: R^2 mod p: {r}")
    return r


# For prime p, return centered representation of 1/p % r.
def mont_pinv(p, r):
    pinv = redc_even(Mod(1/p, r), r)
    printv(f"montgomery mul param: p^(-1) mod R: {pinv}")
    return pinv


# For prime p, return 1/d % p.
def intt_const(d, p):
    inttc = redc(Mod(1/d, p), p)
    printv(f"intt param: p^(-1) mod R: {inttc}")
    return inttc


# For d a power of 2, return list of exponents in [0,d-1] in bitreversed
# order i.e., exponents with greater powers of two in their prime
# factorization go first.
def bitrev_exps(d):
    log2d = log(d, 2)
    # sage's bits() output is least- to most-significant bit.
    # python's int() input is most- to least-significant bit.
    # So l is aleary in bitreversed order from initialization
    # and just has to be zero-padded to log2d bits to the right.
    l = [ZZ(x).bits() for x in range(2 ** log2d)]
    for i in range(len(l)):
        while (len(l[i]) < log2d):
            l[i] = l[i] + [0]
    for i in range(len(l)):
        l[i] = int("".join(str(x) for x in l[i]), 2)
    printv(f"exponents in bitrev order: {l}")
    return l


# For prime p = 1 mod 2*d, d a power of 2, find the smallest element of
# order 2*d in Zp* i.e. the smalles primitive 2d'th root of unity.
# For prime p Zp* is cyclic and of order p-1. In a cyclic group there
# is excactly one subgroup for each divisor of its order, so if 2*d | p-1
# such an element exists. For any generator g of Zp*, w = g^((p-1)/(2*d))
# has order 2*d, and also all its powers coprime to 2*d i.e., all odd
# powers. So the first 2*d odd powers (in [1,4*d-1]) of w form the
# subgrpup of elements of order 2*d and we search for the smallest.
# "Smallest" refers to the element's infinity norm, that is, the
# absolute value of its centered representation in [-(p-1)/2,(p-1)/2].
def min_root(d, p):
    g = primitive_root(p)  # get a generator of Zp* (order p-1)
    g = Mod(g,p)
    w = g ^ ((p-1) / (2*d))   # get an element of order 2*d
    w = redc(int(w),p)
    min_w = w
    cand_w = w
    for i in range(2*d):
        if abs(cand_w) < abs(min_w):
            min_w = cand_w
        cand_w = redc(cand_w * w ** 2, p)
    printv(f"min 2*{d}-th primitive root of 1 in Z{p}*: {min_w}")
    return min_w


# Returns a list of root raised to the powers in list exps and multiplied
# by mont in Zp.
def root_list(root, exps, p, mont):
    l = []
    for e in exps:
        l = l + [redc((root ** e) * mont, p)]
    printv(f"root list: {l}")
    return l


# Estimating MLWE hardness: Distinguish (A, A*s mod q) from (A,b)
# where A in Rq^(m x n), coefficients of s sampled uniformly between
# -nu and nu. Returns the root hermite factor.
# XXX add references
# XXX update to new LWE estimator
# def get_delta_mlwe_new(nu, n, d, q):
#    n = n * d
#    lweparams = LWE.Parameters(
#        n, q, ND.Uniform(-nu, nu), ND.Uniform(-nu, nu), n)
#    L = LWE.estimate(lweparams)
def get_delta_mlwe(nu, n, d, q):
    #XXXload("https://bitbucket.org/malb/lwe-estimator/raw/HEAD/estimator.py")
    load("../third_party/estimator.py")
    n = n * d
    stdev = mp.sqrt(mpf((2*nu+1) ** 2 - 1)/mpf(12))
    alpha = alphaf(sigmaf(stdev), q)
    # set_verbose(1)
    L = estimate_lwe(n, alpha, q, reduction_cost_model=BKZ.enum)
    delta_enum1 = L['usvp']['delta_0']
    delta_enum2 = L['dec']['delta_0']
    delta_enum3 = L['dual']['delta_0']
    L = estimate_lwe(n, alpha, q, reduction_cost_model=BKZ.sieve)
    delta_sieve1 = L['usvp']['delta_0']
    delta_sieve2 = L['dec']['delta_0']
    delta_sieve3 = L['dual']['delta_0']
    return max(delta_enum1, delta_enum2, delta_enum3, delta_sieve1, delta_sieve2, delta_sieve3)


# Estimate MSIS hardness: Find non-zero s such that A*s = 0 for
# A in Rq^(n x m) and |s| <= beta. Returns the root hermite factor.
# XXX add references
def get_delta_msis(beta, n, d, q):
    log2q = log(q, 2)
    log2beta = mp.log(beta, 2)
    delta = mpf(2) ** (log2beta ** 2 / mpf(4*n*d*log2q))
    return delta


def std_gamma2M(gamma):
    global KAPPA
    x = mp.sqrt(mpf(2*(KAPPA+1))/mp.log(mp.e, 2))
    return mp.exp(x * 1/gamma + 1/(2*gamma ** 2))


def std_M2gamma(M):
    global KAPPA
    x = mp.sqrt(mpf(2*(KAPPA+1))/mp.log(mp.e, 2))
    return mp.sqrt(mpf(1)/(mpf(2)*mp.log(M)) + (x/(mpf(2)*mp.log(M))) ** 2) + x/(mpf(2)*mp.log(M))


def bim_gamma2M(gamma):
    return mp.exp(mpf(1)/mpf((2*gamma ** 2)))


def bim_M2gamma(M):
    return mp.sqrt(mpf(1)/(mpf(2)*mp.log(M)))


# Round to closest standard deviation we can sample.
# That is standard deviations of the form 1.55*2^x
def round_stdev(stdev):
    log2stdev = mp.log(stdev / mpf(1.55), 2)
    lo = mpf(1.55) * 2 ** mp.floor(log2stdev)
    hi = mpf(1.55) * 2 ** mp.ceil(log2stdev)
    if stdev - lo <= hi - stdev:
        return lo
    else:
        return hi


# print error and exit
def err(x):
    global codegen_err
    global loaded

    print(f"error: {x}", file=sys.stderr) # XXX
    if not loaded:
        sys.exit(int(1))
    codegen_err = 1
