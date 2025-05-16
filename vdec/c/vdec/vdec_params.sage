name = "params1"                                # param variable name

# log2q should be greater than log2(fhe_ctxt_mod) + 2 + log2((d+3)/2) 
# log2((d+3)/2) is 6(if d=64) or 7(if d=128)
log2q = 68                                       # ring modulus bits
#log2q = 40                                       # ring modulus bits 
d = 64                                           # ring degree

#m1 = 32                                          # length of bounded message s1
m1 = 48
alpha = 1                       # bound on s1: l2(s1) <= alpha
l = 5                                           # length of unbounded message m
#l = 3
# l = 32 * nr ciphertexts + y_s, y_l, y_v, beta_s, beta_l, beta_v

# gamma1 = 10
# gamma2 = 10
# gamma4 = 5
