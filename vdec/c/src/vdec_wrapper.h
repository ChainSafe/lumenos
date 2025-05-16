#ifndef VDEC_WRAPPER_H
#define VDEC_WRAPPER_H

#include "../lazer/lazer.h"
#include "vdec_params.h"
#include <stdint.h>
#include <stdlib.h>

// typedef struct {
//     polyvec_ptr zv;
//     int_ptr bz4_squared;
// } ZvBoundProof;

// typedef struct {
//     polyvec_ptr h_our;
//     unsigned int degree_div_2;
// } HOurCoeffProof;

// typedef struct {
//     uint8_t hashv[32];
//     poly_ptr c;
//     polyvec_ptr z1;
//     polyvec_ptr z21;
//     polyvec_ptr hint;
//     polyvec_ptr tA1;
//     polyvec_ptr tB;
//     polymat_ptr A1;
//     polymat_ptr A2prime;
//     polymat_ptr Bprime;
//     spolymat_ptr* R2prime_sz;
//     spolyvec_ptr* r1prime_sz;
//     poly_ptr* r0prime_sz;
//     unsigned int num_equations;
//     abdlop_params_srcptr quad_many_params;
// } LnpQuadManyProof;

// typedef struct {
//     ZvBoundProof zv_bound_proof;
//     HOurCoeffProof h_our_coeff_proof;
//     LnpQuadManyProof lnp_quad_many_proof;
// } VdecProof;

#ifdef __cplusplus
extern "C"
{
#endif

    polyring_srcptr GetRqFromVdecParams1(void);
    
    polyvec_struct *CreatePolyvec(polyring_srcptr Rq, unsigned int nelems);
    void FreePolyvec(polyvec_struct *pv_s_ptr);
    void SetPolyvecPolyCoeffs(polyvec_struct *pv_s_ptr, unsigned int poly_index, int64_t *coeffs_data, unsigned int num_coeffs);
    unsigned int GetPolyvecNelems(polyvec_struct *pv_s_ptr);
    polyring_srcptr GetPolyvecRing(polyvec_struct *pv_s_ptr);

    void ProveVdecLnpTbox(
        uint8_t seed[32],
        polyvec_struct *sk,
        int8_t sk_sign[],
        unsigned int sk_sign_len,
        polyvec_struct *ct0,
        polyvec_struct *ct1,
        polyvec_struct *m_delta,
        unsigned int fhe_degree
    );

#ifdef __cplusplus
}
#endif

#endif
