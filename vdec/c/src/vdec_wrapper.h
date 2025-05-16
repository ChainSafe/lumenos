#ifndef VDEC_WRAPPER_H
#define VDEC_WRAPPER_H

#include "../lazer/lazer.h"
#include "vdec_params.h"
#include <stdint.h>
#include <stdlib.h>

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

    int ProveVdecLnpTbox(
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
