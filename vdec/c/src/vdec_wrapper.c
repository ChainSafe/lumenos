#include "vdec_wrapper.h"
#include "../lazer/src/memory.h"
#include <stdio.h>

int vdec_lnp_tbox(uint8_t seed[32], const lnp_quad_eval_params_t params,
                   polyvec_t sk, int8_t sk_sign[], polyvec_t ct0, polyvec_t ct1,
                   polyvec_t m_delta, unsigned int fhe_degree);

// verify_vdec_lnp_tbox is declared in vdec_wrapper.h now

polyring_srcptr GetRqFromVdecParams1(void)
{
    return params1->quad_eval->ring;
}

polyvec_struct *CreatePolyvec(polyring_srcptr Rq, unsigned int nelems)
{
    polyvec_struct *pv_s_ptr = (polyvec_struct *)malloc(sizeof(polyvec_struct));
    if (!pv_s_ptr)
    {
        fprintf(stderr, "CreatePolyvec: Failed to allocate memory for polyvec_struct struct\n");
        return NULL;
    }
    polyvec_alloc(pv_s_ptr, Rq, nelems);
    return pv_s_ptr;
}

void FreePolyvec(polyvec_struct *pv_s_ptr)
{
    if (pv_s_ptr)
    {
        polyvec_free((polyvec_ptr)pv_s_ptr);
        free(pv_s_ptr);
    }
}

void SetPolyvecPolyCoeffs(polyvec_struct *pv_s_ptr, unsigned int poly_index, int64_t *coeffs_data, unsigned int num_coeffs)
{
    polyvec_ptr pv = (polyvec_ptr)pv_s_ptr;
    if (!pv || poly_index >= pv->nelems)
    {
        fprintf(stderr, "SetPolyvecPolyCoeffs: Invalid poly_index or null polyvec\n");
        return;
    }

    poly_ptr poly = polyvec_get_elem(pv, poly_index);
    intvec_ptr c_coeffs = poly_get_coeffvec(poly);
    polyring_srcptr Rq = pv->ring;
    unsigned int poly_degree = polyring_get_deg(Rq);

    if (num_coeffs > poly_degree)
        num_coeffs = poly_degree;

    for (unsigned int i = 0; i < num_coeffs; ++i)
        intvec_set_elem_i64(c_coeffs, i, coeffs_data[i]);
}

unsigned int GetPolyvecNelems(polyvec_struct *pv_s_ptr)
{
    if (!pv_s_ptr)
        return 0;
    return ((polyvec_ptr)pv_s_ptr)->nelems;
}

polyring_srcptr GetPolyvecRing(polyvec_struct *pv_s_ptr)
{
    if (!pv_s_ptr)
        return NULL;
    return ((polyvec_ptr)pv_s_ptr)->ring;
}

int ProveVdecLnpTbox(
    uint8_t seed[32],
    polyvec_struct *sk_s_ptr,
    int8_t sk_sign[],
    unsigned int sk_sign_len,
    polyvec_struct *ct0_s_ptr,
    polyvec_struct *ct1_s_ptr,
    polyvec_struct *m_delta_s_ptr,
    unsigned int fhe_degree)
{
    (void)sk_sign_len;

    return vdec_lnp_tbox(seed, params1, sk_s_ptr, sk_sign,
                  ct0_s_ptr, ct1_s_ptr,
                  m_delta_s_ptr, fhe_degree);
}
