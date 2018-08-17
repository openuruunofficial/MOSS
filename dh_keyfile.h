/*
  MOSS - A server for the Myst Online: Uru Live client/protocol
  Copyright (C) 2018  a'moaca'

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * The following OpenSSL ASN1 goo is because OpenSSL does not already have
 * functions to write out the D-H parameters as needed by the modified D-H
 * we have.
 */

#ifndef _KEYFILE_H
#define _KEYFILE_H

//#include <openssl/bn.h>
//#include <openssl/asn1t.h>
//#include <openssl/bio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  BIGNUM *p;
  BIGNUM *g;
  BIGNUM *priv_key;
} dh_params;

dh_params * create_dh_params() {
  dh_params *params = (dh_params*)malloc(sizeof(dh_params));
  memset(params, 0, sizeof(dh_params));
  return params;
}

/*
 * The OpenSSL accessors adopt the pointers of BIGNUMs passed to them.
 * So we may want to leak them. In error cases we don't want to do
 * that, so we have this cleanup function.
 */
void cleanup_dh_params(dh_params *params) {
  if (params->p) BN_free(params->p);
  if (params->g) BN_free(params->g);
  if (params->priv_key) BN_free(params->priv_key);
}

#if OPENSSL_VERSION_NUMBER >= 0x00909000L
static int cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
	      void *exarg)
#else
static int cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it)
#endif
{
  if (operation == ASN1_OP_NEW_PRE) {
    *pval = (ASN1_VALUE *)create_dh_params();
    if(*pval) return 2;
    return 0;
  } else if(operation == ASN1_OP_FREE_PRE) {
    dh_params *params = (dh_params*)*pval;
    cleanup_dh_params(params);
    free(params);
    *pval = NULL;
    return 2;
  }
  return 1;
}

ASN1_SEQUENCE_cb(CyanDHParams, cb) = {
  ASN1_SIMPLE(dh_params, p, BIGNUM),
  ASN1_SIMPLE(dh_params, g, BIGNUM),
  ASN1_SIMPLE(dh_params, priv_key, BIGNUM)
} ASN1_SEQUENCE_END_cb(dh_params, CyanDHParams)
IMPLEMENT_ASN1_FUNCTIONS_name(dh_params, CyanDHParams)

#define i2d_CyanDHParams_bio(bp,x) \
  ASN1_i2d_bio_of(dh_params, i2d_CyanDHParams, bp, x)
#define d2i_CyanDHParams_bio(bp,x) \
  ASN1_d2i_bio_of(dh_params, create_dh_params, d2i_CyanDHParams, bp, x)

#ifdef __cplusplus
}
#endif

#endif /* _KEYFILE_H */
