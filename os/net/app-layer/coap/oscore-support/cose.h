/*
 * Copyright (c) 2018, SICS, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *      An implementation of the CBOR Object Signing and Encryption (RFC8152).
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */


#ifndef _COSE_H
#define _COSE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*
 * See RFC8152 for the COSE algorithm definitions
 * https://tools.ietf.org/html/rfc8152#section-13.1
 */
typedef enum {
  COSE_Elliptic_Curve_P256 = 1,
  //COSE_Elliptic_Curve_P384 = 2,
  //COSE_Elliptic_Curve_P512 = 3,

} COSE_Elliptic_Curves_t;

/* https://tools.ietf.org/html/rfc8152#section-8.1 */
typedef enum {
  COSE_Algorithm_ES256 = -7,
  //COSE_Algorithm_ES384 = -35,
  //COSE_Algorithm_ES512 = -36,

} COSE_ECDSA_Algorithms_t;

#define ES256_SIGNATURE_LEN      64
#define ES256_PRIVATE_KEY_LEN    32
#define ES256_PUBLIC_KEY_LEN     64

/*
 * See RFC8152 for the COSE algorithm definitions
 * https://tools.ietf.org/html/rfc8152#page-49
 */

#define COSE_Algorithm_AES_CCM_16_64_128 10
#define COSE_algorithm_AES_CCM_16_64_128_KEY_LEN 16
#define COSE_algorithm_AES_CCM_16_64_128_IV_LEN  13
#define COSE_algorithm_AES_CCM_16_64_128_TAG_LEN  8

#define COSE_Algorithm_AES_CCM_64_64_128 12
#define COSE_algorithm_AES_CCM_64_64_128_KEY_LEN 16
#define COSE_algorithm_AES_CCM_64_64_128_IV_LEN  7
#define COSE_algorithm_AES_CCM_64_64_128_TAG_LEN  8


#define COSE_LARGEST_IV_LENGTH COSE_algorithm_AES_CCM_16_64_128_IV_LEN


/* COSE Encrypt0 Struct */
typedef struct cose_encrypt0_t {

  uint8_t alg;

  uint8_t key_len;
  uint8_t partial_iv_len;
  uint8_t key_id_len;
  uint8_t kid_context_len;
  uint8_t nonce_len;
  uint8_t aad_len;
  uint16_t content_len;


  const uint8_t *key;
  uint8_t partial_iv[8];
  const uint8_t *key_id;
  const uint8_t *kid_context;
  const uint8_t *nonce;
  const uint8_t *aad;
  uint8_t *content;


  // Below is variables för KUDOS algorithm
  uint8_t X;
  uint8_t len_y_nonce;
  const uint8_t *N;
  const uint8_t *y_nonce;

} cose_encrypt0_t;

/* COSE Sign1 Struct */
typedef struct cose_sign1_t {

  uint8_t alg;
  uint8_t alg_param;

  const uint8_t *private_key;
  int private_key_len;

  const uint8_t *public_key;
  int public_key_len;

  uint8_t *ciphertext;
  int ciphertext_len;

  uint8_t *sigstructure;
  int sigstructure_len;

  uint8_t *signature;
  int signature_len;
} cose_sign1_t;

/* Initiate a new COSE Encrypt0 object. */
void cose_encrypt0_init(cose_encrypt0_t *ptr);

void cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg);

/* Return length */
//uint16_t cose_encrypt0_get_content(cose_encrypt0_t *ptr, uint8_t **buffer);
void cose_encrypt0_set_content(cose_encrypt0_t *ptr, uint8_t *buffer, uint16_t size);


/* Return length */
uint8_t cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, const uint8_t **buffer);
void cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size);


/* Return length */
uint8_t cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, const uint8_t **buffer);
void cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size);

void cose_encrypt0_set_aad(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size);

/* Return length */
uint8_t cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, const uint8_t **buffer);
void cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size);


/* Function for KUDOS implementation*/
void cose_encrypt0_set_x_and_n(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size);
/* Function for KUDOS implementation*/
void cose_encrypt0_set_y_nonce(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size);

bool cose_encrypt0_set_key(cose_encrypt0_t *ptr, const uint8_t *key, uint8_t key_size);

void cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size);

int cose_encrypt0_encrypt(cose_encrypt0_t *ptr);
int cose_encrypt0_decrypt(cose_encrypt0_t *ptr);

/* COSE Sign-1 signature functions */

void cose_sign1_init(cose_sign1_t *ptr);

void cose_sign1_set_alg(cose_sign1_t *ptr, uint8_t alg, uint8_t param);

void cose_sign1_set_ciphertext(cose_sign1_t *ptr, uint8_t *buffer, int size);

void cose_sign1_set_public_key(cose_sign1_t *ptr, const uint8_t *buffer);

void cose_sign1_set_private_key(cose_sign1_t *ptr, const uint8_t *buffer);

/* Return length */
int cose_sign1_get_signature(cose_sign1_t *ptr, uint8_t **buffer);

void cose_sign1_set_signature(cose_sign1_t *ptr, uint8_t *buffer);

int cose_sign1_sign(cose_sign1_t *ptr);

void cose_sign1_set_sigstructure(cose_sign1_t *ptr, uint8_t *buffer, int size);

int cose_sign1_verify(cose_sign1_t *ptr);


size_t cose_curve_public_key_length(COSE_Elliptic_Curves_t curve);
size_t cose_curve_private_key_length(COSE_Elliptic_Curves_t curve);


#endif /* _COSE_H */
