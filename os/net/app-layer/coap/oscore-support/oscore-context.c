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
 *      An implementation of the Object Security for Constrained RESTful Enviornments (Internet-Draft-15) .
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */


#include "oscore-context.h"
#include <stddef.h>
#include "lib/memb.h"
#include "lib/list.h"
#include <string.h>
#include "oscore-crypto.h"
#include "oscore.h"
#include "assert.h"

#include "oscore-nanocbor-helper.h"

#include <stdio.h>

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "oscore"
#define LOG_LEVEL LOG_LEVEL_COAP

#ifndef OSCORE_MAX_ID_CONTEXT_LEN
#define OSCORE_MAX_ID_CONTEXT_LEN 16
#endif

MEMB(exchange_memb, oscore_exchange_t, TOKEN_SEQ_NUM);

LIST(common_context_list);
LIST(exchange_list);

app_b2_nonces_t nonces = {
  .kid_context_nonce = NULL,        // Pointer initialized to NULL
  .len_kid_context_nonce = 0,       // Length initialized to 0
  .aead_nonce = NULL,                // Pointer initialized to NULL
  .len_aead_nonce = 0                // Length initialized to 0
};

kudos_variables_t kudos_nonces = {
  .kudos_running= false,
  .N = NULL,
  .X = 0,
  .y_nonce = NULL,
  .len_y_nonce = 0,
  .ctx_old = NULL
};


static void
printf_hex_detailed(const char* name, const uint8_t *data, size_t len)
{
  LOG_DBG("%s (len=%zu): ", name, len);
  LOG_DBG_BYTES(data, len);
  LOG_DBG_("\n");
}

#define INFO_BUFFER_LENGTH ( \
  1 + /* array */ \
  1 + OSCORE_SENDER_ID_MAX_SUPPORTED_LEN + /* bstr, identity maximum length */ \
  1 + OSCORE_MAX_ID_CONTEXT_LEN + /* bstr, id context maximum length */ \
  1 + /* algorithm */ \
  1 + 3 + /* tstr, "Key" or "IV" */ \
  1 /* int, output length */ \
)

void
oscore_ctx_store_init(void)
{
  list_init(common_context_list);
}

static uint8_t
compose_info(
  uint8_t *buffer, uint8_t buffer_len,
  uint8_t alg,
  const uint8_t *id, uint8_t id_len,
  const uint8_t *id_context, uint8_t id_context_len,
  const char* kind,
  uint8_t out_len)
{
  nanocbor_encoder_t enc;
  nanocbor_encoder_init(&enc, buffer, buffer_len);

  NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 5));
  NANOCBOR_CHECK(nanocbor_put_bstr(&enc, id, id_len));
  if(id_context != NULL && id_context_len > 0) {
    NANOCBOR_CHECK(nanocbor_put_bstr(&enc, id_context, id_context_len));

  } else {
    NANOCBOR_CHECK(nanocbor_fmt_null(&enc));
  }

  NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, alg));
  NANOCBOR_CHECK(nanocbor_put_tstr(&enc, kind));
  NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, out_len));
  return nanocbor_encoded_len(&enc);
}


static uint8_t
compose_Expandlabel(uint8_t *buffer, uint8_t buffer_len, char *label, const uint8_t *context, uint8_t context_len, uint8_t oscore_key_length)
{ 

  uint16_t oscore_key_lengthened = oscore_key_length; 
  uint8_t zeros = 0;
  uint8_t oscore_key_length_size = sizeof(uint16_t);
  char pre_label[] = "oscore "; // Include the null terminator
  uint8_t pre_label_len = strlen(pre_label);
  uint8_t label_len = strlen(label);
  
  /* HERE CHANGE */
  char combined_label[pre_label_len + label_len + 1]; 
  strcpy(combined_label, pre_label); 
  strcat(combined_label, label); 
  uint8_t combined_label_len = strlen(combined_label);

  uint8_t expandlabel_len = oscore_key_length_size + combined_label_len + context_len ;

  if (expandlabel_len > buffer_len) {
    LOG_ERR("Expandlabel too long");
  }

  LOG_DBG("OSCORE_KEY_LENGTH : %u\n\n", oscore_key_lengthened);

  // Store both bytes of oscore_key_lengthened
  //memcpy(buffer, &oscore_key_lengthened, sizeof(oscore_key_lengthened)); 
  memcpy(buffer, &zeros, 1);
  memcpy(buffer + 1, &oscore_key_length, 1);


  // Combine pre_label and label into a single string
  memcpy(buffer + oscore_key_length_size, combined_label, combined_label_len);
  memcpy(buffer + oscore_key_length_size + combined_label_len , context, context_len);
  /*
  
  memcpy(buffer + oscore_key_length_size, pre_label, pre_label_len);
  memcpy(buffer + oscore_key_length_size + pre_label_len, label, label_len);
  memcpy(buffer + oscore_key_length_size + pre_label_len + label_len, context, context_len);
  */

  return expandlabel_len;
}

static bool
bytes_equal(const uint8_t *a_ptr, uint8_t a_len, const uint8_t *b_ptr, uint8_t b_len)
{
  return a_len == b_len && memcmp(a_ptr, b_ptr, a_len) == 0;
}

#ifdef WITH_GROUPCOM
void
oscore_derive_ctx(oscore_ctx_t *common_ctx,
  const uint8_t *master_secret, uint8_t master_secret_len,
  const uint8_t *master_salt, uint8_t master_salt_len,
  uint8_t alg,
  const uint8_t *sid, uint8_t sid_len,
  const uint8_t *rid, uint8_t rid_len,
  const uint8_t *id_context, uint8_t id_context_len,
  const uint8_t *gid)
#else
void
oscore_derive_ctx(oscore_ctx_t *common_ctx,
  const uint8_t *master_secret, uint8_t master_secret_len,
  const uint8_t *master_salt, uint8_t master_salt_len,
  uint8_t alg,
  const uint8_t *sid, uint8_t sid_len,
  const uint8_t *rid, uint8_t rid_len,
  const uint8_t *id_context, uint8_t id_context_len)
#endif
{
  uint8_t info_buffer[INFO_BUFFER_LENGTH];
  uint8_t info_len;

  if (id_context_len > OSCORE_MAX_ID_CONTEXT_LEN)
  {
    LOG_WARN("Please decrease OSCORE_MAX_ID_CONTEXT_LEN to be at maximum %" PRIu8 "\n", id_context_len);
  }
  printf_hex_detailed("master secret: ", master_secret, master_secret_len);
  printf_hex_detailed("master salt: ", master_salt, master_salt_len);
  printf_hex_detailed("id_context: ", id_context, id_context_len);
  printf_hex_detailed("sid: ", sid, sid_len);
  printf_hex_detailed("rid: ", rid, rid_len);
  



  /* sender_key */
  info_len = compose_info(info_buffer, sizeof(info_buffer), alg, sid, sid_len, id_context, id_context_len, "Key", CONTEXT_KEY_LEN);
  LOG_DBG("info_len =%u \n\n", info_len );
  assert(info_len > 0);
  hkdf(master_salt, master_salt_len,
       master_secret, master_secret_len,
       info_buffer, info_len,
       common_ctx->sender_context.sender_key, CONTEXT_KEY_LEN);
  printf_hex_detailed("sender key: ", common_ctx->sender_context.sender_key, 16);

  /* Receiver key */
  info_len = compose_info(info_buffer, sizeof(info_buffer), alg, rid, rid_len, id_context, id_context_len, "Key", CONTEXT_KEY_LEN);
  assert(info_len > 0);
  hkdf(master_salt, master_salt_len,
       master_secret, master_secret_len,
       info_buffer, info_len,
       common_ctx->recipient_context.recipient_key, CONTEXT_KEY_LEN);
  printf_hex_detailed("recipient key: ", common_ctx->recipient_context.recipient_key, 16);

  /* common IV */
  info_len = compose_info(info_buffer, sizeof(info_buffer), alg, NULL, 0, id_context, id_context_len, "IV", CONTEXT_INIT_VECT_LEN);
  assert(info_len > 0);
  hkdf(master_salt, master_salt_len,
       master_secret, master_secret_len,
       info_buffer, info_len,
       common_ctx->common_iv, CONTEXT_INIT_VECT_LEN);

  common_ctx->master_secret = master_secret;
  common_ctx->master_secret_len = master_secret_len;
  common_ctx->master_salt = master_salt;
  common_ctx->master_salt_len = master_salt_len;
  common_ctx->alg = alg;

#ifdef WITH_GROUPCOM 
  common_ctx->gid = gid;
#endif

  common_ctx->sender_context.sender_id = sid;
  common_ctx->sender_context.sender_id_len = sid_len;
  common_ctx->sender_context.seq = 0; /* rfc8613 Section 3.2.2 */

  common_ctx->recipient_context.recipient_id = rid;
  common_ctx->recipient_context.recipient_id_len = rid_len;

  oscore_sliding_window_init(&common_ctx->recipient_context.sliding_window);

  list_add(common_context_list, common_ctx);
}


void
oscore_free_ctx(oscore_ctx_t *ctx)
{
  list_remove(common_context_list, ctx); 
  memset(ctx, 0, sizeof(*ctx));
}

oscore_ctx_t *
oscore_find_ctx_by_rid(const uint8_t *rid, uint8_t rid_len)
{
  oscore_ctx_t *ptr = NULL;
  for(ptr = list_head(common_context_list); ptr != NULL; ptr = list_item_next(ptr)){
    if(bytes_equal(ptr->recipient_context.recipient_id, ptr->recipient_context.recipient_id_len, rid, rid_len)) {
      return ptr;
    }
  }
  return NULL;
} 

oscore_ctx_t *
oscore_updateCtx(const uint8_t *X,uint8_t len_X, const uint8_t *N,uint8_t len_N, oscore_ctx_t *old_Ctx)
{


  static oscore_ctx_t CTX_OUT;     // The new Security Context
  uint8_t *MSECRET_NEW;   // The new Master Secret
  const uint8_t *MSALT_NEW = N;    // The new Master Salt  
  uint8_t X_cbor_len = len_X + 1;
  uint8_t *X_cbor;
  uint8_t N_cbor_len = len_N + 1;
  if(len_N > 23){
    N_cbor_len += 2;
  }
  uint8_t *N_cbor;
  uint8_t len_X_N = X_cbor_len + N_cbor_len; 
  uint8_t *X_N = malloc(len_X_N * sizeof(uint8_t));
  
  X_cbor = oscore_cbor_byte_string(X,len_X);
  N_cbor = oscore_cbor_byte_string(N, len_N);
  memcpy(X_N,X_cbor,X_cbor_len);
  memcpy(X_N + X_cbor_len,N_cbor,N_cbor_len);
  
  
  uint8_t oscore_key_length = old_Ctx->master_secret_len;

  char *label = "key update";
  uint8_t expandlabel[HKDF_INFO_MAXLEN];
  uint8_t expandlabel_len = compose_Expandlabel(expandlabel,HKDF_INFO_MAXLEN, label, X_N, len_X_N, oscore_key_length);
  MSECRET_NEW = malloc(oscore_key_length*sizeof(u_int8_t));
  printf_hex_detailed("X_N is: ",X_N,len_X_N);
  LOG_DBG("\n");
  const uint8_t *sender_id = old_Ctx->sender_context.sender_id;
  uint8_t sender_id_len = old_Ctx->sender_context.sender_id_len;
  const uint8_t *reciever_id = old_Ctx->recipient_context.recipient_id;
  uint8_t reciever_id_len = old_Ctx->recipient_context.recipient_id_len;
  uint8_t alg = old_Ctx->alg;
  printf_hex_detailed("old secret :",old_Ctx->master_secret, oscore_key_length );
  LOG_DBG("\n");
  hkdf_expand(old_Ctx->master_secret, oscore_key_length,expandlabel, expandlabel_len, MSECRET_NEW, oscore_key_length);
  printf_hex_detailed("Master secret new : ", MSECRET_NEW, oscore_key_length);
  LOG_DBG("\n");
  oscore_kudos_free_ctx(old_Ctx);
  oscore_derive_ctx(&CTX_OUT, MSECRET_NEW, oscore_key_length, MSALT_NEW, len_N, alg, sender_id, sender_id_len,reciever_id, reciever_id_len, NULL, 0 );

  return &CTX_OUT;
}


/* Token <=> SEQ association */
void
oscore_exchange_store_init(void)
{
  memb_init(&exchange_memb);
  list_init(exchange_list);
}

oscore_exchange_t*
oscore_get_exchange(const uint8_t *token, uint8_t token_len)
{
  for(oscore_exchange_t *ptr = list_head(exchange_list); ptr != NULL; ptr = list_item_next(ptr)) {
    if(bytes_equal(ptr->token, ptr->token_len, token, token_len)) {
      return ptr;
    }
  }
  return NULL;
}

bool
oscore_set_exchange(const uint8_t *token, uint8_t token_len, uint64_t seq, oscore_ctx_t *context)
{
  if (token_len > COAP_TOKEN_LEN)
  {
    LOG_ERR("Token too long %" PRIu8 " > %" PRIu8 "\n", token_len, COAP_TOKEN_LEN);
    return false;
  }

  oscore_exchange_t *new_exchange = memb_alloc(&exchange_memb);
  if (new_exchange == NULL) {
    /* If we are at capacity for Endpoint <-> Context associations: */
    LOG_WARN("oscore_set_exchange: out of memory, will try to make room\n");

    /* Remove first element in list, to make space for a new one. */
    /* The head of the list contains the oldest inserted item,
     * so most likely to never be coming back to us */
    new_exchange = list_pop(exchange_list);

    if (new_exchange == NULL) {
      LOG_ERR("oscore_set_exchange: failed to make room\n");
      return false;
    }
  }

  memcpy(new_exchange->token, token, token_len);
  new_exchange->token_len = token_len;
  new_exchange->seq = seq;
  new_exchange->context = context;

  /* Add to end of the exchange list */
  list_add(exchange_list, new_exchange);

  return true;
}

void
oscore_remove_exchange(const uint8_t *token, uint8_t token_len)
{
  oscore_exchange_t *ptr = oscore_get_exchange(token, token_len);
  if (ptr) {
    list_remove(exchange_list, ptr);
    memb_free(&exchange_memb, ptr);
  }
}

void
oscore_appendixb2_set_nonce_kidcontext(const uint8_t *new_nonce, uint8_t len_nonce)
{
  nonces.kid_context_nonce = new_nonce;
  nonces.len_kid_context_nonce = len_nonce;
}

void
oscore_appendixb2_set_nonce_aead(const uint8_t *new_nonce, uint8_t len_nonce)
{
  nonces.aead_nonce = malloc(sizeof(uint8_t) * len_nonce);
  memcpy(nonces.aead_nonce, new_nonce, len_nonce);
  nonces.len_aead_nonce = len_nonce;
}

void
oscore_kudos_set_N_and_X(uint8_t *new_nonce, uint8_t X)
{
  kudos_nonces.N = malloc(sizeof(uint8_t ) * ((X & 0x0f) + 1));
  memcpy(kudos_nonces.N,new_nonce,(X & 0x0f) + 1);
  kudos_nonces.X = X;
}

void
oscore_kudos_set_nonce_y(uint8_t *new_nonce, uint8_t len_nonce)
{
  kudos_nonces.y_nonce = malloc(sizeof(uint8_t ) * len_nonce);
  memcpy(kudos_nonces.y_nonce,new_nonce,len_nonce);
  kudos_nonces.len_y_nonce = len_nonce;
}

void
oscore_kudos_true(void)
{
  kudos_nonces.kudos_running = true;
}

void
oscore_kudos_false(void)
{
  kudos_nonces.kudos_running = false;
}

kudos_variables_t
oscore_kudos_get_variables(void)
{
  return kudos_nonces;
}

void
oscore_kudos_free_ctx(oscore_ctx_t *ctx)
{
  list_remove(common_context_list, ctx); 
}

void
oscore_kudos_set_old_ctx(oscore_ctx_t *ctx)
{
  kudos_nonces.ctx_old = ctx;
}

uint8_t *
oscore_cbor_byte_string(const uint8_t *byte_string, const uint8_t len_byte_string)
{ 
  uint8_t enc_byte_string_len; 
  if(len_byte_string > 23){
    enc_byte_string_len = len_byte_string + 2;
  }else {
    enc_byte_string_len = len_byte_string + 1;
  }
  uint8_t *enc_byte_string = malloc(enc_byte_string_len * sizeof(uint8_t));
  nanocbor_encoder_t enc;
  nanocbor_encoder_init(&enc, enc_byte_string , (enc_byte_string_len * sizeof(uint8_t)));
  if(nanocbor_put_bstr(&enc, byte_string,len_byte_string * sizeof(uint8_t))!= NANOCBOR_OK){
    LOG_ERR("Did not encode byte string");
  }
  return enc_byte_string;
}


app_b2_nonces_t
oscore_appendixb2_get_nonces(void)
{
  return nonces;
}

#ifdef WITH_GROUPCOM
void
oscore_add_group_keys(oscore_ctx_t *ctx,  
   const uint8_t *snd_public_key,
   const uint8_t *snd_private_key,
   const uint8_t *rcv_public_key,
   COSE_ECDSA_Algorithms_t counter_signature_algorithm,
   COSE_Elliptic_Curves_t counter_signature_parameters)
{
    ctx->mode = OSCORE_GROUP;

    ctx->counter_signature_algorithm = counter_signature_algorithm;
    ctx->counter_signature_parameters = counter_signature_parameters;

    /* Currently only support these parameters */
    assert(counter_signature_algorithm == COSE_Algorithm_ES256);
    assert(counter_signature_parameters == COSE_Elliptic_Curve_P256);

    ctx->sender_context.public_key = snd_public_key;
    ctx->sender_context.private_key = snd_private_key;
    ctx->sender_context.curve = counter_signature_parameters;

    ctx->recipient_context.public_key = rcv_public_key;
    ctx->recipient_context.curve = counter_signature_parameters;
}
#endif /* WITH_GROUPCOM */
