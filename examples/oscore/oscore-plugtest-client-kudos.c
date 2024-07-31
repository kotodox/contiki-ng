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
 *      OSCORE interops client, tests specified according to https://raw.githubusercontent.com/EricssonResearch/OSCOAP/master/test-spec5.md .
 * \author
 *      Martin Gunnarsson <martin.gunnarsson@ri.se>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "dev/button-sensor.h"
#include "plugtest_resources.h"
#include "appendix_b2.h"
#include "res_kudos.h"


#ifdef WITH_OSCORE
#include "oscore.h"

void response_handler(coap_message_t *response);

uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40}; 
//uint8_t *sender_id = NULL;
uint8_t sender_id[] = { 0x02};

uint8_t receiver_id[] = { 0x01};
#endif /* WITH_OSCORE */

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_COAP

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
//#define SERVER_EP "coap://[fe80::202:0002:0002:0002]" //Cooja simulation address 
#define SERVER_EP "coap://[fe80::212:4b00:14b5:d8a3]:5683" //Ip for plugtest server  coap://


uint8_t test = 0;
uint8_t failed_tests = 0;

#define TOGGLE_INTERVAL 10

PROCESS(er_example_client, "OSCORE interops Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;

uint8_t token[2] = { 0x05, 0x05};

#define NUMBER_OF_URLS 4
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "oscore/hello/coap", "/rederivation/blackhole/","well-known/kudos/"};


PROCESS_THREAD(er_example_client, ev, data)
{
  PROCESS_BEGIN();

  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */
  static coap_endpoint_t server_ep;
  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
  #ifdef WITH_OSCORE
  static oscore_ctx_t context;
  oscore_derive_ctx(&context, master_secret, 16, salt, 8, 10, sender_id, 1, receiver_id, 1, NULL, 0);

  uint8_t ret = 0;
  ret += oscore_ep_ctx_set_association(&server_ep, service_urls[2], &context);
  ret += oscore_ep_ctx_set_association(&server_ep, service_urls[3], &context);
  if( ret != 2) {
	 printf("Not all URIs associated with contexts!\n");
  } 

  #endif /* WITH_OSCORE */
  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
  
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      switch ( test ) {
      	case 0:
	  test0_a(request);
	  break;
	case 1:
  	  oscore_kudos_true();
          break;
        case 2:
          test_kudos(request);
          break;
    	}
        coap_set_token(request, token, 2);
      	COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);

	test++;
        etimer_reset(&et);
    }
    }
  

  PROCESS_END();
}

void response_handler(coap_message_t *response){
  printf("Response handler test: %d\n", test);

}

