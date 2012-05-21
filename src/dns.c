/*
 * Copyright (c) 2012, Vaibhav Bajpai <contact@vaibhavbajpai.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met: 
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are 
 * those of the authors and should not be interpreted as representing official 
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>

static void
do_section(const res_state statp,
           ns_msg *handle, 
           ns_sect section,
           FILE *file) {

  int n, rrnum;
  static int buflen = 2048;
  char *buf;
  ns_opcode opcode;
  ns_rr rr;

  buf = malloc(buflen);
  if (buf == NULL) {
    fprintf(file, ";; memory allocation failure\n");
    return;
  }

  opcode = (ns_opcode) ns_msg_getflag(*handle, ns_f_opcode);
  rrnum = 0;
  for (;;) {
    if (ns_parserr(handle, section, rrnum, &rr)) {
      if (errno != ENODEV)
        fprintf(file, ";; ns_parserr: %s\n",
          strerror(errno));
      else if (rrnum > 0)
        putc('\n', file);
      goto cleanup;
    }
    if (rrnum == 0)
      fprintf(file, ";; %s SECTION:\n",
        p_section(section, opcode));
    if (section == ns_s_qd)
      fprintf(file, ";;\t%s, type = %s, class = %s\n",
        ns_rr_name(rr),
        p_type(ns_rr_type(rr)),
        p_class(ns_rr_class(rr)));
    else if (section == ns_s_ar && ns_rr_type(rr) == ns_t_opt) {
      u_int32_t ttl = ns_rr_ttl(rr);
      fprintf(file,
        "; EDNS: version: %u, udp=%u, flags=%04x\n",
        (ttl>>16)&0xff, ns_rr_class(rr), ttl&0xffff);
    } else {
      n = ns_sprintrr(handle, &rr, NULL, NULL,
          buf, buflen);
      if (n < 0) {
        if (errno == ENOSPC) {
          free(buf);
          buf = NULL;
          if (buflen < 131072)
            buf = malloc(buflen += 1024);
          if (buf == NULL) {
            fprintf(file,
                      ";; memory allocation failure\n");
                return;
          }
          continue;
        }
        fprintf(file, ";; ns_sprintrr: %s\n",
          strerror(errno));
        goto cleanup;
      }
      fputs(buf, file);
      fputc('\n', file);
    }
    rrnum++;
  }
 cleanup:
  if (buf != NULL)
    free(buf);
} 

int main(int argc, char* argv[]) {

  /* create a query message */
  u_char msg[NS_PACKETSZ];
  int msglen = res_mkquery(
                           ns_o_query,          /* regular query */
                           argv[1],             /* domain name to look up */
                           ns_c_in,             /* internet type */
                           ns_t_a,              /* A record to look up */
                           NULL,                /* always NULL for QUERY */
                           0,                   /* length of NULL */
                           (u_char*) NULL,      /* always NULL */
                           (u_char*) msg,       /* query buffer */
                           sizeof(msg)          /* query buffer size */
                          );
  if(msglen == -1)
    herror("res_mkquery(...)");

  /* send the query message */
  u_char answer[NS_PACKETSZ];
  int answerlen = res_send(
                           (u_char*) msg,          /* query buffer */
                           msglen,                 /* true query length */
                           (u_char*) answer,       /* answer buffer */
                           sizeof(answer)          /* answer buffer size */
                          );
  if(answerlen == -1)
    herror("res_send(...)");

  /* initialize data structure to store the parsed response */
  ns_msg handle;
  if (
      ns_initparse(
                   answer,      /* answer buffer */
                   answerlen,   /* true answer length */
                   &handle      /* data structure filled in by ns_initparse */
                  ) < 0
     )
    herror("ns_initparse(...)");
#ifdef DEBUG
  res_pquery(&_res, answer, answerlen, stdout);
#endif
  do_section(&_res, &handle, ns_s_an, stdout);

  /* get msg_id */
  u_int16_t msg_id = ns_msg_id(handle);
  printf("\nmsg_id: %u", msg_id);

  /* get msg_count */
  u_int16_t qd_count = ns_msg_count(handle, ns_s_qd);
  u_int16_t an_count = ns_msg_count(handle, ns_s_an);
  u_int16_t ns_count = ns_msg_count(handle, ns_s_ns);
  u_int16_t ar_count = ns_msg_count(handle, ns_s_ar);
  printf("\nqd_count: %u", qd_count);
  printf("\nan_count: %u", an_count);
  printf("\nns_count: %u", ns_count);
  printf("\nar_count: %u", ar_count);
  
  /* parse a resource record section */
  ns_rr rr;
  if (
      ns_parserr(
                 &handle,    /* data structure filled by ns_initparse */
                 ns_s_an,    /* resource record section */
                 1,          /* index of the resource record in this section */   
                 &rr         /* data structure filled in by ns_parseerr */
                ) < 0
     )   
    herror("ns_parserr(...)");
#ifdef DEBUG
  printf("\nns_rr_name: %s", ns_rr_name(rr));
  printf("\nns_rr_type: %u", ns_rr_type(rr));
  printf("\nns_rr_class: %u", ns_rr_class(rr));
  printf("\nns_rr_ttl: %u", ns_rr_ttl(rr));
  printf("\nns_rr_rdlen: %u", ns_rr_rdlen(rr));
  printf("\nns_rr_rdata: %s", ns_rr_rdata(rr));
#endif

  /* get RR in a presentation format */
  char buf[100];
  if (
      ns_sprintrr(
                  &handle,
                  &rr,
                  NULL,
                  NULL,
                  (char*) &buf,
                  sizeof(buf)
                 ) < 0
     )
    herror("ns_sprintrr(...)");  
#ifdef DEBUG
  printf("\nbuffer: %s", buf);
#endif
  return(EXIT_SUCCESS);
}
