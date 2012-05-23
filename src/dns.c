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
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_NS "8.8.8.8"
#define DEFAULT_DNS_PORT 53

void
echoaddr(
         const u_char* const answer,
         const int answerlen
        ) {

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

  /* iterate over each resource record */
  ns_rr rr;
  for (int rrnum = 0; ; rrnum++) {

    /* parse the answer section of the resource record */
    if (
        ns_parserr(
                   &handle, /* data structure filled by ns_initparse */
                   ns_s_an, /* resource record answer section */
                   rrnum,   /* index of the resource record in this section */
                   &rr      /* data structure filled in by ns_parseerr */
                   ) < 0
        ) {

      /* continue to the next resource records if this cannot be parsed */
      if (errno != ENODEV) {
        herror("ns_parserr(...)");
        continue;
      }

      /* break out of the loop when all resource records have been read */
      break;
    }

    /* get A and AAAA in a presentation format */
    char* dst = NULL;
    switch (ns_rr_type(rr)) {

      /* type: A record */
      case ns_t_a:
        if (ns_rr_rdlen(rr) != (size_t)NS_INADDRSZ) {
          fprintf(stderr, "RR format error");
          break;
        }
        dst = calloc(1, INET_ADDRSTRLEN);
        if (dst == NULL) {
          perror("calloc(...)");
          exit(EXIT_FAILURE);
        }
        if (
            inet_ntop(
                      AF_INET,         /* IPv4 address format */
                      ns_rr_rdata(rr), /* src address in network format */
                      dst,             /* dst address in presentation format */
                      INET_ADDRSTRLEN  /* size of dst address */
                      ) == NULL
            ) {
          perror("inet_ntop(...)");
          free(dst); dst = NULL;
          break;
        }
        break;

      /* type: AAAA record */
      case ns_t_aaaa:
        if (ns_rr_rdlen(rr) != (size_t)NS_IN6ADDRSZ) {
          fprintf(stderr, "RR format error");
          break;
        }
        dst = calloc(1, INET6_ADDRSTRLEN);
        if (dst == NULL) {
          perror("calloc(...)");
          exit(EXIT_FAILURE);
        }
        if (
            inet_ntop(
                      AF_INET6,         /* IPv6 address format */
                      ns_rr_rdata(rr),  /* src address in network format */
                      dst,              /* dst address in presentation format */
                      INET6_ADDRSTRLEN  /* size of dst address */
                      ) == NULL
            ) {
          perror("inet_ntop(...)");
          free(dst); dst = NULL;
          break;
        }
        break;

      /* type: CNAME record */
      case ns_t_cname:
        fprintf(stderr, "CNAME\n");
        break;

      /* ignore all the other types */
      default:
        break;
    }

    /* echo the presentation format */
    if (dst != NULL) {
      fputs(dst, stdout); fputc('\n', stdout);
      free(dst); dst = NULL;
    }
  }

}

int
send_query(
           u_char* msg,
           int msglen
          ) {

  /* create a v4 socket */
  int sockfd = socket (
                       AF_INET,      /* communication domain: v4 */
                       SOCK_DGRAM,   /* socket type: connectionless datagram */
                       0             /* communication protocol: v4 */
                      );
  if (sockfd < 0) {
    perror("socket(...)");
    return -1;
  }

  /* create a v4 socket address structure */
  struct sockaddr_in v4addr;
  memset(&v4addr, 0, sizeof(struct sockaddr_in));
  v4addr.sin_family = AF_INET;
  v4addr.sin_port = htons(DEFAULT_DNS_PORT);
  v4addr.sin_addr = _res.nsaddr_list[0].sin_addr;

  /* send msg using the v4 socket */
  if (
      sendto (
              sockfd,                            /* socket descriptor */
              msg,                               /* send buffer */
              msglen,                            /* send buffer length */
              0,                                 /* flags */
              (struct sockaddr*) &v4addr,        /* target address */
              sizeof(struct sockaddr_in)         /* target address size */
              ) < 0
      ) {
    perror("sendto(...)");
    return -1;
  }

  return sockfd;
}

void receive_response_and_echo(
                               int sockfd
                              ) {

  /* receive answer using the provided socket */
  u_char answer[NS_PACKETSZ];
  ssize_t answerlen = recvfrom (
                                sockfd,         /* socket descriptor */
                                answer,         /* receive buffer */
                                NS_PACKETSZ,    /* receive buffer length */
                                0,              /* flags */
                                NULL,           /* source address */
                                NULL            /* source address length */
                               );
  if (answerlen < 0) {
    perror("recvfrom(...)");
    return;
  }

  /* echo the answer */
  echoaddr(answer, answerlen);

}

int main(int argc, char* argv[]) {

  /* parse command line arguments */
  int opt; char* ns = NULL; char* domain = NULL;
  while ((opt = getopt(argc, argv, "s:t:")) != -1) {
    switch (opt) {
      case 's':
        ns = optarg; break;
    }
  }
  if (argc == optind) {
    printf("usage: %s [-s namesever] host", argv[0]);
    exit(EXIT_FAILURE);
  }

  /* change the default behavior of resolver routines */
  res_init();
  _res.nscount = 1;
  if (ns == NULL) ns = DEFAULT_NS;
  if (
      inet_pton(
                AF_INET,                         /* IPv4 address fmt */
                ns,                              /* ns in presentation fmt */
                &_res.nsaddr_list[0].sin_addr    /* ns in network fmt */
                ) <= 0
      ) {
    perror("inet_pton(...)");
    exit(EXIT_FAILURE);
  }

  ns = calloc(1, INET_ADDRSTRLEN);
  if (
      inet_ntop(
                AF_INET,                         /* IPv4 address fmt */
                &_res.nsaddr_list[0].sin_addr,   /* ns in network fmt */
                ns,                              /* ns in presentation fmt */
                INET_ADDRSTRLEN                  /* size of dst address */
                ) == NULL
      ) {
    perror("inet_ntop(...)");
    exit(EXIT_FAILURE);
  }
  printf("using nameserver: %s\n", ns);
  free(ns); ns = NULL;

  while(optind < argc) {

    domain = argv[optind++];
    printf("\n%s\n", domain);

    /* create a A query message */
    u_char msg4[NS_PACKETSZ];
    int msg4len = res_mkquery(
                              ns_o_query,       /* regular query */
                              domain,           /* domain name to look up */
                              ns_c_in,          /* internet type */
                              ns_t_a,           /* type of record to look up */
                              NULL,             /* always NULL for QUERY */
                              0,                /* length of NULL */
                              (u_char*) NULL,   /* always NULL */
                              (u_char*) msg4,   /* query buffer */
                              NS_PACKETSZ       /* query buffer size */
                             );
    if(msg4len == -1)
      herror("res_mkquery(...)");

    /* create a AAAA query message */
    u_char msg6[NS_PACKETSZ];
    int msg6len = res_mkquery(
                              ns_o_query,       /* regular query */
                              domain,           /* domain name to look up */
                              ns_c_in,          /* internet type */
                              ns_t_aaaa,        /* type of record to look up */
                              NULL,             /* always NULL for QUERY */
                              0,                /* length of NULL */
                              (u_char*) NULL,   /* always NULL */
                              (u_char*) msg6,   /* query buffer */
                              NS_PACKETSZ       /* query buffer size */
                             );
    if(msg6len == -1)
      herror("res_mkquery(...)");

    /* send the query message */
    int sockv4query = send_query(
                                 (u_char*) msg4,       /* query buffer */
                                 msg4len               /* true query length */
                                );
    if(sockv4query == -1) {
      perror("send_query(...)");
      continue;
    }

    /* send the query message */
    int sockv6query = send_query(
                                 (u_char*) msg6,       /* query buffer */
                                 msg6len               /* true query length */
                                );
    if(sockv6query == -1) {
      perror("send_query(...)");
      continue;
    }

    /* an event driven loop */ 
    fd_set readfds; FD_ZERO(&readfds);
    int waiting = 2;
    while(waiting) {

      FD_SET(sockv4query, &readfds);
      FD_SET(sockv6query, &readfds);

      /* one greater than the highest fd number */
      int nfds = (sockv4query > sockv6query ? sockv4query : sockv6query) + 1;

      if (
         select(
                 nfds,         /* number of fds */
                 &readfds,     /* set of read fds */
                 NULL,         /* set of write fds */
                 NULL,         /* set of exception fds */
                 NULL          /* maximum wait interval */
               ) < 0
       ) {
        perror("select(...)");
        continue;
      } else {

        /* one or more descriptors are ready */
        if(FD_ISSET(sockv4query, &readfds)) {
          receive_response_and_echo(sockv4query);
          waiting -= 1;
        }
        if(FD_ISSET(sockv6query, &readfds)) {
          receive_response_and_echo(sockv6query);
          waiting -= 1;
        }
      }
    }

    /* close the sockets */
    close(sockv4query);
    close(sockv6query);
  }
  return(EXIT_SUCCESS);
}
