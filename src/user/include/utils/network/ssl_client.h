// This is based from the following tutorial:
// https://aticleworld.com/ssl-server-client-using-openssl-in-c/
#include <errno.h>
#include <malloc.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LOCAL_ABORT()                                                          \
  do {                                                                         \
    printf("Abort at %s:%d\n", __FILE__, __LINE__);                            \
    abort();                                                                   \
  } while (0)

#define USE_FUNCTIONS 0

#if (USE_FUNCTIONS)
int OpenConnection(const char *hostname, uint16_t port) {
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;

  if ((host = gethostbyname(hostname)) == NULL) {
    perror(hostname);
    LOCAL_ABORT();
  }
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long *)(host->h_addr);

  if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(sd);
    perror(hostname);
    fprintf(stderr, "Is the server running, and on the correct port (%d)?\n",
            port);
    LOCAL_ABORT();
  }
  return sd;
}

SSL_CTX *InitCTX(void) {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  OpenSSL_add_all_algorithms();     /* Load cryptos, et.al. */
  SSL_load_error_strings();         /* Bring in and register error messages */
  method = TLSv1_2_client_method(); /* Create new client-method instance */
  ctx = SSL_CTX_new(method);        /* Create new context */
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    LOCAL_ABORT();
  }
  return ctx;
}

void ShowCerts(SSL *ssl) {
  X509 *cert;
  char *line;
  cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if (cert != NULL) {
    printf("Server certificates:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    free(line); /* free the malloc'ed string */
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n\n", line);
    free(line);      /* free the malloc'ed string */
    X509_free(cert); /* free the malloc'ed certificate copy */
  } else {
    printf("Info: No client certificates configured.\n");
  }
}
#endif

int client_run(char* hostname, uint16_t portnum) {
  SSL_CTX *ctx;
  int server;
  SSL *ssl;
  static char buf[1024 * 1024];
  int bytes;
#if (!(USE_FUNCTIONS))
  struct hostent *host;
  struct sockaddr_in addr;
  const SSL_METHOD *method;
#endif

  // Initialize the SSL library
  SSL_library_init();

#if (USE_FUNCTIONS)
  ctx = InitCTX();
  server = OpenConnection(hostname, portnum);
#else
  OpenSSL_add_all_algorithms();     /* Load cryptos, et.al. */
  SSL_load_error_strings();         /* Bring in and register error messages */
  method = TLSv1_2_client_method(); /* Create new client-method instance */
  ctx = SSL_CTX_new(method);        /* Create new context */
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    LOCAL_ABORT();
  }

  if ((host = gethostbyname(hostname)) == NULL) {
    perror(hostname);
    LOCAL_ABORT();
  }
  server = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(portnum);
  addr.sin_addr.s_addr = *(long *)(host->h_addr);

  if (connect(server, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(server);
    perror(hostname);
    fprintf(stderr, "Is the server running, and on the correct port (%d)?\n",
            portnum);
    LOCAL_ABORT();
  }
#endif

  ssl = SSL_new(ctx);        /* create new SSL connection state */
  SSL_set_fd(ssl, server);   /* attach the socket descriptor */
  if (SSL_connect(ssl) <= 0) /* perform the connection */
  {
    ERR_print_errors_fp(stderr);
  } else {
#if (!(USE_FUNCTIONS))
    X509 *cert;
    char *line;
#endif
    char request[4096];
    sprintf(request,
            "GET / HTTP/1.1\r\n"
            "User-Agent: Wget/1.17.1 (linux-gnu)\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Host: %s:%d\r\n"
            //             "Connection: Keep-Alive\n"
            "\r\n",
            hostname, portnum);

    printf("Sending:\n[%s]\n", request);

    printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));

#if (USE_FUNCTIONS)
    ShowCerts(ssl); /* get any certs */
#else
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL) {
      printf("Server certificates:\n");
      line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
      printf("Subject: %s\n", line);
      free(line); /* free the malloc'ed string */
      line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
      printf("Issuer: %s\n\n", line);
      free(line);      /* free the malloc'ed string */
      X509_free(cert); /* free the malloc'ed certificate copy */
    } else {
      printf("Info: No client certificates configured.\n");
    }
#endif

    SSL_write(ssl, request, strlen(request)); /* encrypt & send message */

    bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
    buf[bytes] = 0;
    printf("Received (%d bytes):\n[%s]\n", bytes, buf);

    // second send.. - for my real web page, it comes in two parts.
    // bytes = SSL_read (ssl, buf, sizeof (buf)); /* get reply & decrypt */
    // buf[bytes] = 0;
    // printf ("Received (%d bytes):\n[%s]\n", bytes, buf);

    SSL_free(ssl); /* release connection state */
  }

  close(server);     /* close socket */
  SSL_CTX_free(ctx); /* release context */

  return 0;
}
