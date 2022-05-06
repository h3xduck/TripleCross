// This code is based from the following tutorial:
// https://aticleworld.com/ssl-server-client-using-openssl-in-c/

#include "openssl/err.h"
#include "openssl/ssl.h"
#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define FAIL -1

#define USE_FUNCTIONS 0

#if (USE_FUNCTIONS)
SSL_CTX *InitServerCTX(void) {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  OpenSSL_add_all_algorithms();     /* load & register all cryptos, etc. */
  SSL_load_error_strings();         /* load all error messages */
  method = TLSv1_2_server_method(); /* create new server-method instance */
  ctx = SSL_CTX_new(method);        /* create new context from method */
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  return ctx;
}

void LoadCertificates(SSL_CTX *ctx, const char *CertFile, const char *KeyFile) {
  /* set the local certificate from CertFile */
  if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    instructionsForPem();
    abort();
  }

  /* set the private key from KeyFile (may be the same as CertFile) */
  if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    instructionsForPem();
    abort();
  }

  /* verify private key */
  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr, "Private key does not match the public certificate\n");
    abort();
  }
}

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port) {
  int sd;
  struct sockaddr_in addr;

  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("can't bind port");
    abort();
  }
  if (listen(sd, 10) != 0) {
    perror("Can't configure listening port");
    abort();
  }
  return sd;
}

void ShowCerts(SSL *ssl) //? RBW
{
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
  if (cert != NULL) {
    printf("Server certificates:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);
    X509_free(cert);
  } else {
    printf("No certificates.\n");
  }
}

/* Serve the connection -- threadable */
void Servlet(SSL *ssl) {
  char buf[1024] = {0};

  int sd, bytes;

  // this is my attempt to run HTTPS.. This is sort of the minimal header that
  // seems to work.  \r is absolutely necessary.
  const char *szHelloWorld =
      "HTTP/1.1 200 OK\r\n"
      "Content-type: text/html\r\n"
      "\r\n"
      "<html>\n"
      "<body>\n"
      "<h1>So, this works, if you added a security exception to your web "
      "browser</h1>\n"
      "<h2>Or.... are using a genuine certificate.</h2>\n"
      "<h3>This is using functions BTW..</h3>\n"
      "</body>\n"
      "</html>\n";

  if (SSL_accept(ssl) == FAIL) /* do SSL-protocol accept */
  {
    ERR_print_errors_fp(stderr);
  } else {
    ShowCerts(ssl);                          /* get any certificates */
    bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
    buf[bytes] = '\0';

    printf("Client msg:\n[%s]\n", buf);

    if (bytes > 0) {
      printf("Reply with:\n[%s]\n", szHelloWorld);
      SSL_write(ssl, szHelloWorld, strlen(szHelloWorld));
    } else {
      ERR_print_errors_fp(stderr);
    }
  }
  sd = SSL_get_fd(ssl); /* get socket connection */
  SSL_free(ssl);        /* release SSL state */
  close(sd);            /* close connection */
}
#endif

int server_run(int port) {
  SSL_CTX *ctx;
  int server;
  const char *szPemPublic = "mycert.pem";
  const char *szPemPrivate = "mycert.pem";
#if (!(USE_FUNCTIONS))
  const SSL_METHOD *method;
#endif

  if (port < 1024) {
    if (getuid() != 0) {
      printf("This program must be run as root/sudo user since your port # "
             "(%d) is < 1024\n",
             port);
      exit(1);
    }
  }

  SSL_library_init(); /* Initialize the SSL library */

#if (USE_FUNCTIONS)
  ctx = InitServerCTX(); /* initialize SSL */
#else
  // InitServerCTX ();
  OpenSSL_add_all_algorithms();     /* load & register all cryptos, etc. */
  SSL_load_error_strings();         /* load all error messages */
  method = TLSv1_2_server_method(); /* create new server-method instance */
  ctx = SSL_CTX_new(method);        /* create new context from method */
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    abort();
  }
#endif

#if (USE_FUNCTIONS)
  LoadCertificates(ctx, szPemPublic, szPemPrivate); /* load certs */
#else
  /* set the local certificate from CertFile */
  if (SSL_CTX_use_certificate_file(ctx, szPemPublic, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  /* set the private key from KeyFile (may be the same as CertFile) */
  if (SSL_CTX_use_PrivateKey_file(ctx, szPemPrivate, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  /* verify private key */
  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr, "Private key does not match the public certificate\n");
    abort();
  }
#endif

#if (USE_FUNCTIONS)
  server = OpenListener(portnum); /* create server socket */
#else
  struct sockaddr_in addr;

  server = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("can't bind port");
    abort();
  }
  if (listen(server, 10) != 0) {
    perror("Can't configure listening port");
    abort();
  }
#endif

  for (;;) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    SSL *ssl;

#if (!(USE_FUNCTIONS))
    char buf[1024] = {0};
    int sd, bytes;

    // this is my attempt to run HTTPS.. This is sort of the minimal header that
    // seems to work.  \r is absolutely necessary.
    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Content-type: text/html\r\n"
        "\r\n"
        "<html>\n"
        "<body>\n"
        "<h1>So, this works, if you added a security exception to your web "
        "browser</h1>\n"
        "<h2>Or.... are using a genuine certificate.</h2>\n"
        "<h3>This is <u><i>NOT</i></u> using functions BTW..</h3>\n"
        "</body>\n"
        "</html>\n";
#endif
    int client;
    printf("Listening for connections\n");
    client = accept(server, (struct sockaddr *)&addr,
                    &len); /* accept connection as usual */
    printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr),
           ntohs(addr.sin_port));
    ssl = SSL_new(ctx);      /* get new SSL state with context */
    SSL_set_fd(ssl, client); /* set connection socket to SSL state */
#if (USE_FUNCTIONS)
    Servlet(ssl); /* service connection */
#else
    if (SSL_accept(ssl) == FAIL) /* do SSL-protocol accept */
    {
      ERR_print_errors_fp(stderr);
    } else {
      X509 *cert;
      char *line;

      cert =
          SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
      if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
      } else {
        printf("No certificates.\n");
      }

      // ShowCerts (ssl);                         /* get any certificates */
      bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
      buf[bytes] = '\0';

      printf("Client msg:\n[%s]\n", buf);

      if (bytes > 0) {
        printf("Reply with:\n[%s]\n", response);
        SSL_write(ssl, response, strlen(response));
      } else {
        ERR_print_errors_fp(stderr);
      }
    }
    sd = SSL_get_fd(ssl); /* get socket connection */
    SSL_free(ssl);        /* release SSL state */
    close(sd);            /* close connection */
#endif
    //    break;
  }
  close(server); /* close server socket */

  ERR_free_strings(); /* free memory from SSL_load_error_strings */
  EVP_cleanup();      /* free memory from OpenSSL_add_all_algorithms */
  SSL_CTX_free(ctx);  /* release context */

  return 0;
}
