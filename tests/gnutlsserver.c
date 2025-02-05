#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <assert.h>

#define CHECK(x) assert((x) >= 0)
#define LOOP_CHECK(rval, cmd)						\
	do {								\
		rval = cmd;						\
	} while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

#define MAX_BUF 1024

/* Open a listening socket */
int gnutlsserver_init(int port) {
	int listen_sd;
	struct sockaddr_in sa_serv;
	int optval = 1;

	listen_sd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(port);

	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval,
		   sizeof(int));

	bind(listen_sd, (struct sockaddr *)&sa_serv, sizeof(sa_serv));

	listen(listen_sd, 1);

	fprintf(stderr, "Server ready. Listening to port '%d'.\n\n", port);

        return listen_sd;
}

/* Loop to accept connections */
int gnutlsserver_run(int listen_sd, char *privkey_file, char *certs_file) {
	char topbuf[512];
	gnutls_session_t session;
	char buffer[MAX_BUF + 1];
	int sd, ret;
	struct sockaddr_in sa_cli;
	socklen_t client_len = sizeof(sa_cli);
        gnutls_certificate_credentials_t x509_cred;
	gnutls_priority_t priority_cache;

	CHECK(gnutls_global_init());
	CHECK(gnutls_certificate_allocate_credentials(&x509_cred));
	CHECK(gnutls_certificate_set_x509_key_file(
		      x509_cred, certs_file, privkey_file, GNUTLS_X509_FMT_PEM));
	/* Disable OCSP */
        gnutls_certificate_set_verify_flags(
		x509_cred, GNUTLS_VERIFY_DISABLE_CRL_CHECKS);

	gnutls_certificate_set_known_dh_params(x509_cred,
					       GNUTLS_SEC_PARAM_MEDIUM);
	for (;;) {
		CHECK(gnutls_init(&session, GNUTLS_SERVER));
		CHECK(gnutls_credentials_set(
			      session, GNUTLS_CRD_CERTIFICATE, x509_cred));
		gnutls_certificate_server_set_request(
			session, GNUTLS_CERT_IGNORE);
		gnutls_handshake_set_timeout(session,
					     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

		sd = accept(listen_sd, (struct sockaddr *)&sa_cli, &client_len);

		fprintf(stderr, "- connection from %s, port %d\n",
			inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
				  sizeof(topbuf)),
			ntohs(sa_cli.sin_port));

		gnutls_transport_set_int(session, sd);

		LOOP_CHECK(ret, gnutls_handshake(session));
		if (ret < 0) {
			close(sd);
			gnutls_deinit(session);
			fprintf(stderr, "*** Handshake has failed (%s)\n\n",
				gnutls_strerror(ret));
			continue;
		}
		fprintf(stderr, "- Handshake was completed\n");

		for (;;) {
			LOOP_CHECK(ret, gnutls_record_recv(session, buffer,
							   MAX_BUF));

			if (ret == 0) {
				fprintf(stderr, "\n- Peer has closed the GnuTLS connection\n");
				break;
			} else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
				fprintf(stderr, "*** Warning: %s\n",
					gnutls_strerror(ret));
			} else if (ret < 0) {
				fprintf(stderr,
					"\n*** Received corrupted "
					"data(%d). Closing the connection.\n\n",
					ret);
				break;
			} else if (ret > 0) {
				/* echo data back to the client
				 */
				CHECK(gnutls_record_send(session, buffer, ret));
			}
		}
		fprintf(stderr, "\n");
		/* do not wait for the peer to close the connection.
		 */
		LOOP_CHECK(ret, gnutls_bye(session, GNUTLS_SHUT_WR));

		close(sd);
		gnutls_deinit(session);
	}
	close(listen_sd);

	gnutls_certificate_free_credentials(x509_cred);

	gnutls_global_deinit();

	return 0;
}
