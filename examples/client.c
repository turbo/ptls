#include <stdio.h>
#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#define socklen_t int
#define sleep(x) Sleep(x * 1000)
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include "../tlse.c"

void error(char *msg) {
  perror(msg);
  exit(0);
}

int send_pending(int client_sock, struct TLSContext *context) {
  unsigned int out_buffer_len = 0;
  const unsigned char *out_buffer =
      tls_get_write_buffer(context, &out_buffer_len);
  unsigned int out_buffer_index = 0;
  int send_res = 0;
  while ((out_buffer) && (out_buffer_len > 0)) {
    int res = send(client_sock, (char *)&out_buffer[out_buffer_index],
                   out_buffer_len, 0);
    if (res <= 0) {
      send_res = res;
      break;
    }
    out_buffer_len -= res;
    out_buffer_index += res;
  }
  tls_buffer_clear(context);
  return send_res;
}

int validate_certificate(struct TLSContext *context,
                         struct TLSCertificate **certificate_chain, int len) {
  int i;
  int err;
  if (certificate_chain) {
    for (i = 0; i < len; i++) {
      struct TLSCertificate *certificate = certificate_chain[i];
      // check validity date
      err = tls_certificate_is_valid(certificate);
      if (err) {
        fprintf(stderr, "Certificate invalid\n");
        return err;
      }
      // check certificate in certificate->bytes of length certificate->len
      // the certificate is in ASN.1 DER format
    }
  }
  // check if chain is valid
  err = tls_certificate_chain_is_valid(certificate_chain, len);
  if (err) {
    fprintf(stderr, "Certificate chain invalid\n");
    // FIXME !! TURN THIS ON AGAIN
    // FIXME !! TURN THIS ON AGAIN
    // FIXME !! TURN THIS ON AGAIN
    // FIXME !! TURN THIS ON AGAIN
    // FIXME !! TURN THIS ON AGAIN
    // FIXME !! TURN THIS ON AGAIN
    // FIXME !! TURN THIS ON AGAIN
    // FIXME !! TURN THIS ON AGAIN
    // return err;
  }

  const char *sni = tls_sni(context);
  if ((len > 0) && (sni)) {
    err = tls_certificate_valid_subject(certificate_chain[0], sni);
    if (err) {
      fprintf(stderr, "Certificate subject invalid\n");
      return err;
    }
  }

  // Perform certificate validation agains ROOT CA
  err = tls_certificate_chain_is_valid_root(context, certificate_chain, len);
  if (err) {
    fprintf(stderr, "Certificate chain root invalid\n");
    return err;
  }

  fprintf(stderr, "Certificate OK\n");

  // return certificate_expired;
  // return certificate_revoked;
  // return certificate_unknown;
  return no_error;
}

int SSL_CTX_root_ca(struct TLSContext *context, const char *pem_filename) {
  if (!context) return TLS_GENERIC_ERROR;

  int count = TLS_GENERIC_ERROR;
  FILE *f = fopen(pem_filename, "rb");
  if (f) {
    fseek(f, 0, SEEK_END);
    size_t size = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size) {
      unsigned char *buf = (unsigned char *)TLS_MALLOC(size + 1);
      if (buf) {
        buf[size] = 1;
        if (fread(buf, 1, size, f) == size) {
          count = tls_load_root_certificates(context, buf, size);
        }
        TLS_FREE(buf);
      }
    }
    fclose(f);
  }
  return count;
}

int main(int argc, char *argv[]) {
  int sockfd, portno, n;
  // tls_print_certificate("testcert/server.certificate");
  // tls_print_certificate("000.certificate");
  // exit(0);
  struct sockaddr_in serv_addr;
  struct hostent *server;

  char buffer[256];
  char *ref_argv[] = {"", "std.fyi", "443"};
  if (argc < 3) {
    argv = ref_argv;
    // fprintf(stderr,"usage %s hostname port\n", argv[0]);
    // exit(0);
  }
#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
  signal(SIGPIPE, SIG_IGN);
#endif
  portno = atoi(argv[2]);
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) error("ERROR opening socket");
  server = gethostbyname(argv[1]);
  if (server == NULL) {
    fprintf(stderr, "ERROR, no such host\n");
    exit(0);
  }
  memset((char *)&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  memcpy((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr,
         server->h_length);
  serv_addr.sin_port = htons(portno);
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    error("ERROR connecting");

  struct TLSContext *context = tls_create_context(0, TLS_V12);

  // NOTE: load verifications certs
  int res = SSL_CTX_root_ca(context, "../root.pem");
  fprintf(stderr, "Loaded %i certificates\n", res);

  // the next line is needed only if you want to serialize the connection
  // context or kTLS is used
  tls_make_exportable(context, 1);

  // set sni
  tls_sni_set(context, "std.fyi");

  tls_client_connect(context);
  send_pending(sockfd, context);
  unsigned char client_message[0xFFFF];
  int read_size;
  int sent = 0;
  while ((read_size = recv(sockfd, client_message, sizeof(client_message), 0)) >
         0) {
    tls_consume_stream(context, client_message, read_size,
                       validate_certificate);
    send_pending(sockfd, context);
    if (tls_established(context)) {
      if (!sent) {
        const char *request = "GET / HTTP/1.1\r\nHost: std.fyi:443\r\nConnection: close\r\n\r\n";
        // try kTLS (kernel TLS implementation in linux >= 4.13)
        // note that you can use send on a ktls socket
        // recv must be handled by TLSe
        if (!tls_make_ktls(context, socket)) {
          // call send as on regular TCP sockets
          // TLS record layer is handled by the kernel
          send(sockfd, request, strlen(request), 0);
        } else {
          tls_write(context, (unsigned char *)request, strlen(request));
          send_pending(sockfd, context);
        }
        sent = 1;
      }

      unsigned char read_buffer[0xFFFF];
      int read_size = tls_read(context, read_buffer, 0xFFFF - 1);
      if (read_size > 0) fwrite(read_buffer, read_size, 1, stdout);
    }
  }
  return 0;
}
