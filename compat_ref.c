#ifdef SSL_COMPATIBLE_INTERFACE

int SSL_library_init() {
  // dummy function
  return 1;
}

void SSL_load_error_strings() {
  // dummy function
}

void OpenSSL_add_all_algorithms() {
  // dummy function
}

void OpenSSL_add_all_ciphers() {
  // dummy function
}

void OpenSSL_add_all_digests() {
  // dummy function
}

void EVP_cleanup() {
  // dummy function
}

int _tls_ssl_private_send_pending(int client_sock, struct TLSContext *context) {
  unsigned int out_buffer_len = 0;
  const unsigned char *out_buffer =
      tls_get_write_buffer(context, &out_buffer_len);
  unsigned int out_buffer_index = 0;
  int send_res = 0;
  SOCKET_SEND_CALLBACK write_cb = NULL;
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if (ssl_data) write_cb = (SOCKET_SEND_CALLBACK)ssl_data->send;
  while ((out_buffer) && (out_buffer_len > 0)) {
    int res;
    if (write_cb)
      res = write_cb(client_sock, (char *)&out_buffer[out_buffer_index],
                     out_buffer_len, 0);
    else
      res = send(client_sock, (char *)&out_buffer[out_buffer_index],
                 out_buffer_len, 0);
    if (res <= 0) {
      if ((!write_cb) && (res < 0)) {
#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
          context->tls_buffer_len = out_buffer_len;
          memmove(context->tls_buffer, out_buffer + out_buffer_index,
                  out_buffer_len);
          return res;
        }
#else
        if ((errno == EAGAIN) || (errno == EINTR)) {
          context->tls_buffer_len = out_buffer_len;
          memmove(context->tls_buffer, out_buffer + out_buffer_index,
                  out_buffer_len);
          return res;
        }
#endif
      }
      send_res = res;
      break;
    }
    out_buffer_len -= res;
    out_buffer_index += res;
    send_res += res;
  }
  tls_buffer_clear(context);
  return send_res;
}

struct TLSContext *SSL_new(struct TLSContext *context) {
  return tls_accept(context);
}

int SSLv3_server_method() { return 1; }

int SSLv3_client_method() { return 0; }

int SSL_CTX_use_certificate_file(struct TLSContext *context,
                                 const char *filename, int dummy) {
  // max 64k buffer
  unsigned char buf[0xFFFF];
  int size = _private_tls_read_from_file(filename, buf, sizeof(buf));
  if (size > 0) return tls_load_certificates(context, buf, size);
  return size;
}

int SSL_CTX_use_PrivateKey_file(struct TLSContext *context,
                                const char *filename, int dummy) {
  unsigned char buf[0xFFFF];
  int size = _private_tls_read_from_file(filename, buf, sizeof(buf));
  if (size > 0) return tls_load_private_key(context, buf, size);

  return size;
}

int SSL_CTX_check_private_key(struct TLSContext *context) {
  if ((!context) ||
      (((!context->private_key) || (!context->private_key->der_bytes) ||
        (!context->private_key->der_len))
#ifdef TLS_ECDSA_SUPPORTED
       &&
       ((!context->ec_private_key) || (!context->ec_private_key->der_bytes) ||
        (!context->ec_private_key->der_len))
#endif
           ))
    return 0;
  return 1;
}

struct TLSContext *SSL_CTX_new(int method) {
  return tls_create_context(method, TLS_V12);
}

void SSL_free(struct TLSContext *context) {
  if (context) {
    TLS_FREE(context->user_data);
    tls_destroy_context(context);
  }
}

void SSL_CTX_free(struct TLSContext *context) { SSL_free(context); }

int SSL_get_error(struct TLSContext *context, int ret) {
  if (!context) return TLS_GENERIC_ERROR;
  return context->critical_error;
}

int SSL_set_fd(struct TLSContext *context, int socket) {
  if (!context) return 0;
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if (!ssl_data) {
    ssl_data = (SSLUserData *)TLS_MALLOC(sizeof(SSLUserData));
    if (!ssl_data) return TLS_NO_MEMORY;
    memset(ssl_data, 0, sizeof(SSLUserData));
    context->user_data = ssl_data;
  }
  ssl_data->fd = socket;
  return 1;
}

void *SSL_set_userdata(struct TLSContext *context, void *data) {
  if (!context) return NULL;
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if (!ssl_data) {
    ssl_data = (SSLUserData *)TLS_MALLOC(sizeof(SSLUserData));
    if (!ssl_data) return NULL;
    memset(ssl_data, 0, sizeof(SSLUserData));
    context->user_data = ssl_data;
  }
  void *old_data = ssl_data->user_data;
  ssl_data->user_data = data;
  return old_data;
}

void *SSL_userdata(struct TLSContext *context) {
  if (!context) return NULL;
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if (!ssl_data) return NULL;

  return ssl_data->user_data;
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
          if (count > 0) {
            SSLUserData *ssl_data = (SSLUserData *)context->user_data;
            if (!ssl_data) {
              ssl_data = (SSLUserData *)TLS_MALLOC(sizeof(SSLUserData));
              if (!ssl_data) {
                fclose(f);
                return TLS_NO_MEMORY;
              }
              memset(ssl_data, 0, sizeof(SSLUserData));
              context->user_data = ssl_data;
            }
            if (!ssl_data->certificate_verify)
              ssl_data->certificate_verify = tls_default_verify;
          }
        }
        TLS_FREE(buf);
      }
    }
    fclose(f);
  }
  return count;
}

void SSL_CTX_set_verify(struct TLSContext *context, int mode,
                        tls_validation_function verify_callback) {
  if (!context) return;
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if (!ssl_data) {
    ssl_data = (SSLUserData *)TLS_MALLOC(sizeof(SSLUserData));
    if (!ssl_data) return;
    memset(ssl_data, 0, sizeof(SSLUserData));
    context->user_data = ssl_data;
  }
  if (mode == SSL_VERIFY_NONE)
    ssl_data->certificate_verify = NULL;
  else
    ssl_data->certificate_verify = verify_callback;
}

int _private_tls_safe_read(struct TLSContext *context, void *buffer,
                           int buf_size) {
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if ((!ssl_data) || (ssl_data->fd < 0)) return TLS_GENERIC_ERROR;

  SOCKET_RECV_CALLBACK read_cb = (SOCKET_RECV_CALLBACK)ssl_data->recv;
  if (read_cb) return read_cb(ssl_data->fd, (char *)buffer, buf_size, 0);
  return recv(ssl_data->fd, (char *)buffer, buf_size, 0);
}

int SSL_accept(struct TLSContext *context) {
  if (!context) return TLS_GENERIC_ERROR;
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if ((!ssl_data) || (ssl_data->fd < 0)) return TLS_GENERIC_ERROR;
  if (tls_established(context)) return 1;
  unsigned char client_message[0xFFFF];
  // accept
  int read_size = 0;
  while ((read_size = _private_tls_safe_read(context, (char *)client_message,
                                             sizeof(client_message))) > 0) {
    if (tls_consume_stream(context, client_message, read_size,
                           ssl_data->certificate_verify) >= 0) {
      int res = _tls_ssl_private_send_pending(ssl_data->fd, context);
      if (res < 0) return res;
    }
    if (tls_established(context)) return 1;
  }
  if (read_size <= 0) return TLS_BROKEN_CONNECTION;
  return 0;
}

int SSL_connect(struct TLSContext *context) {
  if (!context) return TLS_GENERIC_ERROR;
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if ((!ssl_data) || (ssl_data->fd < 0) || (context->critical_error))
    return TLS_GENERIC_ERROR;
  int res = tls_client_connect(context);
  if (res < 0) return res;
  res = _tls_ssl_private_send_pending(ssl_data->fd, context);
  if (res < 0) return res;

  int read_size;
  unsigned char client_message[0xFFFF];

  while ((read_size = _private_tls_safe_read(context, (char *)client_message,
                                             sizeof(client_message))) > 0) {
    if (tls_consume_stream(context, client_message, read_size,
                           ssl_data->certificate_verify) >= 0) {
      res = _tls_ssl_private_send_pending(ssl_data->fd, context);
      if (res < 0) return res;
    }
    if (tls_established(context)) return 1;
    if (context->critical_error) return TLS_GENERIC_ERROR;
  }
  return read_size;
}

int SSL_shutdown(struct TLSContext *context) {
  if (!context) return TLS_GENERIC_ERROR;
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if ((!ssl_data) || (ssl_data->fd < 0)) return TLS_GENERIC_ERROR;

  tls_close_notify(context);
  return 0;
}

int SSL_write(struct TLSContext *context, const void *buf, unsigned int len) {
  if (!context) return TLS_GENERIC_ERROR;
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if ((!ssl_data) || (ssl_data->fd < 0)) return TLS_GENERIC_ERROR;

  int written_size = tls_write(context, (const unsigned char *)buf, len);
  if (written_size > 0) {
    int res = _tls_ssl_private_send_pending(ssl_data->fd, context);
    if (res <= 0) return res;
  }
  return written_size;
}

int SSL_read(struct TLSContext *context, void *buf, unsigned int len) {
  if (!context) return TLS_GENERIC_ERROR;

  if (context->application_buffer_len)
    return tls_read(context, (unsigned char *)buf, len);

  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if ((!ssl_data) || (ssl_data->fd < 0) || (context->critical_error))
    return TLS_GENERIC_ERROR;
  if (tls_established(context) != 1) return TLS_GENERIC_ERROR;

  if (!context->application_buffer_len) {
    unsigned char client_message[0xFFFF];
    // accept
    int read_size;
    while ((read_size = _private_tls_safe_read(context, (char *)client_message,
                                               sizeof(client_message))) > 0) {
      if (tls_consume_stream(context, client_message, read_size,
                             ssl_data->certificate_verify) > 0) {
        _tls_ssl_private_send_pending(ssl_data->fd, context);
        break;
      }
      if ((context->critical_error) && (!context->application_buffer_len)) {
        return TLS_GENERIC_ERROR;
      }
    }
    if ((read_size <= 0) && (!context->application_buffer_len))
      return read_size;
  }

  return tls_read(context, (unsigned char *)buf, len);
}

int SSL_pending(struct TLSContext *context) {
  if (!context) return TLS_GENERIC_ERROR;
  return context->application_buffer_len;
}

int SSL_set_io(struct TLSContext *context, void *recv_cb, void *send_cb) {
  if (!context) return TLS_GENERIC_ERROR;
  SSLUserData *ssl_data = (SSLUserData *)context->user_data;
  if (!ssl_data) {
    ssl_data = (SSLUserData *)TLS_MALLOC(sizeof(SSLUserData));
    if (!ssl_data) return TLS_NO_MEMORY;
    memset(ssl_data, 0, sizeof(SSLUserData));
    context->user_data = ssl_data;
  }
  ssl_data->recv = recv_cb;
  ssl_data->send = send_cb;
  return 0;
}
#endif  // SSL_COMPATIBLE_INTERFACE