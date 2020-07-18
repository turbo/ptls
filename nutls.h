#ifndef TLSE_H
#define TLSE_H

#define SSL_V30 0x0300
#define TLS_V10 0x0301
#define TLS_V11 0x0302
#define TLS_V12 0x0303
#define TLS_V13 0x0304
#define DTLS_V10 0xFEFF
#define DTLS_V12 0xFEFD
#define DTLS_V13 0xFEFC

#define TLS_NEED_MORE_DATA 0
#define TLS_GENERIC_ERROR -1
#define TLS_BROKEN_PACKET -2
#define TLS_NOT_UNDERSTOOD -3
#define TLS_NOT_SAFE -4
#define TLS_NO_COMMON_CIPHER -5
#define TLS_UNEXPECTED_MESSAGE -6
#define TLS_COMPRESSION_NOT_SUPPORTED -8
#define TLS_NO_MEMORY -9
#define TLS_NOT_VERIFIED -10
#define TLS_INTEGRITY_FAILED -11
#define TLS_ERROR_ALERT -12
#define TLS_BROKEN_CONNECTION -13
#define TLS_BAD_CERTIFICATE -14
#define TLS_UNSUPPORTED_CERTIFICATE -15
#define TLS_NO_RENEGOTIATION -16
#define TLS_FEATURE_NOT_SUPPORTED -17
#define TLS_DECRYPTION_FAILED -20

#define TLS_AES_128_GCM_SHA256 0x1301
#define TLS_AES_256_GCM_SHA384 0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303
#define TLS_AES_128_CCM_SHA256 0x1304
#define TLS_AES_128_CCM_8_SHA256 0x1305

#define TLS_RSA_WITH_AES_128_GCM_SHA256 0x009C
#define TLS_RSA_WITH_AES_256_GCM_SHA384 0x009D

// forward secrecy
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA 0x0033
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 0x009E
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 0x009F

#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xC02F
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 0xC030

#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA 0xC009
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA 0xC00A
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02C

#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 0xCCA8
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 0xCCA9
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 0xCCAA

#define TLS_FALLBACK_SCSV 0x5600

#define TLS_UNSUPPORTED_ALGORITHM 0x00
#define TLS_RSA_SIGN_RSA 0x01
#define TLS_RSA_SIGN_MD5 0x04
#define TLS_RSA_SIGN_SHA1 0x05
#define TLS_RSA_SIGN_SHA256 0x0B
#define TLS_RSA_SIGN_SHA384 0x0C
#define TLS_RSA_SIGN_SHA512 0x0D

#define TLS_EC_PUBLIC_KEY 0x11
#define TLS_EC_prime192v1 0x12
#define TLS_EC_prime192v2 0x13
#define TLS_EC_prime192v3 0x14
#define TLS_EC_prime239v1 0x15
#define TLS_EC_prime239v2 0x16
#define TLS_EC_prime239v3 0x17
#define TLS_EC_prime256v1 0x18
#define TLS_EC_secp224r1 21
#define TLS_EC_secp256r1 23
#define TLS_EC_secp384r1 24
#define TLS_EC_secp521r1 25

#define TLS_ALERT_WARNING 0x01
#define TLS_ALERT_CRITICAL 0x02

#define TLS_CIPHERS_SIZE(n, mitigated) n * 2

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  close_notify = 0,
  unexpected_message = 10,
  bad_record_mac = 20,
  decryption_failed_RESERVED = 21,
  decompression_failure = 30,
  bad_certificate = 42,
  unsupported_certificate = 43,
  certificate_revoked = 44,
  certificate_expired = 45,
  certificate_unknown = 46,
  decode_error = 50,
  decrypt_error = 51,
  insufficient_security = 71,
  internal_error = 80,
  inappropriate_fallback = 86,
  user_canceled = 90,
  no_renegotiation = 100,
  no_error = 255
} TLSAlertDescription;

// forward declarations
struct TLSPacket;
struct TLSCertificate;
struct TLSContext;
struct ECCCurveParameters;
typedef struct TLSContext TLS;
typedef struct TLSCertificate Certificate;

typedef int (*tls_validation_function)(
    struct TLSContext *context, struct TLSCertificate **certificate_chain,
    int len);

/*
  Global initialization. Optional, as it will be called automatically;
  however, the initialization is not thread-safe, so if you intend to use TLSe
  from multiple threads, you'll need to call tls_init() once, from a single
  thread, before using the library.
 */
void tls_init();
unsigned char *tls_pem_decode(const unsigned char *data_in,
                              unsigned int input_length, int cert_index,
                              unsigned int *output_len);
struct TLSCertificate *tls_create_certificate();
int tls_certificate_valid_subject(struct TLSCertificate *cert,
                                  const char *subject);
int tls_certificate_valid_subject_name(const unsigned char *cert_subject,
                                       const char *subject);
int tls_certificate_is_valid(struct TLSCertificate *cert);
void tls_certificate_set_copy(unsigned char **member, const unsigned char *val,
                              int len);
void tls_certificate_set_copy_date(unsigned char **member,
                                   const unsigned char *val, int len);
void tls_certificate_set_key(struct TLSCertificate *cert,
                             const unsigned char *val, int len);
void tls_certificate_set_priv(struct TLSCertificate *cert,
                              const unsigned char *val, int len);
void tls_certificate_set_sign_key(struct TLSCertificate *cert,
                                  const unsigned char *val, int len);
char *tls_certificate_to_string(struct TLSCertificate *cert, char *buffer,
                                int len);
void tls_certificate_set_exponent(struct TLSCertificate *cert,
                                  const unsigned char *val, int len);
void tls_certificate_set_serial(struct TLSCertificate *cert,
                                const unsigned char *val, int len);
void tls_certificate_set_algorithm(unsigned int *algorithm,
                                   const unsigned char *val, int len);
void tls_destroy_certificate(struct TLSCertificate *cert);
struct TLSPacket *tls_create_packet(struct TLSContext *context,
                                    unsigned char type, unsigned short version,
                                    int payload_size_hint);
void tls_destroy_packet(struct TLSPacket *packet);
void tls_packet_update(struct TLSPacket *packet);
int tls_packet_append(struct TLSPacket *packet, const unsigned char *buf,
                      unsigned int len);
int tls_packet_uint8(struct TLSPacket *packet, unsigned char i);
int tls_packet_uint16(struct TLSPacket *packet, unsigned short i);

int tls_packet_uint24(struct TLSPacket *packet, unsigned int i);
//int tls_random(unsigned char *key, int len);

/*
  Get encrypted data to write, if any. Once you've sent all of it, call
  tls_buffer_clear().
 */
const unsigned char *tls_get_write_buffer(struct TLSContext *context,
                                          unsigned int *outlen);

void tls_buffer_clear(struct TLSContext *context);

/* Returns 1 for established, 0 for not established yet, and -1 for a critical
 * error. */
int tls_established(struct TLSContext *context);

/*
  Reads any unread decrypted data (see tls_consume_stream). If you don't read
  all of it, the remainder will be left in the internal buffers for next
  tls_read(). Returns -1 for fatal error, 0 for no more data, or otherwise the
  number of bytes copied into the buffer (up to a maximum of the given size).
 */
int tls_read(struct TLSContext *context, unsigned char *buf, unsigned int size);

struct TLSContext *tls_create_context(unsigned char is_server,
                                      unsigned short version);

/* Create a context for a given client, from a server context. Returns NULL on
 * error. */
struct TLSContext *tls_accept(struct TLSContext *context);

int tls_set_default_dhe_pg(struct TLSContext *context, const char *p_hex_str,
                           const char *g_hex_str);
void tls_destroy_context(struct TLSContext *context);
int tls_cipher_supported(struct TLSContext *context, unsigned short cipher);
int tls_cipher_is_fs(struct TLSContext *context, unsigned short cipher);
int tls_choose_cipher(struct TLSContext *context, const unsigned char *buf,
                      int buf_len, int *scsv_set);
int tls_cipher_is_ephemeral(struct TLSContext *context);
const char *tls_cipher_name(struct TLSContext *context);
int tls_is_ecdsa(struct TLSContext *context);
struct TLSPacket *tls_build_client_key_exchange(struct TLSContext *context);
struct TLSPacket *tls_build_server_key_exchange(struct TLSContext *context,
                                                int method);
struct TLSPacket *tls_build_hello(struct TLSContext *context,
                                  int tls13_downgrade);
struct TLSPacket *tls_certificate_request(struct TLSContext *context);
struct TLSPacket *tls_build_verify_request(struct TLSContext *context);
int tls_parse_hello(struct TLSContext *context, const unsigned char *buf,
                    int buf_len, unsigned int *write_packets,
                    unsigned int *dtls_verified);
int tls_parse_certificate(struct TLSContext *context, const unsigned char *buf,
                          int buf_len, int is_client);
int tls_parse_server_key_exchange(struct TLSContext *context,
                                  const unsigned char *buf, int buf_len);
int tls_parse_client_key_exchange(struct TLSContext *context,
                                  const unsigned char *buf, int buf_len);
int tls_parse_server_hello_done(struct TLSContext *context,
                                const unsigned char *buf, int buf_len);
int tls_parse_finished(struct TLSContext *context, const unsigned char *buf,
                       int buf_len, unsigned int *write_packets);
int tls_parse_verify(struct TLSContext *context, const unsigned char *buf,
                     int buf_len);
int tls_parse_payload(struct TLSContext *context, const unsigned char *buf,
                      int buf_len, tls_validation_function certificate_verify);
int tls_parse_message(struct TLSContext *context, unsigned char *buf,
                      int buf_len, tls_validation_function certificate_verify);
int tls_certificate_verify_signature(struct TLSCertificate *cert,
                                     struct TLSCertificate *parent);
int tls_certificate_chain_is_valid(struct TLSCertificate **certificates,
                                   int len);
int tls_certificate_chain_is_valid_root(struct TLSContext *context,
                                        struct TLSCertificate **certificates,
                                        int len);

/*
  Add a certificate or a certificate chain to the given context, in PEM form.
  Returns a negative value (TLS_GENERIC_ERROR etc.) on error, 0 if there were no
  certificates in the buffer, or the number of loaded certificates on success.
 */
int tls_load_certificates(struct TLSContext *context,
                          const unsigned char *pem_buffer, unsigned long pem_size);

/*
  Add a private key to the given context, in PEM form. Returns a negative value
  (TLS_GENERIC_ERROR etc.) on error, 0 if there was no private key in the
  buffer, or 1 on success.
 */
int tls_load_private_key(struct TLSContext *context,
                         const unsigned char *pem_buffer, unsigned long pem_size);
struct TLSPacket *tls_build_certificate(struct TLSContext *context);
struct TLSPacket *tls_build_finished(struct TLSContext *context);
struct TLSPacket *tls_build_change_cipher_spec(struct TLSContext *context);
struct TLSPacket *tls_build_done(struct TLSContext *context);
struct TLSPacket *tls_build_message(struct TLSContext *context,
                                    const unsigned char *data,
                                    unsigned int len);
int tls_client_connect(struct TLSContext *context);
int tls_write(struct TLSContext *context, const unsigned char *data,
              unsigned int len);
struct TLSPacket *tls_build_alert(struct TLSContext *context, char critical,
                                  unsigned char code);

/*
  Process a given number of input bytes from a socket. If the other side just
  presented a certificate and certificate_verify is not NULL, it will be called.

  Returns 0 if there's no data ready yet, a negative value (see
  TLS_GENERIC_ERROR etc.) for an error, or a positive value (the number of bytes
  used from buf) if one or more complete TLS messages were received. The data
  is copied into an internal buffer even if not all of it was consumed,
  so you should not re-send it the next time.

  Decrypted data, if any, should be read back with tls_read(). Can change the
  status of tls_established(). If the library has anything to send back on the
  socket (e.g. as part of the handshake), tls_get_write_buffer() will return
  non-NULL.
 */
int tls_consume_stream(struct TLSContext *context, const unsigned char *buf,
                       ssize_t buf_len, tls_validation_function certificate_verify);
void tls_close_notify(struct TLSContext *context);
void tls_alert(struct TLSContext *context, unsigned char critical, int code);

int tls_client_verified(struct TLSContext *context);
const char *tls_sni(struct TLSContext *context);
int tls_sni_set(struct TLSContext *context, const char *sni);
int tls_load_root_certificates(struct TLSContext *context,
                               const unsigned char *pem_buffer, size_t pem_size);

void tls_print_certificate(const char *fname);
//int tls_add_alpn(struct TLSContext *context, const char *alpn);
int tls_alpn_contains(struct TLSContext *context, const char *alpn,
                      unsigned char alpn_size);

// useful when renewing certificates for servers, without the need to restart
// the server
int tls_clear_certificates(struct TLSContext *context);
/*
  Creates a new DTLS random cookie secret to be used in HelloVerifyRequest
  (server-side). It is recommended to call this function from time to time, to
  protect against some DoS attacks.
*/
void dtls_reset_cookie_secret();

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
