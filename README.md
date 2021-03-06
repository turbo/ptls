# TLSe

- Linux only, 4.2xx required, 5.x expected
- TLS 1.3, 1.2 only
- Cha implemented and preferred
- [KTLS](https://github.com/torvalds/linux/blob/master/Documentation/networking/tls.rst) in both directions
- tlse API only, no libssl compat
- client side 1.3 enabled
- bundled [tomcrypt])(https://github.com/libtom/libtomcrypt)

Options in ptls:

- `WEAK_CHIPHERS` will re-enable CBC ciphers, which are considered WEAK. Only non-browser GnuTLS clients on old CentOS versions will need this.
- `FORITIFY_CIPHERS` will get rid of all ciphers except AES 256 and ChaCha20. You should enable this. All modern browsers support them. Only needed for Safari on macOS 10.10 and older, Android 6 and old Chrome (<70) on Win7. This will reach 100% on SSLLabs' cipher score. 

LE proper cert (4k):

```bash
acme.sh --issue --standalone -d nutls2.std.fyi -d www.nutls2.std.fyi -k 4096 -ak 4096
```

Compiling
----------

```bash
# release
gcc -Wall -Werror -fwhole-program -flto -Os -fomit-frame-pointer client.c -o client

# debug
gcc -Wall -Werror -O0 -g client.c -o client -DDEBUG
```

- If thread-safety is needed, you need to call `tls_init()` before letting any other threads in, and not use the same object from multiple threads without a mutex.
- The main feature of this implementation is the ability to serialize TLS context, via tls_export_context and re-import it, via tls_import_context in another pre-forked worker process (socket descriptor may be sent via sendmsg).


Notes
-----

- From tomcrypt it uses RSA, ECDSA and AES(GCM and CBC) encryption/decryption, SHA1, SHA256, SHA384, SHA512 and HMAC functions.
- Now it supports client certificate. To request a client certificate, call ``tls_request_client_certificate(TLSContext *)`` following ``tls_accept(TLSContext *)``.
- It implements SNI extension (Server Name Indication). To get the SNI string call ``tls_sni(TLSContext *)``. Also `sni_set` or prepare for errors.
- It also implements SCSV and ALPN (see ``tls_add_alpn(struct TLSContext *, const char *)`` and ``const char *tls_alpn(struct TLSContext *)``.
- The library supports certificate validation by using ``tls_certificate_chain_is_valid``, ``tls_certificate_chain_is_valid_root``, ``tls_certificate_valid_subject`` and ``tls_certificate_is_valid``(checks not before/not after).
- Certificates fed to ``tls_certificate_chain_is_valid`` must be in correct order (certificate 2 signs certificate 1, certificate 3 signs certificate 2 and so on; also certificate 1 (first) is the certificate to be used in key exchange).

Use TLS1.3 unless 1.2 is really needed. TLS1.2 will fail with ECDSA certs. Need to build logic like this:

![](https://mermaid.ink/svg/eyJjb2RlIjoiZ3JhcGggVERcbiAgQVtUTFMxLjIgQ2xpZW50XSAtLT58U3VjY2Vzc3wgQihSZXNwb25zZSlcbiAgQSAtLT58RmFpbHVyZXwgQ3tFQ0RTQT99XG4gIEMgLS0-fE5vfCBEKEVycm9yKVxuICBDIC0tPnxZZXN8IEVcbiAgRVtUTFMxLjMgQ2xpZW50XSAtLT58U3VjY2Vzc3wgQlxuICBFIC0tPnxGYWlsdXJlfCBEXG4iLCJtZXJtYWlkIjp7InRoZW1lIjoiZGVmYXVsdCJ9LCJ1cGRhdGVFZGl0b3IiOmZhbHNlfQ)

Conversly, TLS1.3 might not be ready for some other servers. If TLS1.3 fails with INTEGRITY CHECK FAILED (-11 in consume), retry with 1.2

License
----------
Public domain. Google code removed.
