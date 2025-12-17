#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <asm/byteorder.h>

#include "tls.h"
#include "util.h"

#define print_ssl_state(ssl) zlog_debug(zlog_tls, "SSL-STATE: %s", SSL_state_string_long(ssl));


zlog_category_t *zlog_tls;

//static void __attribute_maybe_unused__ hexdump(const char *title, void *buf, size_t len)
//{
//  printf("%s (%lu bytes) :\n", title, len);
//  for (size_t i = 0; i < len; i++) {
//    printf("%02hhX ", ((uint8_t *)buf)[i]);
//    if (i % 16 == 15) printf("\n");
//  }
//  printf("\n");
//}

static unsigned char hex_char_to_int(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return 0;
}

static void hex_to_bytes(const char *hex_str, unsigned char *bytes, size_t bytes_len)
{
    for (size_t i = 0; i < bytes_len; ++i) {
        bytes[i] = hex_char_to_int(hex_str[2*i]) * 16 + hex_char_to_int(hex_str[2*i + 1]);
    }
}

int hkdf_tls13_sha384_expand(EVP_KDF_CTX *kctx,
	const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len,
	const char *label)
{
    OSSL_PARAM params[8], *p = params;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha384, strlen(SN_sha384));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)in, in_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX, "tls13 ", strlen("tls13 "));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, (void *)label, strlen(label));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_DATA, "", 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "EXPAND_ONLY", strlen("EXPAND_ONLY"));
    *p = OSSL_PARAM_construct_end();

    return EVP_KDF_derive(kctx, out, out_len, params);
}

void keylog_callback(const SSL *ssl, const char *line)
{
    const char *client_prefix = "CLIENT_TRAFFIC_SECRET_0 ";
    const char *server_prefix = "SERVER_TRAFFIC_SECRET_0 ";

	bool is_client_secret;
    if (strncmp(line, client_prefix, strlen(client_prefix)) == 0) {
		is_client_secret = true;
    } else if (strncmp(line, server_prefix, strlen(server_prefix)) == 0) {
        is_client_secret = false;
    } else {
        return;
    }

	char *traffic_secret_start = strchr(line + strlen(server_prefix), ' ');
	if (traffic_secret_start == NULL) {
		fprintf(stderr, "%s: incomplete keylog line \"%s\"\n", __func__, line);
		exit(EXIT_FAILURE);
	}
	traffic_secret_start++;

	if (strlen(traffic_secret_start) != 48 * 2) {
		fprintf(stderr, "%s: secret incorrect length %ld \"%s\"\n", __func__,
			strlen(traffic_secret_start), traffic_secret_start);
		exit(EXIT_FAILURE);
	}

	struct http_client *client = SSL_get_app_data(ssl);
	if (client == NULL) {
		fprintf(stderr, "%s: client is NULL\n", __func__);
		exit(EXIT_FAILURE);
	}

	if (is_client_secret) {
		if (client->tls.is_client_traffic_secret_set) {
			fprintf(stderr, "%s: is_client_traffic_secret_set is true\n", __func__);
			exit(EXIT_FAILURE);
		}
		hex_to_bytes(traffic_secret_start, client->tls.client_traffic_secret,
			sizeof(client->tls.client_traffic_secret));
		//hexdump("client->tls.client_traffic_secret", client->tls.client_traffic_secret,
		//	sizeof(client->tls.client_traffic_secret));
		client->tls.is_client_traffic_secret_set = true;
	} else {
		if (client->tls.is_server_traffic_secret_set) {
			fprintf(stderr, "%s: is_server_traffic_secret_set is true\n", __func__);
			exit(EXIT_FAILURE);
		}
		hex_to_bytes(traffic_secret_start, client->tls.server_traffic_secret,
			sizeof(client->tls.server_traffic_secret));
		//hexdump("client->tls.client_traffic_secret", client->tls.server_traffic_secret,
		//	sizeof(client->tls.server_traffic_secret));
		client->tls.is_server_traffic_secret_set = true;
	}
}

static inline void print_ssl_error(const char *msg)
{
	zlog_error(zlog_tls, "%s", msg);

	BIO *bio = BIO_new(BIO_s_mem());
	ERR_print_errors(bio);
	char *buf;
	size_t len = BIO_get_mem_data(bio, &buf);
	if (len > 0)
		zlog_error(zlog_tls, "SSL-ERROR: %s", buf);
	BIO_free(bio);
}

static inline int count_tls_records(const char *buffer, size_t buf_size) {
    // Check if the buffer starts with a TLS header
    if (buf_size < 5 || buffer[0] != 0x17 || buffer[1] != 0x03 || buffer[2] != 0x03) {
        zlog_error(zlog_tls, "Error: Buffer does not start with a TLS header.");
        return -1;
    }

    size_t i = 0;
    int count = 0;

    while (i + 5 <= buf_size) { // Ensure there's enough buffer left for header + length field
        // At this point, buffer[i] must be the start of a TLS header
        // Found a TLS header, read the length
        uint16_t length = (buffer[i+3] << 8) | (buffer[i+4] & 0xff);

	//printf("i %d buf_size %d length %d buffer[i+3] %X buffer[i+4] %X\n", i, buf_size, length,
	//		buffer[i+3], buffer[i+4]);

        if (i + 5 + length > buf_size) {
            // Not enough data for the complete record
            printf("Error: Partial TLS record encountered.\n");
            return -1;
        }

        // Jump ahead by the length of the TLS record
        i += 5 + length;
        count++;

        // If the next record does not start immediately, we're done
        if (i < buf_size && (buffer[i] != 0x17 || buffer[i+1] != 0x03 || buffer[i+2] != 0x03)) {
            printf("Error: Data after a complete TLS record is not a TLS header.\n");
            return -1;
        }
    }

    return count;
}

int tls_init()
{
//	if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS) != 1) {
//		print_ssl_error("OPENSSL_init_crypto failed\n");
//		return -1;
//	}
// 	SSL_library_init();
// 	OpenSSL_add_all_algorithms();
// 	SSL_load_error_strings();
// #if OPENSSL_VERSION_MAJOR < 3
// 	ERR_load_BIO_strings(); // deprecated since OpenSSL 3.0
// #endif
// 	ERR_load_crypto_strings();
// 	SSL_load_error_strings();
// 	ERR_load_crypto_strings();
	return 0;
}

void tls_uninit_ctx(SSL_CTX *ctx) {
	void *app_data = NULL;
	if ((app_data = SSL_CTX_get_app_data(ctx)) != NULL) {
		EVP_KDF_CTX *kctx = app_data;
		EVP_KDF *kdf = EVP_KDF_CTX_kdf(kctx);
		EVP_KDF_CTX_free(kctx);
		if (kdf != NULL) EVP_KDF_free(kdf);
	}
	if (ctx) {
		SSL_CTX_free(ctx);
	}
}

// per thread
SSL_CTX *tls_init_ctx(const char *certfile, const char *keyfile)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_method());
	if (ctx == NULL) {
		print_ssl_error("SSL_CTX_new failed\n");
		goto err;
	}

	/* Load certificate and private key files, and check consistency */
	if (certfile && keyfile) {
		if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) != 1) {
			print_ssl_error("SSL_CTX_use_certificate_file failed\n");
			goto err;
		}
		//urintf("keyfile %s\n", keyfile);
		if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
			print_ssl_error("SSL_CTX_use_PrivateKey_file failed\n");
			goto err;
		}

		/* Make sure the key and certificate file match. */
		if (SSL_CTX_check_private_key(ctx) != 1) {
			print_ssl_error("SSL_CTX_check_private_key failed\n");
			goto err;
		}

		//zlog_debug(zlog_tls, "certificate and private key loaded and verified");
	}

	// Enable all bug workarounds, only also TLS 1.3
	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
		print_ssl_error("SSL_CTX_set_min_proto_version failed\n");
		goto err;
	}

	// TODO: add AES_128_GCM_SHA256, now TLS_AES_256_GCM_SHA384 only
	if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != 1) {
		print_ssl_error("SSL_CTX_set_ciphersuites failed\n");
		goto err;
	}

	SSL_CTX_set_keylog_callback(ctx, keylog_callback);
	if (SSL_CTX_get_keylog_callback(ctx) != keylog_callback) {
		fprintf(stderr, "Failed to set keylog callback\n");
		goto err;
	}

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "TLS13-KDF", NULL);
    if (kdf == NULL) {
		fprintf(stderr, "Failed to EVP_KDF_fetch(NULL, TLS13-KDF, NULL)\n");
		goto err;
	}

	EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
		fprintf(stderr, "Failed to EVP_KDF_CTX_new(kdf)\n");
		EVP_KDF_free(kdf);
		goto err;
	}

	SSL_CTX_set_app_data(ctx, kctx);
	if (SSL_CTX_get_app_data(ctx) != kctx) {
		fprintf(stderr, "Failed to SSL_CTX_set_app_data(ctx, kctx)\n");
		EVP_KDF_CTX_free(kctx);
		EVP_KDF_free(kdf);
		goto err;
	}

	return ctx;

err:
	if (ctx != NULL) {
		SSL_CTX_free(ctx);
	}
	return NULL;
}

void tls_free_client(struct http_client *client) {
	if (client->tls.ssl) {
		SSL_free(client->tls.ssl);
		return;
	}
	// We shouldn't free BIO since it will be freed at SSL_free
	if (client->tls.wbio) BIO_free_all(client->tls.wbio);
	if (client->tls.rbio) BIO_free_all(client->tls.rbio);
}

// per connection
// 0 on success, -1 on error
int tls_init_client(SSL_CTX *ctx, struct http_client *client, char *buf, ssize_t size)
{
	const int min_bytes = 3;

	int copy_size = min_bytes - client->tls.client_hello_check_off;
	if (size < copy_size) copy_size = size;
	memcpy(client->tls.client_hello_check_buf, buf, copy_size);
	client->tls.client_hello_check_off += copy_size;

	if (client->tls.client_hello_check_off < min_bytes) {
		return 0;
	}

	if (client->tls.client_hello_check_off == min_bytes) {
		// now indicates bytes from previous recv, i.e. bytes current
		// not in client_data_buffer
		client->tls.client_hello_check_off -= copy_size;
		if (!(client->tls.client_hello_check_buf[0] == 0x16 &&
			client->tls.client_hello_check_buf[1] == 0x03 &&
			client->tls.client_hello_check_buf[2] == 0x01)) {
			// HTTP mode
			client->tls.is_ssl = false;
			return 0;
		}
	}

	client->tls.rbio = BIO_new(BIO_s_mem());
	if (client->tls.rbio == NULL) {
		zlog_error(zlog_tls, "BIO_new for rbio failed (fd=%d)", client->fd);
		goto err_rbio;
	}

	client->tls.wbio = BIO_new(BIO_s_mem());
	if (client->tls.wbio == NULL) {
		zlog_error(zlog_tls, "BIO_new for wbio failed (fd=%d)", client->fd);
		goto err_wbio;
	}

	client->tls.ssl = SSL_new(ctx);
	if (client->tls.ssl == NULL) {
		zlog_error(zlog_tls, "BIO_new for ssl failed (fd=%d)", client->fd);
		goto err_ssl_new;
	}

	SSL_set_app_data(client->tls.ssl, client);
	if (SSL_get_app_data(client->tls.ssl) != client) {
		zlog_error(zlog_tls, "SSL_set_app_data failed (fd=%d)", client->fd);
		goto err;
	}

	SSL_set_accept_state(client->tls.ssl);

	SSL_set_bio(client->tls.ssl, client->tls.rbio, client->tls.wbio);

	if (client->tls.client_hello_check_off) {
		BIO_write(client->tls.rbio, client->tls.client_hello_check_buf,
			client->tls.client_hello_check_off);
	}

	return 0;

err:
	SSL_free(client->tls.ssl);
err_ssl_new:
	BIO_free_all(client->tls.wbio);
err_wbio:
	BIO_free_all(client->tls.rbio);
err_rbio:
	return -1;
}

static inline void reset_client_send_buffer(struct http_client *client)
{
	//if (client->response != NULL) {
	//	free(client->response);
	//	client->response = NULL;
		client->response_size = 0;
		client->response_sent = 0;
	//}

	//if (client->data_payload != NULL) {
		//free(client->data_payload);
		//client->data_payload = NULL;
		client->data_payload_size = 0;
		client->data_payload_sent = 0;
	//}
}

static int tls_make_ktls(struct http_client *client, uint64_t recv_rec_seqnum) {
	struct tls12_crypto_info_aes_gcm_256 crypto_info_send = {0};
	struct tls12_crypto_info_aes_gcm_256 crypto_info_recv = {0};
	crypto_info_send.info.version = TLS_1_3_VERSION;
	crypto_info_recv.info.version = TLS_1_3_VERSION;
	crypto_info_send.info.cipher_type = TLS_CIPHER_AES_GCM_256;
	crypto_info_recv.info.cipher_type = TLS_CIPHER_AES_GCM_256;

	unsigned char iv_buffer[TLS_CIPHER_AES_GCM_256_IV_SIZE + TLS_CIPHER_AES_GCM_256_SALT_SIZE];

	if (!client->tls.is_client_traffic_secret_set || !client->tls.is_server_traffic_secret_set) {
		zlog_error(zlog_tls, "traffic secret not set (fd=%d)", client->fd);
		return -1;
	}

	SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(client->tls.ssl);
	EVP_KDF_CTX *kctx = SSL_CTX_get_app_data(ssl_ctx);
	if (kctx == NULL) {
		zlog_error(zlog_tls, "kctx is NULL (fd=%d)", client->fd);
		EVP_KDF_CTX_free(kctx);
		return -1;
	}

	hkdf_tls13_sha384_expand(kctx, client->tls.client_traffic_secret, sizeof(client->tls.client_traffic_secret),
		crypto_info_recv.key, sizeof(crypto_info_recv.key), "key");
	hkdf_tls13_sha384_expand(kctx, client->tls.client_traffic_secret, sizeof(client->tls.client_traffic_secret),
		iv_buffer, sizeof(iv_buffer), "iv");
	memcpy(crypto_info_recv.iv, iv_buffer + 4, TLS_CIPHER_AES_GCM_256_IV_SIZE);
  	memcpy(crypto_info_recv.salt, iv_buffer, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
	*((__be64 *)crypto_info_recv.rec_seq) = __be64_to_cpu(recv_rec_seqnum);

	hkdf_tls13_sha384_expand(kctx, client->tls.server_traffic_secret, sizeof(client->tls.server_traffic_secret),
		crypto_info_send.key, sizeof(crypto_info_send.key), "key");
	hkdf_tls13_sha384_expand(kctx, client->tls.server_traffic_secret, sizeof(client->tls.server_traffic_secret),
		iv_buffer, sizeof(iv_buffer), "iv");
	memcpy(crypto_info_send.iv, iv_buffer + 4, TLS_CIPHER_AES_GCM_256_IV_SIZE);
  	memcpy(crypto_info_send.salt, iv_buffer, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
	*((__be64 *)crypto_info_send.rec_seq) = __be64_to_cpu(0);

	if (setsockopt(client->fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
		zlog_error(zlog_tls, "set ULP tls fail: %s (fd=%d)", strerror(errno), client->fd);
		return -1;
	}

	if (setsockopt(client->fd, SOL_TLS, TLS_TX, &crypto_info_send,
					sizeof(crypto_info_send)) < 0) {
		zlog_error(zlog_tls, "Couldn't set TLS_TX option: %s (fd=%d)", strerror(errno), client->fd);
		return -1;
	}

	if (setsockopt(client->fd, SOL_TLS, TLS_RX, &crypto_info_recv,
					sizeof(crypto_info_recv)) < 0) {
		zlog_error(zlog_tls, "Couldn't set TLS_RX option: %s (fd=%d)", strerror(errno), client->fd);
		return -1;
	}

	client->tls.is_ktls_set = true;

	return 0;
}

// return number of bytes left in client_data_buffer after this function
int tls_handle_handshake(struct http_client *client, const char *client_data_buffer, const ssize_t bytes_received)
{
	int ret;

	if (SSL_is_init_finished(client->tls.ssl)) {
		zlog_fatal(zlog_tls, "conn with handshake done should enter this function (fd=%d)", client->fd);
		return -1;
	}

	reset_client_send_buffer(client);

	// printf("%s: bytes_received %d\n", __func__, bytes_received);
	int bytes_written = 0;
	while (bytes_written != bytes_received) {
		ret = BIO_write(client->tls.rbio, client_data_buffer, bytes_received);
		bytes_written += ret;
		if (ret == -1) {
			print_ssl_error("BIO_write(client->tls.rbio, client_.. returned -1");
			return -1;
		} else if (ret == 0) {
			print_ssl_error("unable to write more bytes into rbio but client_data_buffer not drained");
			return -1;
		}
	}

	print_ssl_state(client->tls.ssl);
	ret = SSL_get_error(client->tls.ssl, SSL_do_handshake(client->tls.ssl));
	print_ssl_state(client->tls.ssl);

	if (ret == SSL_ERROR_NONE) {
		client->tls.is_handshake_done = true;
		zlog_info(zlog_tls, "Handshake Done - TLS Version: %s, TLS Cipher: %s", SSL_get_version(client->tls.ssl), SSL_get_cipher(client->tls.ssl));

		// printf("BIO_pending(client->tls.rbio) %d SSL_has_pending(client->tls.ssl) %d\n",
		// 	BIO_pending(client->tls.rbio), SSL_has_pending(client->tls.ssl));
		// if (SSL_pending(client->tls.ssl)) {
		// 	print_ssl_error("Unable to handle the case openssl decrypt data"
		// 		"before call SSL_read\n");
		// 	return -1;
		// }

		// application bytes in openssl come with client finish
		int bytes_pending = BIO_pending(client->tls.rbio);
		if (bytes_pending == 0) {
			if (tls_make_ktls(client, 0) == -1) {
				zlog_error(zlog_tls, "tls_make_ktls failed (fd=%d)", client->fd);
				return -1;
			}
			return 0;
		}

		//printf("received %d pengding %d\n", bytes_received, bytes_pending);
		//hexdump("pending_bytes", client_data_buffer + bytes_received - bytes_pending, bytes_pending);

		// scan number of tls record headers from pending bytes
		int recv_rec_seqnum = count_tls_records(client_data_buffer + bytes_received - bytes_pending, bytes_pending);
		if (recv_rec_seqnum == -1) {
			zlog_error(zlog_tls, "Unable to handle the case tls record arrived partically before set ktls (fd=%d)", client->fd);
		}

		// 1. first data record can come with client finish
		// 2. bytes_received as ciphertext should be larger than bytes_decrypted
		//    so it is safe to put decrypted bytes in client_data_buffer
		// 3. we need
		int bytes_decrypted = 0;
		ret = 0;
		do {
			ret = SSL_read(client->tls.ssl, client_data_buffer + bytes_decrypted,
				bytes_received - bytes_decrypted);
			zlog_debug(zlog_tls, "bytes_decrypted %d ret %d (fd=%d)", bytes_decrypted, ret, client->fd);
			if (ret < 0) {
				ret = SSL_get_error(client->tls.ssl, ret);
				if (ret != SSL_ERROR_WANT_READ) {
					print_ssl_error("SSL_read(client->tls.ssl, client_data_buffer"
						" + bytes_decrypted, bytes_received - bytes_decrypted) "
						"returned -1");
					zlog_error(zlog_tls, "SSL_get_error %d (fd=%d)", ret, client->fd);
					return -1;
				} else {
					ret = 0;
				}
			}
			bytes_decrypted += ret;
		} while (ret > 0);

		if (SSL_has_pending(client->tls.ssl)) {
			print_ssl_error("Unable to handle the case tls record arrived partically before set ktls");
			return -1;
		}

		// now we are safe to set ktls
		if (tls_make_ktls(client, (uint64_t) recv_rec_seqnum) == -1) {
			zlog_error(zlog_tls, "tls_make_ktls failed (fd=%d)", client->fd);
			return -1;
		}

		return bytes_decrypted;
	} else if (ret == SSL_ERROR_WANT_WRITE || ret == SSL_ERROR_WANT_READ) {
		// printf("BIO_pending(client->tls.wbio) %d BIO_pending(client->tls.rbio) %d SSL_has_pending(client->tls.ssl) %d\n",
		// 	BIO_pending(client->tls.wbio), BIO_pending(client->tls.rbio), SSL_has_pending(client->tls.ssl));

		// need more bytes to process read side
		if (SSL_has_pending(client->tls.ssl)) return 0;

		// server wants to send server hello / fin etc.
		if ((ret = BIO_pending(client->tls.wbio)) > 0) {
			client->response_size = ret;
			//client->response = malloc(client->response_size);

			int bytes_read = 0;
			while (bytes_read != client->response_size) {
				ret = BIO_read(client->tls.wbio, client->response + bytes_read,
					client->response_size - bytes_read);
				bytes_read += ret;
				if (ret == -1) {
					reset_client_send_buffer(client);
					print_ssl_error("BIO_read(client->tls.wbio, client->res.. returned -1");
					return -1;
				} else if (ret == 0) {
					reset_client_send_buffer(client);
					print_ssl_error("unable to write more bytes into client->response but wbio not drained");
					return -1;
				}
			}

			send_response(client);
			return 0;
		}

		print_ssl_error("SSL_handshake returned SSL_ERROR_WANT_WRITE or"
			"SSL_ERROR_WANT_READ but no pending client hello / finish, and no"
			"pending server hello");
	} else {
		print_ssl_error("SSL_handshake returned a status can not handle");
		return -1;
	}

	return -1;
}
