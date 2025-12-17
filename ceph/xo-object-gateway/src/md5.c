#include <stdio.h>
#include "md5.h"

// Initialize the rolling MD5 context
void initRollingMD5(RollingMD5Context *ctx) {
	MD5_Init(&ctx->md5_ctx);
	ctx->data_size = 0;
}

// Update the rolling MD5 hash with new data
void updateRollingMD5(RollingMD5Context *ctx, const void *data, size_t size) {
	MD5_Update(&ctx->md5_ctx, data, size);
	ctx->data_size += size;
}

// Finalize the rolling MD5 hash and store the result in the provided buffer
void finalizeRollingMD5(RollingMD5Context *ctx, char *result) {
	unsigned char md5_digest[MD5_DIGEST_LENGTH];
	MD5_Final(md5_digest, &ctx->md5_ctx);
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		sprintf(&result[i * 2], "%02x", md5_digest[i]);
	}
}
