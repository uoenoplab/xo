#ifndef __MD5_H__
#define __MD5_H__

#include <openssl/md5.h>

// Structure to hold the rolling MD5 context
typedef struct {
    MD5_CTX md5_ctx; // MD5 context
    unsigned char buffer[MD5_DIGEST_LENGTH]; // MD5 hash result
    size_t data_size; // Current data size in the buffer
} RollingMD5Context;

void initRollingMD5(RollingMD5Context *ctx);
void updateRollingMD5(RollingMD5Context *ctx, const void *data, size_t size);
void finalizeRollingMD5(RollingMD5Context *ctx, char *result);

#endif
