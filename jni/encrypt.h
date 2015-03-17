/*
 * encrypt.h - Define the enryptor's interface
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */
#ifdef __cplusplus
extern "C" {
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "openssl/evp.h"
#include "system.h"

typedef EVP_CIPHER cipher_kt_t;
typedef EVP_CIPHER_CTX cipher_evp_t;
typedef EVP_MD digest_type_t;

#define MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH
#define MAX_IV_LENGTH EVP_MAX_IV_LENGTH
#define MAX_MD_SIZE EVP_MAX_MD_SIZE

typedef struct {
    cipher_evp_t evp;
    uint8_t iv[MAX_IV_LENGTH];
} cipher_ctx_t;

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define SODIUM_BLOCK_SIZE   64
#define CIPHER_NUM          17

#define NONE                -1
#define TABLE               0
#define RC4                 1
#define RC4_MD5             2
#define AES_128_CFB         3
#define AES_192_CFB         4
#define AES_256_CFB         5
#define BF_CFB              6
#define CAMELLIA_128_CFB    7
#define CAMELLIA_192_CFB    8
#define CAMELLIA_256_CFB    9
#define CAST5_CFB           10
#define DES_CFB             11
#define IDEA_CFB            12
#define RC2_CFB             13
#define SEED_CFB            14
#define SALSA20             15
#define CHACHA20            16

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))
//#define DEBUG 1

struct enc_ctx {
    uint8_t init;
    uint64_t counter;
    cipher_ctx_t evp;
};

char * ss_encrypt_all(int buf_size, char *plaintext, ssize_t *len, int method);
char * ss_decrypt_all(int buf_size, char *ciphertext, ssize_t *len, int method);
char * ss_encrypt(int buf_size, char *plaintext, ssize_t *len,
                  struct enc_ctx *ctx);
char * ss_decrypt(int buf_size, char *ciphertext, ssize_t *len,
                  struct enc_ctx *ctx);
void enc_ctx_init(int method, struct enc_ctx *ctx, int enc);
int enc_init(const char *pass, const char *method);
int enc_get_iv_len(void);
void cipher_context_release(cipher_ctx_t *evp);
unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md);
int rand_bytes(uint8_t *output, int len);
#ifdef __cplusplus
}
#endif
