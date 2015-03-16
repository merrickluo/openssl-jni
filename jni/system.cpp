#include "jni.h"
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cpu-features.h>
#include "system.h"

#include "encrypt.h"

#define BUFF_SIZE 20000

struct enc_ctx *text_e_ctx, *text_d_ctx;

//enc_ctx *encryptors;

JNIEXPORT void JNICALL Java_me_smartproxy_crypto_CryptoUtils_initEncryptor(JNIEnv *env, jclass thiz, jstring jpassword, jstring jmethod) {
    const char *password = env->GetStringUTFChars(jpassword, 0);
    const char *method = env->GetStringUTFChars(jmethod, 0);

    text_e_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));
    text_d_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));

    int enc_method = enc_init(password, method);
    enc_ctx_init(enc_method, text_e_ctx, 1);
    enc_ctx_init(enc_method, text_d_ctx, 0);
}

JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_encryptAll(JNIEnv *env, jclass thiz, jbyteArray array, jstring jpassword, jstring jmethod) {
    const char *password = env->GetStringUTFChars(jpassword, 0);
    const char *method = env->GetStringUTFChars(jmethod, 0);

    struct enc_ctx *temp_e_ctx;
    temp_e_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));
    int enc_method = enc_init(password, method);
    enc_ctx_init(enc_method, temp_e_ctx, 1);

    ssize_t size = 0;
    char *buffer = as_char_array(env, array, &size);
    char *encrypted = ss_encrypt(BUFF_SIZE, buffer, &size, temp_e_ctx,0);
    return as_byte_array(env, encrypted, size);
}

JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_decryptAll(JNIEnv *env, jclass thiz, jbyteArray array, jstring jpassword, jstring jmethod) {
    const char *password = env->GetStringUTFChars(jpassword, 0);
    const char *method = env->GetStringUTFChars(jmethod, 0);

    struct enc_ctx *temp_d_ctx;
    temp_d_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));
    int enc_method = enc_init(password, method);
    enc_ctx_init(enc_method, temp_d_ctx, 1);

    ssize_t size = 0;
    char *buffer = as_char_array(env, array, &size);
    char *decrypted = ss_decrypt(BUFF_SIZE, buffer, &size, temp_d_ctx,0);
    if(decrypted == NULL) {
        return NULL;
    }
    return as_byte_array(env, decrypted, size);
}


JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_encrypt(JNIEnv *env, jclass thiz, jbyteArray array, jbyteArray jIV) {
    ssize_t size = 0, iv_size = 0;
    char *buffer = as_char_array(env, array, &size);
    uint8_t *iv = (uint8_t*) as_char_array(env, jIV, &iv_size);
    char *encrypted = ss_encrypt(BUFF_SIZE, buffer, &size, text_e_ctx, iv);
    return as_byte_array(env, encrypted, size);
}

JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_decrypt(JNIEnv *env, jclass thiz, jbyteArray array, jbyteArray jIV) {
    ssize_t size = 0, iv_size = 0;
    char *buffer = as_char_array(env, array, &size);
    uint8_t *iv = (uint8_t *) as_char_array(env, jIV, &iv_size);
    char *decrypted = ss_decrypt(BUFF_SIZE, buffer, &size, text_d_ctx, iv);
    return as_byte_array(env, decrypted, size);
}

jbyteArray as_byte_array(JNIEnv *env, char* buf, ssize_t len) {
    jbyteArray array = env->NewByteArray(len);
    env->SetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(buf));
    return array;
}

char* as_char_array(JNIEnv *env, jbyteArray array,ssize_t *len) {
    *len = env->GetArrayLength(array);
    char* buf = new char[*len];
    env->GetByteArrayRegion(array, 0, *len, reinterpret_cast<jbyte*>(buf));
    return buf;
}
