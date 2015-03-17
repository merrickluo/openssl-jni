#include "jni.h"
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cpu-features.h>
#include "system.h"
#include <map>

#include "encrypt.h"

#define BUFF_SIZE 20000

struct enc_ctx *text_e_ctx, *text_d_ctx;

struct enc_connection {
    enc_ctx *text_e_ctx;
    enc_ctx *text_d_ctx;
};

std::map<long,enc_connection *> enc_ctx_map;

JNIEXPORT void JNICALL Java_me_smartproxy_crypto_CryptoUtils_releaseEncryptor(JNIEnv *env, jclass thiz, jlong id) {
    enc_connection *connection = enc_ctx_map[id];
    free(connection);
}

JNIEXPORT void JNICALL Java_me_smartproxy_crypto_CryptoUtils_initEncryptor(JNIEnv *env, jclass thiz, jstring jpassword, jstring jmethod, jlong id) {
    const char *password = env->GetStringUTFChars(jpassword, 0);
    const char *method = env->GetStringUTFChars(jmethod, 0);

    enc_connection *connection = enc_ctx_map[id];

    if(connection == NULL) {
        connection = (enc_connection *)malloc(sizeof(struct enc_connection));
        connection->text_e_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));
        connection->text_d_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));
        int enc_method = enc_init(password, method);
        enc_ctx_init(enc_method, connection->text_e_ctx, 1);
        enc_ctx_init(enc_method, connection->text_d_ctx, 0);
        enc_ctx_map[id] = connection;
    }
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
    char *encrypted = ss_encrypt(BUFF_SIZE, buffer, &size, temp_e_ctx);
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
    char *decrypted = ss_decrypt(BUFF_SIZE, buffer, &size, temp_d_ctx);
    if(decrypted == NULL) {
        return NULL;
    }
    return as_byte_array(env, decrypted, size);
}

JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_encrypt(JNIEnv *env, jclass thiz, jbyteArray array, jlong id) {
    ssize_t size = 0, iv_size = 0;
    char *buffer = as_char_array(env, array, &size);
//    uint8_t *iv = (uint8_t*) as_char_array(env, jIV, &iv_size);
//    LOGE("passed iv is %s",(char*) iv);
    enc_connection *connection = enc_ctx_map[(long)id];
    char *encrypted = ss_encrypt(BUFF_SIZE, buffer, &size, connection->text_e_ctx);
    return as_byte_array(env, encrypted, size);
}

JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_decrypt(JNIEnv *env, jclass thiz, jbyteArray array, jlong id) {
    ssize_t size = 0, iv_size = 0;
    char *buffer = as_char_array(env, array, &size);
//    uint8_t *iv = (uint8_t *) as_char_array(env, jIV, &iv_size);
    enc_connection *connection = enc_ctx_map[id];
    char *decrypted = ss_decrypt(BUFF_SIZE, buffer, &size, connection->text_d_ctx);
    return as_byte_array(env, decrypted, size);
}

jbyteArray as_byte_array(JNIEnv *env, char* buf, ssize_t len) {
    jbyteArray array = env->NewByteArray(len);
    env->ReleaseByteArrayElements(array, (jbyte *)buf, JNI_COMMIT);
//    env->SetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(buf));
    return array;
}

char* as_char_array(JNIEnv *env, jbyteArray array,ssize_t *len) {
    *len = env->GetArrayLength(array);
    char* buf = new char[*len];
//    env->GetByteArrayRegion(array, 0, *len, reinterpret_cast<jbyte*>(buf));
    buf = (char*) env->GetByteArrayElements(array, NULL);
    return buf;
}


JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_randBytes(JNIEnv *env, jclass thiz, int len) {
    uint8_t random_bytes[len];
    rand_bytes(random_bytes, len);
    return as_byte_array(env,(char *) random_bytes, len);
}
