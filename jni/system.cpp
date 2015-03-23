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

std::map<long long int,enc_connection *> enc_ctx_map;

JNIEXPORT void JNICALL Java_me_smartproxy_crypto_CryptoUtils_releaseEncryptor(JNIEnv *env, jclass thiz, jlong id) {
    enc_connection *connection = enc_ctx_map[id];
    enc_ctx_map.erase(id);
    if(connection != NULL) {
        if(connection->text_e_ctx != NULL) {
            cipher_context_release(&connection->text_e_ctx->evp);
            free(connection->text_e_ctx);
        }
        if(connection->text_d_ctx != NULL) {
            cipher_context_release(&connection->text_d_ctx->evp);
            free(connection->text_d_ctx);
        }
        free(connection);
//        LOGE("delete one connection id is %lld, %d connection remain", id, enc_ctx_map.size());
//    } else {
//        LOGE("what happened here id is %lld", id);
    }
}

JNIEXPORT void JNICALL Java_me_smartproxy_crypto_CryptoUtils_initEncryptor(JNIEnv *env, jclass thiz, jstring jpassword, jstring jmethod, jlong id) {
    enc_connection *connection = enc_ctx_map[id];

    if(connection == NULL) {
        const char *password = env->GetStringUTFChars(jpassword, 0);
        const char *method = env->GetStringUTFChars(jmethod, 0);
        connection = (enc_connection *)malloc(sizeof(struct enc_connection));
        connection->text_e_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));
        connection->text_d_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));
        int enc_method = enc_init(password, "rc4-md5");
        enc_ctx_init(enc_method, connection->text_e_ctx, 1);
        enc_ctx_init(enc_method, connection->text_d_ctx, 0);
        enc_ctx_map[id] = connection;
        env->ReleaseStringUTFChars(jpassword, password);
        env->ReleaseStringUTFChars(jmethod, method);
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

JNIEXPORT jint JNICALL Java_me_smartproxy_crypto_CryptoUtils_encrypt(JNIEnv *env, jclass thiz, jobject array, 
                                                                    jint jsize, jlong id) {

    ssize_t size = (ssize_t) jsize;
    jbyte *byteArray = (jbyte *) env->GetDirectBufferAddress(array);
    char *buffer = (char *) malloc(size * sizeof(char));

    memcpy(buffer, byteArray, size);
    enc_connection *connection = enc_ctx_map[id];
    buffer = ss_encrypt(BUFF_SIZE, buffer, &size, connection->text_e_ctx);
    memcpy(byteArray, buffer, size);

    free(buffer);
    return size;
}

JNIEXPORT jint JNICALL Java_me_smartproxy_crypto_CryptoUtils_decrypt(JNIEnv *env, jclass thiz, jobject array, 
                                                                    jint jsize, jlong id) {
    ssize_t size = (ssize_t) jsize;
    jbyte *byteArray = (jbyte *) env->GetDirectBufferAddress(array);
    char *buffer = (char *) malloc(size * sizeof(char));

    memcpy(buffer, byteArray, size);
    enc_connection *connection = enc_ctx_map[id];
    buffer = ss_decrypt(BUFF_SIZE, buffer, &size, connection->text_d_ctx);
    memcpy(byteArray, buffer, size);

    free(buffer);
    return size;
}

jbyteArray as_byte_array(JNIEnv *env, char* buf, ssize_t len) {
    jbyteArray array = env->NewByteArray(len);
    env->ReleaseByteArrayElements(array, (jbyte *)buf, JNI_ABORT);
    return array;
}

char* as_char_array(JNIEnv *env, jbyteArray array,ssize_t *len) {
    *len = env->GetArrayLength(array);
    char* buf = new char[*len];
    buf = (char*) env->GetByteArrayElements(array, NULL);
    return buf;
}


JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_randBytes(JNIEnv *env, jclass thiz, int len) {
    uint8_t random_bytes[len];
    rand_bytes(random_bytes, len);
    return as_byte_array(env,(char *) random_bytes, len);
}
