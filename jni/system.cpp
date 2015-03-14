#include "jni.h"
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cpu-features.h>
#include "system.h"

#include "encrypt.h"

JNIEXPORT jstring JNICALL Java_me_smartproxy_crypto_CryptoUtils_getABI(JNIEnv *env, jclass thiz) {
    AndroidCpuFamily family = android_getCpuFamily();
    uint64_t features = android_getCpuFeatures();
    const char *abi;

    if (family == ANDROID_CPU_FAMILY_X86) {
        abi = "x86";
    } else if (family == ANDROID_CPU_FAMILY_MIPS) {
        abi = "mips";
    } else if (family == ANDROID_CPU_FAMILY_ARM) {
        // if (features & ANDROID_CPU_ARM_FEATURE_ARMv7) {
        abi = "armeabi-v7a";
        // } else {
        //   abi = "armeabi";
        // }
    }
    return env->NewStringUTF(abi);
}

JNIEXPORT void JNICALL Java_me_smartproxy_crypto_CryptoUtils_exec(JNIEnv *env, jclass thiz, jstring cmd) {
    const char *str  = env->GetStringUTFChars(cmd, 0);
    system(str);
    env->ReleaseStringUTFChars(cmd, str);
}

JNIEXPORT jstring JNICALL  Java_me_smartproxy_crypto_CryptoUtils_testEncrypt(JNIEnv *env, jclass thiz) {
    struct enc_ctx *text_e_ctx, *text_d_ctx;
    text_e_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));
    text_d_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));

    int method = enc_init("SHarry33", "aes-256-cfb");

    enc_ctx_init(method, text_e_ctx, 1);
    enc_ctx_init(method, text_d_ctx, 0);

    char *test_text = new char[1024];
    char data1[] = {82,
                   212,
                   95,
                   62,
                   13,
                   118,
                   174,
                   177,
                   170,
                   156,
                   231,
                   62,
                   206,
                   166,
                   255,
                   76,
                   255,
                   225,
                   198,
                   50,
                   83,
                   67,
                   201,
                   199,
                   124,
                   112,
                   135,
                   127};

//     char *data = "Not so happy now.";
//     LOGE("data size %d", strlen(data));
// //    memcpy(test_text, data, strlen(data));

     ssize_t size = 2048;
//     data = ss_encrypt(2048, data, &size, text_e_ctx);
    char *data = data1;
    size = strlen(data);
    LOGE("encrypted data size is %d", size);
    char *result = ss_decrypt(1024,data, &size, text_d_ctx);
    LOGE("result is %s",result);

    return env->NewStringUTF(result);

}

struct enc_ctx *text_e_ctx, *text_d_ctx;

#define BUFF_SIZE 20000

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

    char *buffer = as_char_array(env, array);
    ssize_t size = strlen(buffer);
    char *encrypted = ss_encrypt(BUFF_SIZE, buffer, &size, temp_e_ctx);
    return as_byte_array(env, encrypted, strlen(encrypted));
}

JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_decryptAll(JNIEnv *env, jclass thiz, jbyteArray array, jstring jpassword, jstring jmethod) {
    const char *password = env->GetStringUTFChars(jpassword, 0);
    const char *method = env->GetStringUTFChars(jmethod, 0);

    struct enc_ctx *temp_d_ctx;
    temp_d_ctx = (enc_ctx *)malloc(sizeof(struct enc_ctx));
    int enc_method = enc_init(password, method);
    enc_ctx_init(enc_method, temp_d_ctx, 1);


    char *buffer = as_char_array(env, array);
    ssize_t size = strlen(buffer);
    char *decrypted = ss_decrypt(BUFF_SIZE, buffer, &size, temp_d_ctx);
    return as_byte_array(env, decrypted, strlen(decrypted));
}


JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_encrypt(JNIEnv *env, jclass thiz, jbyteArray array) {
    char *buffer = as_char_array(env, array);
    ssize_t size = strlen(buffer);
    char *encrypted = ss_encrypt(BUFF_SIZE, buffer, &size, text_e_ctx);
    return as_byte_array(env, encrypted, strlen(encrypted));
}

JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_decrypt(JNIEnv *env, jclass thiz, jbyteArray array) {
    char *buffer = as_char_array(env, array);
    ssize_t size = strlen(buffer);
    char *decrypted = ss_decrypt(BUFF_SIZE, buffer, &size, text_d_ctx);
    return as_byte_array(env, decrypted, strlen(decrypted));
}

jbyteArray as_byte_array(JNIEnv *env, char* buf, int len) {
    jbyteArray array = env->NewByteArray(len);
    env->SetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(buf));
    return array;
}

char* as_char_array(JNIEnv *env, jbyteArray array) {
    int len = env->GetArrayLength(array);
    char* buf = new char[len];
    env->GetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(buf));
    return buf;
}


// void Java_me_smartproxy_crypto_CryptoUtils_EVP_BytesToKey(JNIEnv *env, ) {

// }

// static const char *classPathName = "me/smartproxy/crypto/CryptoUtils";

// static JNINativeMethod method_table[] = {
//     { "exec", "(Ljava/lang/String;)V",
//       (void*) Java_me_smartproxy_crypto_CryptoUtils_exec },
//     { "getABI", "()Ljava/lang/String;",
//       (void*) Java_me_smartproxy_crypto_CryptoUtils_getabi },
//     { "testEncrypt", "()Ljava/lang/String;",
//       (void*) Java_me_smartproxy_crypto_CryptoUtils_testEncrypt }
// };



/*
 * Register several native methods for one class.
 */
// static int registerNativeMethods(JNIEnv* env, const char* className,
//     JNINativeMethod* gMethods, int numMethods)
// {
//     jclass clazz;

//     clazz = env->FindClass(className);
//     if (clazz == NULL) {
//         LOGE("Native registration unable to find class '%s'", className);
//         return JNI_FALSE;
//     }
//     if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
//         LOGE("RegisterNatives failed for '%s'", className);
//         return JNI_FALSE;
//     }

//     return JNI_TRUE;
// }

/*
 * Register native methods for all classes we know about.
 *
 * returns JNI_TRUE on success.
 */
// static int registerNatives(JNIEnv* env)
// {
//   if (!registerNativeMethods(env, classPathName, method_table,
//                  sizeof(method_table) / sizeof(method_table[0]))) {
//     return JNI_FALSE;
//   }

//   return JNI_TRUE;
// }

/*
 * This is called by the VM when the shared library is first loaded.
 */

// typedef union {
//     JNIEnv* env;
//     void* venv;
// } UnionJNIEnvToVoid;

// jint JNI_OnLoad(JavaVM* vm, void* reserved) {
//     UnionJNIEnvToVoid uenv;
//     uenv.venv = NULL;
//     jint result = -1;
//     JNIEnv* env = NULL;

//     LOGI("JNI_OnLoad");

//     if (vm->GetEnv(&uenv.venv, JNI_VERSION_1_4) != JNI_OK) {
//         LOGE("ERROR: GetEnv failed");
//         goto bail;
//     }
//     env = uenv.env;

//     if (registerNatives(env) != JNI_TRUE) {
//         LOGE("ERROR: registerNatives failed");
//         goto bail;
//     }

//     result = JNI_VERSION_1_4;

// bail:
//     return result;
//}
