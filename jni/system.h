#define LOG_TAG "SmartProxy"

#include <android/log.h>
#include <jni.h>

#define LOGI(...) do { __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); } while(0)
#define LOGW(...) do { __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__); } while(0)
#define LOGE(...) do { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); } while(0)

#ifndef _Included_me_smartproxy_crypto_CryptoUtils
#define _Included_me_smartproxy_crypto_CryptoUtils

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     me_smartproxy_crypto_CryptoUtils
 * Method:    exec
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_me_smartproxy_crypto_CryptoUtils_exec
  (JNIEnv *, jclass, jstring);

/*
 * Class:     me_smartproxy_crypto_CryptoUtils
 * Method:    getABI
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_me_smartproxy_crypto_CryptoUtils_getABI
  (JNIEnv *, jclass);

/*
 * Class:     me_smartproxy_crypto_CryptoUtils
 * Method:    testEncrypt
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_me_smartproxy_crypto_CryptoUtils_testEncrypt
  (JNIEnv *, jclass);

/*
 * Class:     me_smartproxy_crypto_CryptoUtils
 * Method:    initEncryptor
 * Signature: (Ljava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_me_smartproxy_crypto_CryptoUtils_initEncryptor
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     me_smartproxy_crypto_CryptoUtils
 * Method:    encrypt
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_encrypt
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     me_smartproxy_crypto_CryptoUtils
 * Method:    decrypt
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_me_smartproxy_crypto_CryptoUtils_decrypt
  (JNIEnv *, jclass, jbyteArray);

jbyteArray as_byte_array(JNIEnv *, char *, int);

char* as_char_array(JNIEnv *, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif


//#define LOGI(...) do {} while(0)
//#define LOGW(...) do {} while(0)
//#define LOGE(...) do {} while(0)
