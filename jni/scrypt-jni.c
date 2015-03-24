
#include <errno.h>
#include <string.h>
#include <jni.h>
#include <android/log.h>

#include "libscrypt.h"

#define  LOG_TAG    "libscrypt_crypho"
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#define  LOGV(...)  __android_log_print(ANDROID_LOG_VERBOSE,LOG_TAG,__VA_ARGS__)

//#define DEBUG_ON

static jclass 
getIntegerClass(JNIEnv* env) {
    jclass cls = (*env)->FindClass(env, "java/lang/Integer");
    if((*env)->ExceptionOccurred(env)) {
      return NULL;
    }
    return cls;
}

static jmethodID 
getIntValueMethod(JNIEnv* env, jclass cls) {
    jmethodID methodID = (*env)->GetMethodID(env, cls, "intValue", "()I");
    if((*env)->ExceptionOccurred(env)) {
      return NULL;
    }
    return methodID;
}

static jint
callIntMethod(JNIEnv* env, jmethodID method, jobject integerObject, jint defaultValue) {
	if (integerObject == NULL) {
		return defaultValue;
	}
    jint result = (*env)->CallIntMethod(env, integerObject, method); 
    if((*env)->ExceptionOccurred(env)) {
      return defaultValue;
    }
    return result;
}

jbyteArray
Java_com_crypho_plugins_ScryptPlugin_scrypt( JNIEnv* env, jobject thiz, 
	jbyteArray pass, jcharArray salt, jobject N, jobject r, jobject p, jobject dkLen)
{
    int i;
    char *msg_error;

    jclass integer = getIntegerClass(env);
    if (integer == NULL) {
        LOGE("Failed to load java.lang.Integer class");
        return;      
    }

    jmethodID intValueMethod = getIntValueMethod(env, integer);
    if (intValueMethod == NULL) {
        LOGE("Failed to load method intValue from java.lang.Integer class");
        return;      
    }

    jint N_i = callIntMethod(env, intValueMethod, N, SCRYPT_N);
    jint r_i = callIntMethod(env, intValueMethod, r, SCRYPT_r);
    jint p_i = callIntMethod(env, intValueMethod, p, SCRYPT_p);
    jint dkLen_i = callIntMethod(env, intValueMethod, dkLen, 32);

    jint passLen = (*env)->GetArrayLength(env, pass);
    if((*env)->ExceptionOccurred(env)) {
        LOGE("Failed to get passphrase lenght.");
        return;
    }

    jint saltLen = (*env)->GetArrayLength(env, salt);
    if((*env)->ExceptionOccurred(env)) {
        LOGE("Failed to get salt lenght.");
        return;
    }

	jbyte *passphrase = (*env)->GetByteArrayElements(env, pass, NULL);
    if((*env)->ExceptionOccurred(env)) {
        LOGE("Failed to get passphrase elements.");
        return;
    }

    jchar *salt_chars = (*env)->GetCharArrayElements(env, salt, NULL);
    if((*env)->ExceptionOccurred(env)) {
        LOGE("Failed to get salt elements.");
        return;
    }

    uint8_t *parsedSalt = malloc(sizeof(uint8_t) * saltLen);
    if (parsedSalt == NULL) {
        msg_error = "Failed to malloc parsedSalt.";
        goto END;      
    }

    uint8_t *hashbuf = malloc(sizeof(uint8_t) * dkLen_i);
    if (hashbuf == NULL) {
        msg_error = "Failed to malloc parsedSalt.";
        goto END;      
    }

    for (i = 0; i < saltLen; ++i) {
        parsedSalt[i] = (uint8_t) salt_chars[i];
    }

	#ifdef DEBUG_ON
    	LOGV("Using N=%d r=%d p=%d dkLen=%d", N_i, r_i, p_i, dkLen_i);
    #endif

	if (libscrypt_scrypt(passphrase, passLen, parsedSalt, saltLen, N_i, r_i, p_i, hashbuf, dkLen_i)) {
        jclass e = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        char *msg;
        switch (errno) {
            case EINVAL:
                msg = "N must be a power of 2 greater than 1";
                break;
            case EFBIG:
            case ENOMEM:
                msg = "Insufficient memory available";
                break;
            default:
                msg = "Memory allocation failed";
        }
        (*env)->ThrowNew(env, e, msg);
        goto END;
    }
	jbyteArray result = (*env)->NewByteArray(env, dkLen_i);
    if((*env)->ExceptionOccurred(env)) {
        //TODO Log;
        goto END;      
    }

    (*env)->SetByteArrayRegion(env, result, 0, dkLen_i, (jbyte *) hashbuf);
    if((*env)->ExceptionOccurred(env)) {
        //TODO Log;
        goto END;      
    }

    END:
    	if (passphrase) (*env)->ReleaseByteArrayElements(env, pass, passphrase, JNI_ABORT);
        if((*env)->ExceptionOccurred(env)) {
            //TODO Log;
        }
        if (salt_chars) (*env)->ReleaseCharArrayElements(env, salt, salt_chars, JNI_ABORT);
        if((*env)->ExceptionOccurred(env)) {
            //TODO Log;
        }
    	if (hashbuf) free(hashbuf);
        if (parsedSalt) free(parsedSalt);

    return result;
}
