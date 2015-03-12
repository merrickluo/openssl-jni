#include "encrypt.h"


int main(int argc, char **argv) {

    struct enc_ctx *text_e_ctx = malloc(sizeof(struct enc_ctx));
    struct enc_ctx *text_d_ctx = malloc(sizeof(struct enc_ctx));

    int method = enc_init("SHarry33", "aes-256-cfb");

    enc_ctx_init(method, text_e_ctx, 1);
    enc_ctx_init(method, text_d_ctx, 0);
    ssize_t size = 2048;
    char *encryptBuffer = ss_encrypt(2048,"Hello World!", &size, text_e_ctx);
    printf("%s\n",encryptBuffer);

    printf("%s\n",ss_decrypt(2048,encryptBuffer , &size, text_d_ctx));

}
