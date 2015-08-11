#include <sodium.h>
#include <string.h>

/* example of symmetric encryption, and generating a key */

#define PASSWORD "Correct Horse Battery Staple"
#define KEY_LEN crypto_box_SEEDBYTES

/* store both salt and nonce with message */
/* use salt to gen key from password */
int get_key(const unsigned char *salt,
            unsigned char *key,
            unsigned int key_len,
            const char *pw,
            unsigned int pw_len)
{

    /* unsigned char salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES]; */
    /* unsigned char key[KEY_LEN]; */

    /* randombytes_buf(salt, sizeof salt); */
    return crypto_pwhash_scryptsalsa208sha256(key, key_len,
                                              pw, pw_len,
                                              salt,
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    /* if (crypto_pwhash_scryptsalsa208sha256 */
    /*     (key, sizeof key, PASSWORD, strlen(PASSWORD), salt, */
    /*      crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, */
    /*      crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) { */
    /*     /\* out of memory *\/ */
    /* } */
}
/* #define PASSWORD "my silly password" */
/* use nonce to encrypt/decrypt message with key */
int main(void)
{
    printf("salt length: %d\n", crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    printf("this is my test\n");
    if (sodium_init() == -1) {
        return 1;
    }
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char *ciphertext;
    unsigned int m_len, c_len;
    unsigned char *message;
    unsigned char salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];

    randombytes_buf(salt, sizeof salt);
    printf("key len is: %d, computed: %lu\n", crypto_secretbox_KEYBYTES, sizeof(key));
    if (get_key(salt, key, sizeof(key), PASSWORD, strlen(PASSWORD))) {
        printf("get_key failed\n");
        exit(-1);
    }

    message = (unsigned char *) "quick brown fox jumps over the short white fence";
    /* message = malloc((1<<20) * sizeof(*message)); */
    /* if (!message) { */
    /*     printf("cannot malloc message\n"); */
    /*     exit(-1); */
    /* } */
    /* int i; */
    /* for (i = 0; i < (1<<20) - 1; i++) { */
    /*     message[i] = 'a'; */
    /* } */
    /* message[i] = '\0'; */

    m_len = strlen((char *)message);
    printf("strlen is: %d\n", m_len);
    c_len = crypto_secretbox_MACBYTES + m_len;

    ciphertext = malloc(c_len * sizeof(*ciphertext));
    if (!ciphertext) {
        printf("cannot malloc ciphertext buffer\n");
        exit(-1);
    }

    randombytes_buf(nonce, sizeof nonce);
    /* randombytes_buf(key, sizeof key); */
    crypto_secretbox_easy(ciphertext, message, m_len, nonce, key);

    unsigned char *decrypted;
    decrypted = malloc(m_len * sizeof(*decrypted));
    if (!decrypted)
        exit(-1);
    
    if (crypto_secretbox_open_easy(decrypted, ciphertext, c_len, nonce, key) != 0) {
        printf("what the beef\n");
        /* message forged! */
    }
    /* printf("ciphertext: %s\n", ciphertext); */
    printf("decrypted: %s\n", decrypted);
    printf("all good?\n");

    free(decrypted);
    free(ciphertext);
    /* free(message); */
    return 0;
}
