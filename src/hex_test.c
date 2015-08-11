#include <sodium.h>
#include <string.h>
#include <stdio.h>

typedef unsigned char uchar;

#define R_LEN 32
#define H_LEN (R_LEN) * 2 + 1

int
main()
{
    uchar r[R_LEN], back[R_LEN];
    char hex_r[H_LEN];
    char *hex_end;
    size_t blen;
    int err;
    printf("length of crazy things: %d, %d\n", crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
           crypto_secretbox_NONCEBYTES);

    printf("mac bytes: %d\n", crypto_secretbox_MACBYTES);
    /* randombytes_buf(r, sizeof(r)); */
    /* sodium_bin2hex(hex_r, sizeof(hex_r), r, R_LEN); */
    /* printf("I got: %s\n", hex_r); */
    /* printf("last character in string is null: %d\n", hex_r[H_LEN-1] == '\0'); */
    /* err = sodium_hex2bin(back, sizeof(back), hex_r, sizeof(hex_r), NULL, &blen, NULL); */
    /* if (err) */
    /*     printf("error!\n"); */
    /* printf("%lu\n", blen); */
    /* printf("result: %d\n", memcmp(r, back, R_LEN)); */
}

/* 85f772678573b38c691477c9b1d94bc2c1db81d787a454164cc94fe7a6d4d6efb352f3f9191cbd2e305b1ef04f443a973342041d4b234648 */
/* 0000010: 3537 3362 3338 6336 3931 3437 3763 3962  573b38c691477c9b */
/* 0000020: 3164 3934 6263 3263 3164 6238 3164 3738  1d94bc2c1db81d78 */
/* 0000030: 3761 3435 3431 3634 6363 3934 6665 3761  7a454164cc94fe7a */
/* 0000040: 3664 3464 3665 6662 3335 3266 3366 3931  6d4d6efb352f3f91 */
/* 0000050: 3931 6362 6432 6533 3035 6231 6566 3034  91cbd2e305b1ef04 */
/* 0000060: 6634 3433 6139 3733 3334 3230 3431 6434  f443a973342041d4 */
/* 0000070: 6232 3334 3634 38a5 793a 18ac 9555 c814  b234648 */
