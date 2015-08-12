#include <sodium.h>
#include <string.h>
#include <stdio.h>

#include <termios.h>

#define PASSWORD_MAX_LEN 13
#define CHUNK_SIZE (1<<14)

#define KEY_LEN crypto_secretbox_KEYBYTES
#define NONCE_LEN crypto_secretbox_NONCEBYTES
#define SALT_LEN crypto_pwhash_scryptsalsa208sha256_SALTBYTES

#define PARAMS_LEN ((SALT_LEN + NONCE_LEN) * 2 + 1)
#define HEADER_LEN (sizeof(header) - 1)
#define SALT_H_LEN (SALT_LEN * 2)
#define NONCE_H_LEN (NONCE_LEN * 2)

typedef unsigned char uchar;
typedef unsigned int uint;
typedef enum {ENC, DEC, TEST} cmd_t;

char header[] = "Params_";
static char key_hex[KEY_LEN * 2 + 1];

/*  */
/* goal: encrypt/decrypt file
   take a password from the user
   NOT as a command line argument, but take input later */

/* using password from user:
  encrypt a file passed on the command line
  write the salt, nonce, and params in the header of the file
  first is a switch - enc/dec
  snd is filename
  get pass from user
  if enc - encrypt file, stream to stdout
  if dec - decrypt file, stream to sdout
*/
int
get_key(const unsigned char *salt,
            unsigned char *key,
            unsigned int key_len,
            const char *pw,
            unsigned int pw_len)
{
    /* store all parameters along with the password */
    return crypto_pwhash_scryptsalsa208sha256(key, key_len,
                                              pw, pw_len,
                                              salt,
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
}

/* read entire file into a buffer */
char *
read_file(FILE *fd, int *bytes)
{
    char *out;
    int cnt, rc, err;

    out = NULL;
    rc = -1;
    cnt = 0;
    /* out = malloc(CHUNK_SIZE); */
    /* if (!out) */
    /*     goto out; */

    while (!feof(fd)) {
        char *p;
        size_t br;

        p = realloc(out, cnt + CHUNK_SIZE);
        if (!p)
            goto out;
        out = p;
        br = fread(out + cnt, 1, CHUNK_SIZE, fd);
        if ((err = ferror(fd))) {
            fprintf(stderr, "error reading file: %s\n", strerror(err));
            goto out;
        }
        cnt += br;
    }

    rc = 0;
    *bytes = cnt;
 out:
    if (rc) {
        free(out);
        out = NULL;
    }
    return out;
}

/* int crypto_secretbox_easy(unsigned char *c, const unsigned char *m, */
/*                           unsigned long long mlen, const unsigned char *n, */
/*                           const unsigned char *k); */
/* int get_key(const unsigned char *salt, */
/*             unsigned char *key, */
/*             unsigned int key_len, */
/*             const char *pw, */
/*             unsigned int pw_len) */

int
encrypt_file(const char *pwd, uint pwd_len, const uchar *msg, uint msg_len, FILE *stream)
{
    /* first: turn password into key */
    /* randomly generate salt */
    uchar salt[SALT_LEN];
    uchar nonce[NONCE_LEN];
    uchar key[KEY_LEN], *cphr;
    int rc;
    int cphr_len;

    rc = -1;
    cphr_len = crypto_secretbox_MACBYTES + msg_len;
    cphr = NULL;

    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(salt, sizeof(salt));

    cphr = malloc(cphr_len * sizeof(*cphr));
    if (!cphr)
        goto out;

    if (get_key(salt, key, KEY_LEN, pwd, pwd_len)) {
        fprintf(stderr, "oom\n");
        goto out;
    }

    fprintf(stderr, "msg len is: %u\n", msg_len);
    crypto_secretbox_easy(cphr, msg, msg_len, nonce, key);
    fprintf(stderr, "encrypted the stuff\n");
    fprintf(stderr, "first char of cphr: %d\n", (int) *cphr);

    /* salt, then nonce */
    size_t br;
    br = fwrite(header, sizeof(*header), strlen(header), stream);
    fprintf(stderr, "wrote %lu bytes for header\n", br);
    br = fwrite(salt, sizeof(*salt), SALT_LEN, stream);
    fprintf(stderr, "wrote %lu bytes for salt\n", br);
    br = fwrite(nonce, sizeof(*nonce), NONCE_LEN, stream);
    fprintf(stderr, "wrote %lu bytes for nonce\n", br);
    br = fwrite(cphr, sizeof(*cphr), cphr_len, stream);
    fprintf(stderr, "wrote %lu bytes for cphr\n", br);

    rc = 0;
 out:
    free(cphr);
    /* free(dec); */
    return rc;
    
}


    /* err = sodium_hex2bin(back, sizeof(back), hex_r, sizeof(hex_r), NULL, &blen, NULL); */
/* reads chars from fin, converts to uchars */
int
read_params(FILE *fin, uchar *salt, uchar *nonce) {
    size_t br;

    br = fread(salt, sizeof(*salt), SALT_LEN, fin);
    if (br != SALT_LEN)
        fprintf(stderr, "oops\n");
    fprintf(stderr, "read %lu bytes for salt\n", br);
    br = fread(nonce, sizeof(*nonce), NONCE_LEN, fin);
    if (br != NONCE_LEN)
        fprintf(stderr, "nonce oops\n");
    fprintf(stderr, "read %lu bytes for nonce\n", br);

    return 0;
}

/* crypto_secretbox_open_easy(decrypted, ciphertext, c_len, nonce, key) */
char *
decrypt_file(const char *pwd, uint pwd_len, FILE *fin, uint *mlen)
{
    char headbuf[sizeof(header) - 1];
    char paramsbuf[PARAMS_LEN - 1];
    uchar salt[SALT_LEN], nonce[NONCE_LEN], key[KEY_LEN], *msg;
    uchar *cphr;
    int msg_len, cphr_len, err;

    cphr = NULL;
    msg = NULL;
    err = -1;
    /* read salt, nonce, and then gen key  */
    fread(headbuf, sizeof(*headbuf), sizeof(headbuf), fin);
    if (strncmp(headbuf, header, HEADER_LEN)) {
        fprintf(stderr, "header mismatch\n");
        goto out;
    }
    fprintf(stderr, "all seems good\n");
    read_params(fin, salt, nonce);
    if (get_key(salt, key, KEY_LEN, pwd, pwd_len)) {
        fprintf(stderr, "couldn't get key\n");
        goto out;
    }
    sodium_bin2hex(key_hex, sizeof(key_hex), key, KEY_LEN);
    fprintf(stderr, "key is: %s\n", key_hex);
    fprintf(stderr, "key length should be: %d\n", KEY_LEN * 2);

    cphr = (uchar *)read_file(fin, &cphr_len);
    if (!cphr) {
        fprintf(stderr, "couldn't read file\n");
        goto out;
    }
    fprintf(stderr, "cphr len is: %d\n", cphr_len);
    fprintf(stderr, "first char of cphr: %d\n", (int)*cphr);
    msg_len = cphr_len - crypto_secretbox_MACBYTES;
    if (msg_len < 0)
        goto out;
    char *cphr_hex;
    cphr_hex = malloc((cphr_len * 2 + 1) * sizeof(*cphr_hex));
    sodium_bin2hex(cphr_hex, cphr_len * 2 + 1, cphr, cphr_len);
    fprintf(stderr, "argggh cphr: %s\n", cphr_hex);

    msg = malloc(msg_len * sizeof(*msg));
    if (!msg)
        goto out;
    if (crypto_secretbox_open_easy(msg, cphr, cphr_len, nonce, key)) {
        fprintf(stderr, "oops - couldn't decrypt\n");
        goto out;
    }

/*      char * */
/* read_file(FILE *fd, int *bytes) */

    *mlen = (uint) msg_len;
    err = 0;
 out:
    free(cphr);
    if (err) {
        free(msg);
        msg = NULL;
    }
    
    return (char *)msg;
}
        /* err = decrypt(pwd, strlen(pwd), fd, stdout); */
int
decrypt(const char *pwd, uint pwd_len, FILE *fin, FILE *fout)
{
    char *res;
    int rc;
    uint mlen;

    rc = -1;
    res = decrypt_file(pwd, pwd_len, fin, &mlen);
    if (!res)
        goto out;

    fprintf(stderr, "all good\n");
    fwrite(res, sizeof(*res), mlen, fout);
    rc = 0;
 out:
    return rc;
}
    /* crypto_secretbox_easy(ciphertext, message, m_len, nonce, key); */
int
my_getpass(char *pwbuf, int buf_len, FILE *stream)
{
    struct termios old, new;
    int nread, rc, term_set;
    size_t br;
    char *p;

    rc = -1;
    term_set = 0;

    /* Turn echoing off and fail if we can't. */
    if (tcgetattr(fileno (stream), &old) != 0)
        goto out;
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(fileno (stream), TCSAFLUSH, &new) != 0)
        goto out;
    term_set = 1;
    
    /* Read the password. */
    if (!fgets(pwbuf, buf_len - 1, stream))
        goto out;

    br = strlen(pwbuf);
    if (pwbuf[br - 1] != '\n') {
        fprintf(stderr, "too many characters in password\n");
        goto out;
    }
    pwbuf[br - 1] = '\0';
    rc = 0;
 out:
    /* Restore terminal. */
    if (term_set)
        (void) tcsetattr(fileno (stream), TCSAFLUSH, &old);
    return rc;
}

int
encrypt(char *pwd, uint pwd_len, FILE *fin, FILE *fout)
{
    int rc, flen;
    char *fbuf;


    rc = -1;
    fbuf = read_file(fin, &flen);
    if (!fbuf)
        goto out;

    fprintf(stderr, "going to encrypt file\n");
    if (encrypt_file(pwd, pwd_len, (unsigned char*) fbuf, flen, fout))
        goto out;
    fprintf(stderr, "all good\n");
    rc = 0;
 out:
    free(fbuf);
    return rc;
}

/* int */
/* test(char *pwd, uint pwd_len, FILE *msg) */
/* { */
/*     FILE *sfcphr, *sfdec; */
/*     char *bufcphr, *bufdec; */
/*     size_t cphr_sz, dec_sz; */
/* /\* int *\/ */
/* /\* decrypt(const char *pwd, uint pwd_len, FILE *fin, FILE *fout) *\/ */

/*     bufcphr = bufdec = NULL; */
/*     cphr_sz = dec_sz = 0; */
/*     sfcphr = open_memstream(&bufcphr, &cphr_sz); */
/*     encrypt(pwd, pwd_len, fin, sfcphr); */
/*     fclose(sfcphr); */
/*     sfcphr = fmemopen(bufcphr, cphr_sz, "r"); */
/*     sfdec = open_memstream(&bufdec, &dec_sz); */
/*     decrypt(pwd, pwd_len, sfcphr, sfdec); */
/* } */

int main(int argc, char **argv)
{
    char pwd[PASSWORD_MAX_LEN], *sp, *fname, *fbuf, *cmds;
    int err, flen, rc;
    FILE *fd;
    cmd_t cmd;

    fd = NULL;
    fbuf = NULL;
    rc = -1;

    if (argc != 3) {
        printf("usage: <me> <enc|dec> FILE\n");
        exit(-1);
    }
    cmds = argv[1];
    if (!strncmp(cmds, "enc", 3))
        cmd = ENC;
    else if (!strncmp(cmds, "dec", 3))
        cmd = DEC;
    else if (!strncmp(cmds, "test", 4))
        cmd = TEST;
    else {
        fprintf(stderr, "invalid command\n");
        goto out;
    }

    fprintf(stderr, "password:");
    if (my_getpass(pwd, PASSWORD_MAX_LEN, stdin)) {
        goto out;
    }
    fname = argv[2];
    switch (cmd) {
    case ENC:
        fprintf(stderr, "encrypting...\n");
        fd = fopen(fname, "r");
        if (!fd) {
            perror("couldn't open file");
            exit(-1);
        }
        /* encrypt(char *pwd, uint pwd_len, stream *fin, stream *fout) */
        err = encrypt(pwd, strlen(pwd), fd, stdout);
        break;
    case DEC:
        fprintf(stderr, "decrypting...\n");
        fd = fopen(fname, "r");
        if (!fd) {
            perror("couldn't open file");
            exit(-1);
        }
        err = decrypt(pwd, strlen(pwd), fd, stdout);
        /* fprintf(stderr, "not implemented\n"); */
        break;
    /* case TEST: */
    /*     fprintf(stderr, "testing..\n"); */
    /*     fd = fopen(fname, "r"); */
    /*     if (!fd) { */
    /*         perror("couldn't open file"); */
    /*         exit(-1); */
    /*     } */
    /*     err = test(pwd, strlen(pwd), fd); */
    default:
        fprintf(stderr, "how did I get here?\n");
        break;
    }

/* int */
/* my_getpass(char *pwbuf, int buf_len, FILE *stream) */


    /* printf("got password: %sEND\n", pwd); */

/* encrypt_file(const char *pwd, uint pwd_len, const uchar *msg, uint msg_len, FILE *stream)     */
    /* now I need to encrypt the file - BUT - need password length */

    rc = 0;
 out:
    fclose(fd);
    free(fbuf);
    return rc;
    /* printf("password:\n"); */
    /* if (my_getpass(pwd, PASSWORD_MAX_LEN, stdin)) { */
    /*     printf("failed\n"); */
    /*     exit(-1); */
    /* } */
    /* printf("i read: %s\n", pwd); */
}
