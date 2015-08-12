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
#define OPSLIMIT crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
#define MEMLIMIT crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

typedef unsigned char uchar;
typedef unsigned int uint;
typedef enum {ENC, DEC} cmd_t;

char header[] = "Params_";
static char key_hex[KEY_LEN * 2 + 1];

int
get_key(const unsigned char *salt,
            unsigned char *key,
            unsigned int key_len,
            const char *pw,
            unsigned int pw_len)
{
    return crypto_pwhash_scryptsalsa208sha256(key, key_len,
                                              pw, pw_len,
                                              salt,
                                              OPSLIMIT,
                                              MEMLIMIT);
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

int
encrypt_file(const char *pwd, uint pwd_len, const uchar *msg, uint msg_len, FILE *stream)
{
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

    crypto_secretbox_easy(cphr, msg, msg_len, nonce, key);

    /* salt, then nonce */
    /* XXX should i check we really wrote the right number of bytes? */
    size_t br;
    br = fwrite(header, sizeof(*header), strlen(header), stream);
    br = fwrite(salt, sizeof(*salt), SALT_LEN, stream);
    br = fwrite(nonce, sizeof(*nonce), NONCE_LEN, stream);
    br = fwrite(cphr, sizeof(*cphr), cphr_len, stream);

    rc = 0;
 out:
    free(cphr);
    return rc;
    
}

int
read_params(FILE *fin, uchar *salt, uchar *nonce) {
    size_t br;

    br = fread(salt, sizeof(*salt), SALT_LEN, fin);
    if (br != SALT_LEN)
        fprintf(stderr, "oops\n");
    br = fread(nonce, sizeof(*nonce), NONCE_LEN, fin);
    if (br != NONCE_LEN)
        fprintf(stderr, "nonce oops\n");

    return 0;
}

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

    fread(headbuf, sizeof(*headbuf), sizeof(headbuf), fin);
    if (strncmp(headbuf, header, HEADER_LEN)) {
        fprintf(stderr, "header mismatch\n");
        goto out;
    }

    read_params(fin, salt, nonce);
    if (get_key(salt, key, KEY_LEN, pwd, pwd_len)) {
        fprintf(stderr, "couldn't get key\n");
        goto out;
    }

    cphr = (uchar *)read_file(fin, &cphr_len);
    if (!cphr) {
        fprintf(stderr, "couldn't read file\n");
        goto out;
    }
    msg_len = cphr_len - crypto_secretbox_MACBYTES;
    if (msg_len < 0)
        goto out;

    msg = malloc(msg_len * sizeof(*msg));
    if (!msg)
        goto out;
    if (crypto_secretbox_open_easy(msg, cphr, cphr_len, nonce, key)) {
        fprintf(stderr, "oops - couldn't decrypt\n");
        goto out;
    }

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

    fwrite(res, sizeof(*res), mlen, fout);
    rc = 0;
 out:
    return rc;
}

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

    if (encrypt_file(pwd, pwd_len, (unsigned char*) fbuf, flen, fout))
        goto out;
    rc = 0;
 out:
    free(fbuf);
    return rc;
}

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
    else {
        fprintf(stderr, "invalid command\n");
        goto out;
    }

    fprintf(stderr, "password:");
    err = my_getpass(pwd, PASSWORD_MAX_LEN, stdin);
    fprintf(stderr, "\n");
    if (err)
        goto out;
    fname = argv[2];
    switch (cmd) {
    case ENC:
        fd = fopen(fname, "r");
        if (!fd) {
            perror("couldn't open file");
            exit(-1);
        }
        rc = encrypt(pwd, strlen(pwd), fd, stdout);
        if (rc)
            fprintf(stderr, "encryption failed\n");
        break;
    case DEC:
        fd = fopen(fname, "r");
        if (!fd) {
            perror("couldn't open file");
            exit(-1);
        }
        rc = decrypt(pwd, strlen(pwd), fd, stdout);
        if (rc)
            fprintf(stderr, "decryption failed\n");
        break;
    default:
        fprintf(stderr, "how did I get here?\n");
        break;
    }

 out:
    fclose(fd);
    free(fbuf);
    return rc;
}
