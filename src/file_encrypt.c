#include <sodium.h>
#include <string.h>
#include <stdio.h>

#include <termios.h>

#define PASSWORD_MAX_LEN 13
#define CHUNK_SIZE (1<<14)

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
int get_key(const unsigned char *salt,
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

        printf("reallcing...\n");
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

/* int */
/* encrypt_file(const char *pwd,  */

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
    rc = 0;
 out:
    /* Restore terminal. */
    if (term_set)
        (void) tcsetattr(fileno (stream), TCSAFLUSH, &old);
    return rc;
}

int main(int argc, char **argv)
{
    char pwd[PASSWORD_MAX_LEN], *sp, *fname, *fbuf;
    int err, flen, rc;
    FILE *fd;

    fd = NULL;
    fbuf = NULL;
    rc = -1;

    if (argc != 2) {
        printf("usage: <me> FILE\n");
        exit(-1);
    }
    fname = argv[1];
    fd = fopen(fname, "r");
    if (!fd) {
        perror("couldn't open file: ");
        exit(-1);
    }

    fbuf = read_file(fd, &flen);
    if (!fbuf)
        goto out;

    printf("I read:\n%.*s", flen, fbuf);
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
