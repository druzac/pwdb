#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <errno.h>

#include "util.h"

#define NUM_CHARS (26*2 + 10)
#define UPPER_START 65
#define LOWER_START 97
#define DIGIT_START 48

/* len is password len
   it's callers responsibility to make sure
   there's 1 extra byte for the null
   */

/* ascii
   A-Z 65-90
   a-z 97-122
   0-9 48-57
   */
int
gen_pass(char *out, size_t len, bool syms)
{
    int i, rc;
    struct rand_state rs;

    rc = -1;
    memset(&rs, 0, sizeof(rs));

    if (rand_init(&rs))
        goto out;

    /* ignore syms for now */
    if (rand_get_bytes(&rs, (unsigned char *) out, len))
        goto out;

    for (i = 0; i < len; i++) {
        unsigned char c;

        c = (unsigned char) out[i] % NUM_CHARS;
        if (c < 26)
            out[i] = c + UPPER_START;
        else if (c < 52)
            out[i] = (c % 26) + LOWER_START;
        else
            out[i] = (c % 10) + DIGIT_START;
    }
    out[len] = '\0';

    rc = 0;
 out:
    rand_destroy(&rs);
    return rc;
}

int
get_pass(char *prompt, char *pwbuf, int buf_len, FILE *stream)
{
    struct termios old, new;
    int rc, term_set, err;
    size_t br;

    rc = -1;
    term_set = 0;
    err = 0;

    /* Turn echoing off and fail if we can't. */
    if (tcgetattr(fileno (stream), &old) != 0) {
        err = errno;
        if (err != ENOTTY)
            goto out;
    }
    if (err == 0) {
        new = old;
        new.c_lflag &= ~ECHO;
        if (tcsetattr(fileno (stream), TCSAFLUSH, &new) != 0)
            goto out;
        term_set = 1;
    }
    
    /* Read the password. */
    printf("%s", prompt);
    if (!fgets(pwbuf, buf_len - 1, stream)) {
        printf("\n");
        goto out;
    }
    printf("\n");
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
rand_init(struct rand_state *rs)
{
    FILE *f;
    int rc;

    rc = -1;
    if (!(f = fopen("/dev/urandom", "r"))) {
        perror("init_random");
        goto out;
    }

    rc = 0;
    rs->rdev = f;
 out:
    return rc;
}

int
rand_get_bytes(struct rand_state *rs, unsigned char *buf, int buflen)
{
    int rc;

    rc = -1;
    if ((fread(buf, 1, buflen, rs->rdev)) < buflen) {
        perror("get_random_bytes");
        goto out;
    }
    rc = 0;
 out:
    return rc;
}

int
rand_destroy(struct rand_state *rs)
{
    int rc;

    rc = -1;
    if (rs && rs->rdev && fclose(rs->rdev)) {
        perror("couldn't deinitialize random");
        goto out;
    }

    rc = 0;
 out:
    return rc;
}
