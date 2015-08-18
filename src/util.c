#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>

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
void
gen_pass(char *out, size_t len, bool syms)
{
    int i;

    /* ignore syms for now */
    randombytes_buf(out, len);
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
}

int
get_pass(char *prompt, char *pwbuf, int buf_len, FILE *stream)
{
    struct termios old, new;
    int rc, term_set;
    size_t br;

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
