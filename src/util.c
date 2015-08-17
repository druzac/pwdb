#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>

#define NUM_CHARS (26*2 + 10)
#define UPPER_START 65
#define LOWER_START 97
#define DIGIT_START 48

/* void randombytes_buf(void * const buf, const size_t size); */

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


/* int main() */
/* { */
/*     char test_pass[13]; */
/*     int i, num_its; */

/*     num_its = 1; */
/*     sodium_init(); */
/*     for (i = 0; i < 1; i++) { */
/*         gen_pass(test_pass, 12, false); */
/*         printf("%s\n", test_pass); */
/*     } */
/*     printf("hey there\n"); */
/* } */
