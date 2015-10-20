#ifndef _PWDB_UTIL_
#define _PWDB_UTIL_

struct rand_state {
    FILE *rdev;
};

int
gen_pass(char *out, size_t len, bool syms);

int
get_pass(char *prompt, char *pwbuf, int buf_len, FILE *stream);

int
rand_init(struct rand_state *rs);

int
rand_destroy(struct rand_state *rs);

int
rand_get_bytes(struct rand_state *rs, unsigned char *buf, int buflen);

#define ARRSIZE(arr) (sizeof(arr) / sizeof(*arr))

#endif
