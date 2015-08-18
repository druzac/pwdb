#ifndef _PWDB_UTIL_
#define _PWDB_UTIL_

void
gen_pass(char *out, size_t len, bool syms);

int
get_pass(char *prompt, char *pwbuf, int buf_len, FILE *stream);

#endif
