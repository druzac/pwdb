#ifndef _PWDB_FENCRYPT_
#define _PWDB_FENCRYPT_

typedef unsigned char uchar;
typedef unsigned int uint;

char *
decrypt_file(const char *pwd, uint pwd_len, FILE *fin, uint *mlen);

int
encrypt_file(const char *pwd, uint pwd_len, const uchar *msg, uint msg_len, FILE *stream);

#endif
