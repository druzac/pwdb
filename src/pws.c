#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


#include <tomcrypt.h>

#define PWS_TAG "PWS3"
#define PWS_TAG_LEN 4

#define SALT_LEN 32
#define KEY_LEN 32
#define BLOCK_LEN 16

#define TYPE_VERSION 0x00
#define TYPE_UUID    0x01

#define VERSION 0x0310

struct db_header {
    short version;
    struct field *fields;
};

struct UUID {
};

struct record {
    struct UUID uuid;
    char *title;
    char *password;
    struct field *fields;
    struct record *next;
    struct record *prev;
};

struct field {
    unsigned int len;
    unsigned char type;
    unsigned char *data;
    struct field *next;
    struct field *prev;
};

struct db {
    struct db_header header;
    struct record *records;
};

unsigned int
read_le_uint32(unsigned char *buf)
{
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
}

unsigned int
read_le_uint16(unsigned char *buf)
{
    return buf[0] | buf[1] << 8;
}

/* pw is a C-string - null terminated  */
int
keystretch(const char *pw,
           const unsigned char *salt,
           unsigned int iter,
           unsigned char *out)
{
    hash_state md;
    unsigned char buf[32];
    int rc, i;

    rc = -1;
    sha256_init(&md);
    sha256_process(&md, (unsigned char *)pw, strlen(pw));
    sha256_process(&md, salt, SALT_LEN);
    sha256_done(&md, buf);

    for (i = 0; i < iter; i++) {
        sha256_init(&md);
        sha256_process(&md, buf, 32);
        sha256_done(&md, buf);
    }

    memcpy(out, buf, 32);
    printf("keystretch is done\n");
    rc = 0;
 out:
    return rc;
}

/* returns bool */
int
check_pass(unsigned char *mkey, unsigned char *hkey)
{
    hash_state md;
    unsigned char myhkey[32];
    int rc;

    rc = -1;

    sha256_init(&md);
    sha256_process(&md, mkey, 32);
    sha256_done(&md, myhkey);

    return (!memcmp(myhkey, hkey, 32));
}

/* ct is a pointer to two blocks which contain a key
   decrypts ct using twofish in ECB mode
   writes 32 bytes to out if successful
   */
int
decrypt_key(unsigned char *key, unsigned char *ct, unsigned char *out)
{
    symmetric_key skey;
    unsigned char buf[32];
    int err, rc;

    rc = -1;

    err = twofish_setup(key, KEY_LEN, 0, &skey);
    if (err != CRYPT_OK) {
        printf("decrypt_key: failed to setup\n");
        goto out;
    }

    err = twofish_ecb_decrypt(ct, buf, &skey);
    if (err != CRYPT_OK) {
        printf("decrypt_key: first decrypt failed\n");
        goto out;
    }

    err = twofish_ecb_decrypt(ct + BLOCK_LEN, buf + BLOCK_LEN, &skey);
    if (err != CRYPT_OK) {
        printf("decrypt_key: second decrypt failed\n");
        goto out;
    }

    rc = 0;
    memcpy(out, buf, 32);
 out:
    twofish_done(&skey);
    return rc;
}

static
int
read_field(FILE *dbf, symmetric_CBC *symkey, struct field *field)
{
    unsigned char cbuf[BLOCK_LEN];
    unsigned char pbuf[BLOCK_LEN];
    unsigned char *field_data;
    unsigned int field_len;
    int rc;

    rc = -1;
    /* if (fread(tagbuf, 1, PWS_TAG_LEN, dbf) < PWS_TAG_LEN) { */
    if (fread(cbuf, 1, BLOCK_LEN, dbf) < BLOCK_LEN) {
        printf("failed to read a block\n");
        goto out;
    }

    if (cbc_decrypt(cbuf, pbuf, BLOCK_LEN, symkey) != CRYPT_OK) {
        printf("failed to decrypt a block\n");
        goto out;
    }

    /* TODO read arbitrary length data (i.e. in more than one block) */
    field_len = read_le_uint32(pbuf);

    if (field_len > 11) {
        printf("oops, not implemented yet\n");
        goto out;
    }

    field_data = malloc(field_len);
    if (!field_data) {
        printf("OOM\n");
        goto out;
    }

    rc = 0;
    memcpy(field_data, pbuf + 5, field_len);
    field->data = field_data;
    field->len = field_len;
    field->type = pbuf[4];
 out:
    if (rc)
        free(field_data);
    return rc;
}

static
int
read_db_header(FILE *dbf, symmetric_CBC *sym, struct db_header *dbh)
{
    int rc;
    struct field field;
    int version;

    rc = -1;
    if (read_field(dbf, sym, &field)) {
        printf("got some kind of problem\n");
        goto out;
    }

    /* we're expecting the first field to be the version */
    if (field.type != TYPE_VERSION) {
        printf("bad format\n");
        goto out;
    }

    version = read_le_uint16(field.data);
    printf("version: 0x%x\n", version);
    if (version > VERSION) {
        printf("version is beyond me\n");
    }

    printf("field length: %u, field type: 0x%x, field data: %.*s\n",
           field.len, field.type, field.len, field.data);

    rc = 0;
 out:
    return rc;
}

static
struct db *
read_db(FILE *dbf, unsigned char *db_key, unsigned char *iv)
{
    symmetric_CBC symcbc;
    int twofish;
    struct db db;

    /* read header */
    /* then read all records - loop */
    /* we know records are done when we hit the record list sentinel */

    
    if ((twofish = register_cipher(&twofish_desc)) == -1) {
        printf("can't register twofish alg\n");
        goto out;
    }

    cbc_start(twofish, iv, db_key, KEY_LEN, 0, &symcbc);

    if (read_db_header(dbf, &symcbc, &db.header)) {
        printf("problem reading header\n");
        goto out;
    }
        

    /* if ((err = cbc_decrypt(ct, dec_pt, 32, &dec_symcbc)) != CRYPT_OK) { */

    
    /* when you're done reading everything... */
    cbc_done(&symcbc);
 out:
    return NULL;
}

int
read_pwsdb(FILE *dbf, char *pw) {
    int err, rc;
    char tagbuf[PWS_TAG_LEN];
    unsigned char salt[SALT_LEN];
    unsigned char iterbuf[4];
    unsigned int iter;
    unsigned char pw_key[KEY_LEN];
    unsigned char hashed_pw_key[KEY_LEN];
    unsigned char db_key[KEY_LEN];
    unsigned char digest_key[KEY_LEN];
    unsigned char iv[BLOCK_LEN];
    struct db *db;

    rc = -1;
    
    if (fread(tagbuf, 1, PWS_TAG_LEN, dbf) < PWS_TAG_LEN) {
        printf("failed to read tag\n");
        goto out;
    }

    if (strncmp(tagbuf, PWS_TAG, PWS_TAG_LEN)) {
        printf("failed tag check\n");
        goto out;
    }

    if (fread(salt, 1, SALT_LEN, dbf) < SALT_LEN) {
        printf("failed to read salt\n");
        goto out;
    }

    if (fread(iterbuf, 1, 4, dbf) < 4) {
        printf("failed to read iter\n");
        goto out;
    }

    iter = read_le_uint32(iterbuf);
    /* iter = iterbuf[0] | iterbuf[1] << 8 | iterbuf[2] << 16 | iterbuf[3] << 24; */
    printf("iter is: %d\n", iter);
    if (fread(hashed_pw_key, 1, 32, dbf) < 32) {
        printf("failed to read hashed key\n");
        goto out;
    }

    /* now check password */
    keystretch(pw, salt, iter, pw_key);
    if (!check_pass(pw_key, hashed_pw_key)) {
        printf("password is incorrect\n");
        goto out;
    }

    /* get K from B1 and B2 */
    if (fread(db_key, 1, KEY_LEN, dbf) < KEY_LEN) {
        printf("failed to read db_key\n");
        goto out;
    }
    decrypt_key(pw_key, db_key, db_key);

    if (fread(digest_key, 1, KEY_LEN, dbf) < KEY_LEN) {
        printf("failed to read digest_key\n");
        goto out;
    }
    decrypt_key(pw_key, digest_key, digest_key);
    if (!memcmp(db_key, digest_key, KEY_LEN)) {
        printf("K and L are identical\n");
        goto out;
    }

    if (fread(iv, 1, BLOCK_LEN, dbf) < BLOCK_LEN) {
        printf("failed to read iv\n");
        goto out;
    }

    db = read_db(dbf, db_key, iv);

    printf("all good\n");
    rc = 0;
 out:
    return rc;
}

int
main(int argc, char **argv)
{
    if (argc == 3) {
        char *dbpath, *pw;
        FILE *dbf;

        dbpath = argv[1];
        pw = argv[2];
        dbf = fopen(dbpath, "r");
        if (!dbf) {
            printf("failed to open file\n");
        } else {
            read_pwsdb(dbf, pw);
        }
    }
}
