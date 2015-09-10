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
#define TYPE_EOE     0xff

/* mandatory record fields:
   UUID
   password
   title
   */
#define TYPE_TITLE      0x03
#define TYPE_PASSWORD   0x06

#define VERSION 0x0310

#define RECORDS_EOF_SENTINEL "PWS3-EOFPWS3-EOF"
#define RECORDS_EOF          1
#define RECORDS_ERR          2

/* any typeof on android + ios? */

/* MIN is defined in tomcrypt_macros */
/* #define MIN(a, b) (((a) < (b)) ? (a) : (b)) */

struct db_header {
    short version;
    struct field *fields;
};

struct record {
    unsigned char *uuid; /* N. B. this is a pointer into one of the fields */
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

/* the behaviour here is undefined if the db is invalid */
void
print_db(struct db *db)
{
    struct field *field, *fields_head;
    struct record *record, *records_head;
    printf("version: 0x%x\n", db->header.version);

    fields_head = db->header.fields;
    field = fields_head;

    do {
        printf("db header field:\n  length: %u, field type: 0x%x, field data: %.*s\n",
               field->len, field->type, field->len, field->data);
        field = field->next;
    } while (field != fields_head);

    records_head = db->records;
    record = records_head;
    if (record) {
        do {
            printf("record:\n  title: %s\n  password: %s\n",
                   record->title, record->password);
            record = record->next;
        } while (record != records_head);
    }
}

void
free_fields(struct field *fields_head)
{
    struct field *curr, *next;
    curr = fields_head;

    while (next != fields_head) {
        next = curr->next;
        free(curr->data);
        curr = next;
    }
}

/* doesn't free the whole list */
void
destroy_record(struct record *record)
{
    if (record) {
        free(record->title);
        free(record->password);
        free_fields(record->fields);
    }
}

void
free_records(struct record *records_head)
{
    struct record *curr, *next;
    curr = records_head;

    while (next != records_head) {
        next = curr->next;
        destroy_record(curr);
        free(curr);
        curr = next;
    }
}

void
destroy_db(struct db *db)
{
    if (db) {
        free_fields(db->header.fields);
        free_records(db->records);
    }
}

unsigned int
read_le_uint32(unsigned char *buf)
{
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
}

unsigned short
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

/* cut down on code duplication
   buf _MUST_ be at least 16 bytes long
   we assume the first read has already populated buf with 16 bytes of data
   */
static
int
__read_field(FILE *dbf, symmetric_CBC *symkey, struct field *field, unsigned char *buf)
{
    unsigned char *field_data;
    unsigned char field_type;
    unsigned int field_len;
    int rem_bytes;
    int rc;

    rc = -1;
    field_data = NULL;

    if (cbc_decrypt(buf, buf, BLOCK_LEN, symkey) != CRYPT_OK) {
        printf("failed to decrypt a block\n");
        goto out;
    }

    field_len = read_le_uint32(buf);
    field_type = buf[4];

    field_data = malloc(field_len);
    if (!field_data) {
        printf("OOM\n");
        goto out;
    }

    memcpy(field_data, buf + 5, MIN(field_len, 11));
    rem_bytes = field_len - 11;

    /* TODO should probably replace this with a bulk read, bulk decrypt */
    while (rem_bytes > 0) {
        if (fread(buf, 1, BLOCK_LEN, dbf) < BLOCK_LEN) {
            printf("failed to read a block\n");
            goto out;
        }

        if (cbc_decrypt(buf, buf, BLOCK_LEN, symkey) != CRYPT_OK) {
            printf("failed to decrypt\n");
            goto out;
        }

        memcpy(field_data + (field_len - rem_bytes), buf, MIN(rem_bytes, 16));
        rem_bytes = rem_bytes - 16;
    }

    rc = 0;
    field->len = field_len;
    field->type = field_type;
    field->data = field_data;
 out:
    if (rc)
        free(field_data);
    return rc;
}

static
int
read_field(FILE *dbf, symmetric_CBC *symkey, struct field *field)
{
    unsigned char buf[BLOCK_LEN];
    int rc;

    if (fread(buf, 1, BLOCK_LEN, dbf) < BLOCK_LEN) {
        printf("failed to read a block\n");
        goto out;
    }

    if (__read_field(dbf, symkey, field, buf)) {
        printf("__read_field failed\n");
        goto out;
    }

    rc = 0;
 out:
    return rc;
}

static
int
read_rest_fields(FILE *dbf, symmetric_CBC *sym, struct field *fields_head)
{
    struct field *field;
    int rc;

    rc = -1;

    do {
        field = malloc(sizeof(*field));
        if (!field) {
            printf("oom\n");
            goto out;
        }

        if (read_field(dbf, sym, field)) {
            printf("failed to read a field\n");
            free(field);
            goto out;
        }

        fields_head->prev->next = field;
        field->prev = fields_head->prev;
        field->next = fields_head;
        fields_head->prev = field;
    } while (field->type != TYPE_EOE);

    rc = 0;
 out:
    return rc;
}

static
int
read_db_header(FILE *dbf, symmetric_CBC *sym, struct db_header *dbh)
{
    int rc;
    struct field *field, *fields_head;
    short version;

    rc = -1;

    fields_head = malloc(sizeof(*fields_head));
    if (!fields_head) {
        printf("malloc failed\n");
        goto out;
    }

    memset(fields_head, 0, sizeof(*fields_head));

    if (read_field(dbf, sym, fields_head)) {
        printf("got some kind of problem\n");
        free(fields_head);
        goto out;
    }

    fields_head->prev = fields_head->next = fields_head;
    dbh->fields = fields_head;
    /* we're expecting the first field to be the version */
    if (fields_head->type != TYPE_VERSION) {
        printf("bad format\n");
        goto out;
    }

    version = read_le_uint16(fields_head->data);
    if (version > VERSION) {
        printf("version is beyond me\n");
        goto out;
    }

    if (read_rest_fields(dbf, sym, fields_head))
        goto out;

    rc = 0;
    dbh->version = version;
 out:
    return rc;
}

static
int
read_db_record(FILE *dbf, symmetric_CBC *symcbc, struct record *rec)
{
    int rc;
    unsigned char buf[BLOCK_LEN];
    struct field *fields_head;
    struct field *field;
    char valid_mask;

    rc = RECORDS_ERR;
    fields_head = NULL;
    memset(rec, 0, sizeof(*rec));
    valid_mask = 0;

    if (fread(buf, 1, BLOCK_LEN, dbf) < BLOCK_LEN) {
        printf("failed to read a block\n");
        goto out;
    }

    /* test for EOF */
    if (!strncmp((char *) buf, RECORDS_EOF_SENTINEL, BLOCK_LEN)) {
        rc = RECORDS_EOF;
        goto out;
        /* XXX make sure we don't have any cleanup above */
    }

    fields_head = malloc(sizeof(*fields_head));
    if (!fields_head) {
        printf("oom\n");
        goto out;
    }
    fields_head->next = fields_head->prev = fields_head;
    /* save now so we can free later */
    rec->fields = fields_head;

    if (__read_field(dbf, symcbc, fields_head, buf)) {
        printf("__read_field failed\n");
        goto out;
    }

    if (fields_head->type == TYPE_EOE) {
        printf("read_db_record: invalid record, too early EOE\n");
        goto out;
    }

    if (read_rest_fields(dbf, symcbc, fields_head)) {
        printf("couldn't read remaining fields\n");
        goto out;
    }

    /* validate the record */
    field = fields_head;
    do {
        switch (field->type) {
        case TYPE_UUID:
            rec->uuid = field->data;
            valid_mask |= (1 << 0);
            break;
        case TYPE_TITLE:
            rec->title = strndup((char *)field->data, field->len);
            if (!rec->title)
                goto out;
            valid_mask |= (1 << 1);
            break;
        case TYPE_PASSWORD:
            rec->password = strndup((char *)field->data, field->len);
            if (!rec->password)
                goto out;
            valid_mask |= (1 << 2);
            break;
        }
        field = field->next;
    } while (field != fields_head && valid_mask != 7);

    if (valid_mask != 7) {
        printf("record is missing required fields, mask value: %d\n", valid_mask);
        goto out;
    }

    rc = 0;
 out:
    if (rc)
        destroy_record(rec);

    return rc;
}

static
int
read_db_records(FILE *dbf, symmetric_CBC *symcbc, struct db *db)
{
    struct record *records_head;

    int rc, err;

    rc = -1;

    records_head = malloc(sizeof(*records_head));
    if (!records_head) {
        printf("oom\n");
        goto out;
    }

    err = read_db_record(dbf, symcbc, records_head);
    
    if (err == RECORDS_ERR) {
        printf("err reading record\n");
        free(records_head);
        goto out;
    }

    if (err == RECORDS_EOF) {
        /* we're done */
        free(records_head);
        db->records = NULL;
    } else { 
        records_head->next = records_head->prev = records_head;
        db->records = records_head;
        do {
            struct record *record;

            record = malloc(sizeof(*record));
            if (!record) {
                printf("oom\n");
                goto out;
            }

            err = read_db_record(dbf, symcbc, record);
            if (err == RECORDS_ERR) {
                free(record);
                goto out;
            }
            if (err == RECORDS_EOF) {
                free(record);
            } else {
                records_head->prev->next = record;
                record->prev = records_head->prev;
                records_head->prev = record;
                record->next = records_head;
            }
        } while (err != RECORDS_EOF);
    }

    rc = 0;
 out:
    /* no cleanup here - let read_db destroy the whole database if
       necessary */
    return rc;
}

static
struct db *
read_db(FILE *dbf, unsigned char *db_key, unsigned char *iv)
{
    symmetric_CBC symcbc;
    int twofish, rc;
    struct db *db;

    rc = -1;
    db = NULL;

    if ((twofish = register_cipher(&twofish_desc)) == -1) {
        printf("can't register twofish alg\n");
        goto out;
    }

    db = malloc(sizeof(*db));
    if (!db)
        goto out;

    cbc_start(twofish, iv, db_key, KEY_LEN, 0, &symcbc);

    if (read_db_header(dbf, &symcbc, &db->header)) {
        printf("problem reading header\n");
        goto dereg_cipher;
    }

    if (read_db_records(dbf, &symcbc, db)) {
        printf("problem reading db records\n");
        goto dereg_cipher;
    }

    rc = 0;
 dereg_cipher:
    cbc_done(&symcbc);
 out:
    if (rc) {
        destroy_db(db);
        free(db);
        db = NULL;
    }
    return db;
}

struct db *
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
    db = NULL;
    
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
    if (!db)
        goto out;

    /* TODO
       hash all the fields to check the HMAC
       */

    rc = 0;
 out:
    return db;
}

int
main(int argc, char **argv)
{
    if (argc == 3) {
        char *dbpath, *pw;
        FILE *dbf;
        struct db *db;

        dbpath = argv[1];
        pw = argv[2];
        dbf = fopen(dbpath, "r");
        if (!dbf) {
            printf("failed to open file\n");
        } else {
            db = read_pwsdb(dbf, pw);
            if (db) {
                print_db(db);
                destroy_db(db);
                free(db);
            }
        }
    }
}
