#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include <tomcrypt.h>

#include "pws.h"
#include "util.h"

#define PWS_TAG "PWS3"
#define PWS_TAG_LEN 4

#define SALT_LEN 32
#define KEY_LEN 32
#define BLOCK_LEN 16
#define DIGEST_LEN 32
#define ITER_BYTES 4
#define UUID_LEN 16

/* common fields */
#define TYPE_UUID    0x01
#define TYPE_EOE     0xff

#define DEFAULT_ITER (1 << 12)

/* db header fields */
#define TYPE_HDR_VERSION 0x00

/* record fields */
#define TYPE_REC_TITLE    0x03
#define TYPE_REC_USER     0x04
#define TYPE_REC_PASSWORD 0x06
#define TYPE_REC_URL      0x0d

#define VERSION 0x0310

#define RECORDS_EOF_SENTINEL "PWS3-EOFPWS3-EOF"
#define RECORDS_EOF          1
#define RECORDS_ERR          2

#define FIELDS_EOE           1
#define FIELDS_ERR           2

/* any typeof on android + ios? */

/* MIN is defined in tomcrypt_macros */
/* #define MIN(a, b) (((a) < (b)) ? (a) : (b)) */

struct db_header {
    short version;
    struct field *fields;
};

/* N.B
   there is duplication in this data structure
   the fields llist is _all_ fields
   this is to make the computation of the db hmac easier
   */
struct record {
    uuid_t uuid;
    char *title;
    char *password;
    char *username;
    char *url;
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

struct field eoe_field = (struct field) {
    .len = 0,
    .type = TYPE_EOE,
    .data = NULL,
    .next = NULL,
    .prev = NULL,
};

struct db {
    struct db_header header;
    struct record *records;
};

void
debug_db(struct db *db)
{
    struct field *f;
    struct record *rec;
    f = db->header.fields;

    if (f)
        do {
            printf("db header field: 0x%02x\n", f->type);
        } while ((f = f->next) != db->header.fields);
    rec = db->records;
    if (rec)
        do {
            f = rec->fields;
            do {
                printf("rec field: 0x%02x\n", f->type);
                if (f->type == TYPE_REC_URL)
                    printf("%*s\n", f->len, f->data);
            } while ((f = f->next) != rec->fields);
        } while ((rec = rec->next) != db->records);
}

void
print_bytes(unsigned char *buf, int buflen)
{
    int i;
    for (i = 0; i < buflen; i++) {
        printf("\\x%02x", buf[i]);
    }
    printf("\n");
}


/* the behaviour here is undefined if the db is invalid */
void
print_db(struct db *db)
{
    struct field *field, *fields_head;
    struct record *record, *records_head;
    uuid_string_t uuid_s;
    printf("version: 0x%x\n", db->header.version);

    fields_head = db->header.fields;
    field = fields_head;

    records_head = db->records;
    record = records_head;
    if (record) {
        do {
            uuid_unparse(record->uuid, uuid_s);
            printf("%s:\n"
                   "  password: %s\n"
                   "  uuid: %s\n",
                   record->title, record->password, uuid_s);
            if (record->username)
                printf("  user: %s\n", record->username);
            if (record->url)
                printf("  url: %s\n", record->url);
            record = record->next;
        } while (record != records_head);
    }
}

static void
destroy_field(struct field *field)
{
    if (field)
        free(field->data);
}

static void
free_fields(struct field *fields_head)
{
    if (fields_head) {
        struct field *curr, *next;

        curr = fields_head;
        while (next != fields_head) {
            next = curr->next;
            free(curr->data);
            free(curr);
            curr = next;
        }
    }
}

static struct field *
create_field(const void *data, unsigned int dlen, unsigned char type)
{
    int rc;
    struct field *f;

    rc = -1;
    if (!(f = malloc(sizeof(*f))))
        goto out;

    memset(f, 0, sizeof(*f));
    if (!(f->data = malloc(dlen)))
        goto out;

    memcpy(f->data, data, dlen);
    f->type = type;
    f->len = dlen;
    rc = 0;
 out:
    if (rc) {
        destroy_field(f);
        free(f);
        f = NULL;
    }
    return f;
}

/* doesn't free the whole list */
static void
destroy_record(struct record *record)
{
    if (record) {
        free(record->title);
        free(record->password);
        free(record->username);
        free(record->url);
        free_fields(record->fields);
    }
}

static void
free_records(struct record *records_head)
{
    struct record *curr, *next;
    curr = records_head;

    if (curr)
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
        memset(db, 0, sizeof(*db));
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

void
write_le_uint16(unsigned short n, unsigned char *buf)
{
    buf[0] = n & 0xff;
    buf[1] = (n >>= 8) & 0xff;
}

void
write_le_uint32(unsigned int n, unsigned char *buf)
{
    buf[0] = n & 0xff;
    buf[1] = (n >>= 8) & 0xff;
    buf[2] = (n >>= 8) & 0xff;
    buf[3] = (n >>= 8) & 0xff;
}

int
sha256_once(const unsigned char *buf, unsigned int buf_len, unsigned char *out)
{
    /* TODO
       check error codes here
       */
    int rc;
    hash_state md;

    sha256_init(&md);
    sha256_process(&md, buf, buf_len);
    sha256_done(&md, out);

    rc = -1;

    rc = 0;
 out:
    return rc;
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
static int
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

static int
write_key(unsigned char *eckey, unsigned char *keybuf, FILE *f)
{
    symmetric_key skey;
    int rc, err;
    unsigned char buf[BLOCK_LEN * 2];

    rc = -1;
    memset(&skey, 0, sizeof(skey));

    err = twofish_setup(eckey, KEY_LEN, 0, &skey);
    if (err != CRYPT_OK) {
        printf("write_key: failed to setup\n");
        goto out;
    }


    if ((err = twofish_ecb_encrypt(keybuf, buf, &skey)) != CRYPT_OK) {
        printf("write_key: first encrypt failed\n");
        goto out;
    }

    if ((err = twofish_ecb_encrypt(keybuf + BLOCK_LEN,
                                   buf + BLOCK_LEN,
                                   &skey)) != CRYPT_OK) {
        printf("write_key: second encrypt failed\n");
        goto out;
    }

    if (fwrite(buf, BLOCK_LEN * 2, 1, f) < 1) {
        printf("write_key: write failed\n");
        goto out;
    }

    rc = 0;
 out:
    twofish_done(&skey);
    return rc;
}

/* ct is a pointer to two blocks which contain a key
   decrypts ct using twofish in ECB mode
   writes 32 bytes to out if successful
   */
static int
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
    memset(field, 0, sizeof(*field)); /* TODO this is really ugly, need to fix this */

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

    memset(field, 0, sizeof(*field));

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
write_field(struct field *field, symmetric_CBC *ec, struct rand_state *rs, FILE *f)
{
    int rc, total_cnt, curr_cnt;
    unsigned char buf[BLOCK_LEN];

    rc = -1;

    write_le_uint32(field->len, buf);
    buf[4] = field->type;
    curr_cnt = MIN(field->len, BLOCK_LEN - 5);
    memcpy(buf + 5, field->data, curr_cnt);
    if (curr_cnt + 5 < BLOCK_LEN) {
        if (rand_get_bytes(rs, buf + 5 + curr_cnt, BLOCK_LEN - (curr_cnt + 5)))
            goto out;
    }
    if (cbc_encrypt(buf, buf, BLOCK_LEN, ec) != CRYPT_OK) {
        printf("write_field: first encrypt failed\n");
        goto out;
    }

    if (fwrite(buf, BLOCK_LEN, 1, f) < 1) {
        printf("failed to write first block\n");
        goto out;
    }
    total_cnt = curr_cnt;
    while (total_cnt < field->len) {
        curr_cnt = MIN(field->len - total_cnt, BLOCK_LEN);
        memcpy(buf, field->data + total_cnt, curr_cnt);
        if (curr_cnt < BLOCK_LEN) {
            if (rand_get_bytes(rs, buf + curr_cnt, BLOCK_LEN - curr_cnt))
                goto out;
        }
        if (cbc_encrypt(buf, buf, BLOCK_LEN, ec) != CRYPT_OK) {
            printf("write_field: encrypt failed\n");
            goto out;
        }
        if (fwrite(buf, BLOCK_LEN, 1, f) < 1) {
            printf("failed to write a block\n");
            goto out;
        }
        total_cnt += curr_cnt;
    }

    rc = 0;
 out:
    return rc;
}

static
int
write_fields(struct field *field_head, symmetric_CBC *ec, struct rand_state *rs, FILE *f)
{
    int rc;
    struct field *field;

    rc = -1;
    field = field_head;

    do {
        if (write_field(field, ec, rs, f)) {
            fprintf(stderr, "write_fields: writing a field failed\n");
            goto out;
        }
        field = field->next;
    } while (field != field_head);

    if (write_field(&eoe_field, ec, rs, f)) /* write EOE field */
        goto out;

    rc = 0;
 out:
    return rc;
}

static
int
add_field_to_header(struct db_header *hdr, struct field *f)
{
    int rc;
    rc = FIELDS_ERR;

    switch (f->type) {
    case TYPE_HDR_VERSION:
        hdr->version = read_le_uint16(f->data);
        break;
    case TYPE_EOE:
        rc = FIELDS_EOE;
        goto out;
    }

    rc = 0;
    if (hdr->fields) {
        f->next = hdr->fields;
        f->prev = hdr->fields->prev;
        hdr->fields->prev->next = f;
        hdr->fields->prev = f;
    } else {
        hdr->fields = f;
        f->next = f->prev = f;
    }
 out:
    return rc;
}

static
int
read_db_header(FILE *dbf, symmetric_CBC *sym, struct db_header *dbh)
{
    int rc, err;
    struct field *field;
    short version;

    rc = -1;

    field = malloc(sizeof(*field));
    if (read_field(dbf, sym, field)) {
        fprintf(stderr, "read_db_header: couldn't read field\n");
        goto out;
    }

    if (field->type != TYPE_HDR_VERSION) {
        fprintf(stderr, "bad db header format\n");
        goto out;
    }

    if (add_field_to_header(dbh, field))
        goto out;

    do {
        if (!(field = malloc(sizeof(*field))) ||
            read_field(dbf, sym, field))
            goto out;
    } while (!(err = add_field_to_header(dbh, field)));

    if (err != FIELDS_EOE)
        goto out;

    rc = 0;
 out:
    destroy_field(field);
    free(field);
    return rc;
}

static
int
add_field_to_record(struct record *rec, struct field *f)
{
    int rc;

    rc = FIELDS_ERR;

    switch (f->type) {
    case TYPE_UUID:
        if (f->len != UUID_LEN)
            goto out;
        memcpy(rec->uuid, f->data, UUID_LEN);
        break;
    case TYPE_REC_TITLE:
        rec->title = strndup((char *)f->data, f->len);
        if (!rec->title)
            goto out;
        break;
    case TYPE_REC_PASSWORD:
        rec->password = strndup((char *)f->data, f->len);
        if (!rec->password)
            goto out;
        break;
    case TYPE_REC_USER:
        if (!(rec->username = strndup((char *)f->data, f->len)))
            goto out;
        break;
    case TYPE_REC_URL:
        if (!(rec->url = strndup((char *)f->data, f->len)))
            goto out;
        break;
    case TYPE_EOE:
        rc = FIELDS_EOE;
        goto out;
    }

    rc = 0;
    if (rec->fields) {
        f->next = rec->fields;
        f->prev = rec->fields->prev;
        rec->fields->prev->next = f;
        rec->fields->prev = f;
    } else {
        rec->fields = f;
        f->next = f->prev = f;
    }
 out:
    return rc;
}

static
int
read_db_record(FILE *dbf, symmetric_CBC *symcbc, struct record *rec)
{
    int rc, err;
    unsigned char buf[BLOCK_LEN];
    struct field *field;
    char valid_mask;

    rc = RECORDS_ERR;
    field = NULL;
    memset(rec, 0, sizeof(*rec));

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

    field = malloc(sizeof(*field));
    if (!field) {
        printf("oom\n");
        goto out;
    }

    if (__read_field(dbf, symcbc, field, buf)) {
        printf("__read_field failed\n");
        goto out;
    }

    if ((err = add_field_to_record(rec, field))) {
        fprintf(stderr, "read_db_record: invalid record (too soon EOE) or bad field"
                "err was %d\n", err);
        goto out;
    }

    do {
        if (!(field = malloc(sizeof(*field))) ||
            read_field(dbf, symcbc, field))
            goto out;
    } while (!(err = add_field_to_record(rec, field)));

    if (err != FIELDS_EOE)
        goto out;

    if (uuid_is_null(rec->uuid) || !rec->password || !rec->title) {
        fprintf(stderr, "invalid record, missing required fields\n");
        goto out;
    }

    rc = 0;
 out:
    /* unconditionally destroy eoe field or err field */
    destroy_field(field);
    free(field);

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
int
hmac_db(const struct db *db, unsigned char *digest_key, unsigned char *digest)
{
    int rc;
    hmac_state hmac;
    int hashfcn;
    struct field *field;
    struct record *record;
    unsigned long dlen;

    dlen = DIGEST_LEN;
    rc = -1;

    if ((hashfcn = register_hash(&sha256_desc)) == -1) {
        printf("couldn't register hash\n");
        goto out;
    }

    if (hmac_init(&hmac, hashfcn, digest_key, KEY_LEN) != CRYPT_OK) {
        printf("couldn't init digest\n");
        goto out;
    }

    field = db->header.fields;
    /* must have the version at least */
    do {
        if (field->len)
            if (hmac_process(&hmac, field->data, field->len) != CRYPT_OK) {
                printf("couldn't hash field\n");
                goto out;
            }
        field = field->next;
    } while (field != db->header.fields);

    record = db->records;
    if (record) {
        do {
            field = record->fields;
            do {
                if (hmac_process(&hmac, field->data, field->len) != CRYPT_OK) {
                    printf("couldn't hash field\n");
                    goto out;
                }
                field = field->next;
            } while (field != record->fields);
            record = record->next;
        } while (record != db->records);
    }

    if (hmac_done(&hmac, digest, &dlen) != CRYPT_OK) {
        printf("couldn't finish digest\n");
        goto out;
    }

    if (dlen != DIGEST_LEN) {
        printf("what the beef, dlen got changed\n");
        goto out;
    }

    rc = 0;
 out:
    return rc;
}

/* symmetry with read_db
   so this guy should write the EOF marker when he's done writing the db records
   */
static
int
write_db(const struct db *db, const unsigned char *db_key, const unsigned char *iv, struct rand_state *rs, FILE *dbf)
{
    int rc, twofish;
    symmetric_CBC symcbc;
    struct record *records_head, *record;

    rc = -1;

    if ((twofish = register_cipher(&twofish_desc)) == -1) {
        printf("can't register twofish alg\n");
        goto out;
    }

    if (cbc_start(twofish, iv, db_key, KEY_LEN, 0, &symcbc) != CRYPT_OK) {
        printf("write_db: couldn't start cbc\n");
        goto out;
    }

    if (write_fields(db->header.fields, &symcbc, rs, dbf)) {
        printf("write_db: failed to write header fields\n");
        goto out;
    }

    record = records_head = db->records;
    if (record) {
        do {
            if (write_fields(record->fields, &symcbc, rs, dbf)) {
                printf("write_db: failed to write a record\n");
                goto out;
            }
            record = record->next;
        } while (record != records_head);
    }

    if (fwrite(RECORDS_EOF_SENTINEL, BLOCK_LEN, 1, dbf) < 1) {
        printf("write_db: failed to write sentinel\n");
        goto out;
    }

    rc = 0;
 out:
    return rc;
}

static int
read_db(struct db *db, unsigned char *db_key, unsigned char *iv, FILE *dbf)
{
    symmetric_CBC symcbc;
    int twofish, rc;

    rc = -1;

    if ((twofish = register_cipher(&twofish_desc)) == -1) {
        printf("can't register twofish alg\n");
        goto out;
    }

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
    return rc;
}

/* this should be used by a save function - atomic rename */
static int
write_pwsdb(const struct db *db, const char *pw, unsigned int iter, FILE *dbf)
{
    int rc;
    unsigned char salt[SALT_LEN],
        pw_key[KEY_LEN],
        hashed_pw_key[KEY_LEN],
        db_key[KEY_LEN],
        digest_key[KEY_LEN],
        iterbuf[ITER_BYTES],
        iv[BLOCK_LEN],
        file_digest[DIGEST_LEN];
    struct rand_state rs;

    memset(&rs, 0, sizeof(rs));
    rc = -1;

    if (rand_init(&rs)) {
        perror("init_random");
        goto out;
    }

    if (fwrite(PWS_TAG, PWS_TAG_LEN, 1, dbf) < 1) {
        printf("tag write failed\n");
        goto out;
    }

    if (rand_get_bytes(&rs, salt, SALT_LEN)) {
        printf("failed to get gen salt\n");
        goto out;
    }

    if (fwrite(salt, SALT_LEN, 1, dbf) < 1) {
        printf("salt write failed\n");
        goto out;
    }

    write_le_uint32(iter, iterbuf);
    if (fwrite(iterbuf, ITER_BYTES, 1, dbf) < 1) {
        printf("iter write failed\n");
        goto out;
    }

    keystretch(pw, salt, iter, pw_key);
    sha256_once(pw_key, KEY_LEN, hashed_pw_key);
    if (fwrite(hashed_pw_key, KEY_LEN, 1, dbf) < 1) {
        printf("hashed pw key write failed\n");
        goto out;
    }

    if (rand_get_bytes(&rs, db_key, KEY_LEN)) {
        printf("failed to get bytes for db_key\n");
        goto out;
    }

    if (write_key(pw_key, db_key, dbf)) {
        printf("failed to write db key\n");
        goto out;
    }

    if (rand_get_bytes(&rs, digest_key, KEY_LEN)) {
        printf("failed to gen digest_key\n");
        goto out;
    }

    if (write_key(pw_key, digest_key, dbf)) {
        printf("failed to write digest_key\n");
        goto out;
    }

    if (rand_get_bytes(&rs, iv, BLOCK_LEN)) {
        printf("failed to generate iv\n");
        goto out;
    }

    if (fwrite(iv, BLOCK_LEN, 1, dbf) < 1) {
        printf("failed to write iv\n");
        goto out;
    }

    if (write_db(db, db_key, iv, &rs, dbf)) {
        printf("failed to write db\n");
        goto out;
    }

    if (hmac_db(db, digest_key, file_digest)) {
        printf("failed to make file digest\n");
        goto out;
    }

    if (fwrite(file_digest, DIGEST_LEN, 1, dbf) < 1) {
        printf("failed to write digest\n");
        goto out;
    }

    rc = 0;
 out:
    rand_destroy(&rs);
    return rc;
}

int
read_pwsdb(struct db *db, const char *pw, FILE *dbf)
{
    int err, rc;
    unsigned int iter;
    char tagbuf[PWS_TAG_LEN];
    unsigned char salt[SALT_LEN],
        iterbuf[ITER_BYTES],
        pw_key[KEY_LEN],
        hashed_pw_key[KEY_LEN],
        db_key[KEY_LEN],
        digest_key[KEY_LEN],
        iv[BLOCK_LEN],
        their_digest[DIGEST_LEN],
        my_digest[DIGEST_LEN];

    rc = -1;
    memset(db, 0, sizeof(*db));

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

    if (fread(iterbuf, 1, ITER_BYTES, dbf) < 4) {
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

    if (read_db(db, db_key, iv, dbf))
        goto out;

    if (fread(their_digest, DIGEST_LEN, 1, dbf) < 1) {
        printf("couldn't read digest\n");
        goto out;
    }

    if (hmac_db(db, digest_key, my_digest)) {
        printf("couldn't verify db\n");
        goto out;
    }

    if (memcmp(their_digest, my_digest, DIGEST_LEN)) {
        printf("digests are different\n");
        goto out;
    }

    rc = 0;
 out:
    if (rc) {
        destroy_db(db);
        free(db);
        db = NULL;
    }
    return rc;
}

int
pwsdb_init(struct db *db)
{
    int rc;
    struct field *vers;
    unsigned char *vers_d;

    rc = -1;

    memset(db, 0, sizeof(*db));
    db->header.version = VERSION;
    vers = NULL;
    vers_d = NULL;

    if (!(vers = malloc(sizeof(*vers))))
        goto out;

    if (!(vers_d = malloc(2 * sizeof(*vers_d))))
        goto out;

    vers->len = 2;
    vers->type = TYPE_HDR_VERSION;
    write_le_uint16(VERSION, vers_d);
    vers->data = vers_d;
    vers->next = vers->next = vers;

    db->header.fields = vers;
    rc = 0;
 out:
    if (rc) {
        free(vers);
        free(vers_d);
    }
    return rc;
}

int
pwsdb_save(const struct db *db, const char *pw, char *dbpath)
{
    int rc, tmpfd, err;
    char tmpfname[] = "/tmp/pwsdb.tmpXXXXXX";
    FILE *tmpdbf;

    rc = tmpfd = -1;

    if (-1 == (tmpfd = mkstemp(tmpfname)))
        goto out;

    if (!(tmpdbf = fdopen(tmpfd, "w")))
        goto out;

    if (write_pwsdb(db, pw, DEFAULT_ITER, tmpdbf)) {
        fprintf(stderr, "failed to write to db");
        goto out;
    }

    /* N.B. this call returns a non-zero value, but it doesn't
       set errno
       bug?
       */
    if (fclose(tmpdbf) && errno != 0) {
        perror("couldn't flush");
        goto out;
    }

    if (rename(tmpfname, dbpath)) {
        fprintf(stderr, "rename failed");
        goto out;
    }

    rc = 0;
 out:
    if (rc)
        err = errno;
    if (tmpfd != -1)
        close(tmpfd);
    if (rc)
        errno = err;
    return rc;
}

struct db *
pwsdb_open(const char *pw, const char *dbpath)
{
    int rc;
    FILE *dbf;
    struct db *db;

    rc = -1;
    db = NULL;
    dbf = NULL;

    if (!(dbf = fopen(dbpath, "r"))) {
        perror("failed to open db");
        goto out;
    }

    if (!(db = malloc(sizeof(*db))))
        goto out;

    rc = read_pwsdb(db, pw, dbf);
 out:
    fclose(dbf);
    return rc ? NULL : db;
}

int
pwsdb_create_new(const char *pw, char *dbpath)
{
    struct db db;
    int rc;

    pwsdb_init(&db);
    rc = pwsdb_save(&db, pw, dbpath);
    destroy_db(&db);

    return rc;
}

/* TODO
   can streamline this with new function add_field_to_record
   */
/* TODO this thing looks like it has problems with the error path and freeing resources */
int
pwsdb_add_record(struct db *db, const char *title, const char *pass, const char *user, const char *url)
{
    int rc;
    struct field *field;
    struct record *rec;
    uuid_t uuid;

    rc = -1;
    rec = NULL;
    field = NULL;

    if (!(rec = malloc(sizeof(*rec))))
        goto out;
    memset(rec, 0, sizeof(*rec));
    uuid_generate_random(uuid);

    if (!(field = create_field((const void *)uuid, UUID_LEN, TYPE_UUID)) ||
            add_field_to_record(rec, field))
        goto out;

    if (!(field = create_field(title, strlen(title), TYPE_REC_TITLE)) ||
            add_field_to_record(rec, field))
        goto out;

    if (!(field = create_field(pass, strlen(pass), TYPE_REC_PASSWORD)) ||
            add_field_to_record(rec, field))
        goto out;

    if (user)
        if (!(field = create_field(user, strlen(user), TYPE_REC_USER)) ||
                add_field_to_record(rec, field))
            goto out;

    if (url)
        if (!(field = create_field(url, strlen(url), TYPE_REC_URL)) ||
                add_field_to_record(rec, field))
            goto out;

    rc = 0;
    if (db->records) {
        rec->next = db->records;
        rec->prev = db->records->prev;
        db->records->prev->next = rec;
        db->records->prev = rec;
    } else {
        rec->next = rec->prev = rec;
        db->records = rec;
    }
 out:
    if (rc) {
        destroy_record(rec);
        free(rec);
        destroy_field(field);
        free(field);
    }
    return rc;
}

char *
pwsdb_get_pass(struct db *db, const uuid_t uuid)
{
    struct record *recs_head, *rec;
    char *pass;

    pass = NULL;
    recs_head = rec = db->records;
    if (rec)
        do {
            if (!uuid_compare(rec->uuid, uuid)) {
                pass = rec->password;
                break;
            }
            rec = rec->next;
        } while (rec != recs_head);
    return pass;
}

int
pwsdb_remove_record(struct db *db, const uuid_t uuid)
{
    struct record *recs_head, *rec;
    int rc;

    rc = -1;
    recs_head = rec = db->records;
    if (rec)
        do {
            if (!uuid_compare(rec->uuid, uuid)) {
                rec->next->prev = rec->prev;
                rec->prev->next = rec->next;
                if (rec == recs_head) {
                    if (rec->next == rec)
                        db->records = NULL;
                    else
                        db->records = rec->next;
                }
                destroy_record(rec);
                free(rec);
                rc = 0;
                break;
            }
        } while ((rec = rec->next) != recs_head);
    return rc;
}
