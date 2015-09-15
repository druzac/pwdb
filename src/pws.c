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
#define DIGEST_LEN 32
#define ITER_BYTES 4

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
    unsigned char *uuid; /* N. B. this is a pointer into one of the fields
                            do not free */
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

struct rand_state {
    FILE *rdev;
};

void
print_bytes(unsigned char *buf, int buflen)
{
    int i;
    for (i = 0; i < buflen; i++) {
        printf("\\x%02x", buf[i]);
    }
    printf("\n");
}

int
init_random(struct rand_state *rs)
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
get_random_bytes(struct rand_state *rs, unsigned char *buf, int buflen)
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
done_random(struct rand_state *rs)
{
    int rc;

    rc = -1;
    if (fclose(rs->rdev)) {
        perror("done_random");
        goto out;
    }

    rc = 0;
 out:
    return rc;
}

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

int
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
        get_random_bytes(rs, buf + 5 + curr_cnt, BLOCK_LEN - (curr_cnt + 5));
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
            get_random_bytes(rs, buf + curr_cnt, BLOCK_LEN - curr_cnt);
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
            printf("write_fields: writing a field failed\n");
            goto out;
        }
        field = field->next;
    } while (field != field_head);

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
int
hmac_db(struct db *db, unsigned char *digest_key, unsigned char *digest)
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
    int rc, twofish, err;
    symmetric_CBC symcbc;
    struct record *records_head, *record;

    rc = -1;

    if ((twofish = register_cipher(&twofish_desc)) == -1) {
        printf("can't register twofish alg\n");
        goto out;
    }

    if ((err = cbc_start(twofish, iv, db_key, KEY_LEN, 0, &symcbc)) != CRYPT_OK) {
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

/* this should be used by a save function - atomic rename */
int
write_pwsdb(FILE *dbf, struct db *db, char *pw, unsigned int iter)
{
    int rc, err;
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

    if (init_random(&rs)) {
        perror("init_random");
        goto out;
    }

    rc = -1;

    if (fwrite(PWS_TAG, PWS_TAG_LEN, 1, dbf) < 1) {
        printf("tag write failed\n");
        goto out;
    }

    err = get_random_bytes(&rs, salt, SALT_LEN);
    if (err) {
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

    if (get_random_bytes(&rs, db_key, KEY_LEN)) {
        printf("failed to get bytes for db_key\n");
        goto out;
    }

    if (write_key(pw_key, db_key, dbf)) {
        printf("failed to write db key\n");
        goto out;
    }

    if (get_random_bytes(&rs, digest_key, KEY_LEN)) {
        printf("failed to gen digest_key\n");
        goto out;
    }

    if (write_key(pw_key, digest_key, dbf)) {
        printf("failed to write digest_key\n");
        goto out;
    }

    if (get_random_bytes(&rs, iv, BLOCK_LEN)) {
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
    done_random(&rs);
    return rc;
}

struct db *
read_pwsdb(FILE *dbf, char *pw)
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

    db = read_db(dbf, db_key, iv);
    if (!db)
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
    return db;
}

int
main(int argc, char **argv)
{
    char *dbinpath, *dboutpath, *pw;
    FILE *dbinf, *dboutf;
    struct db *db;
    int rc;

    dbinf = NULL;
    dboutf = NULL;
    db = NULL;
    rc = -1;

    if (argc != 4) {
        printf("usage: <me> indb outdb password\n");
        goto out;
    }
    dbinpath = argv[1];
    dboutpath = argv[2];
    pw = argv[3];
    dbinf = fopen(dbinpath, "r");
    if (!dbinf) {
        printf("failed to open indb file\n");
        goto out;
    }
    db = read_pwsdb(dbinf, pw);
    if (!db) {
        printf("failed to read db\n");
        goto out;
    }

    print_db(db);

    dboutf = fopen(dboutpath, "w");
    if (write_pwsdb(dboutf, db, pw, 2048)) {
        printf("failed to write db\n");
        goto out;
    }

    rc = 0;
 out:
    fclose(dbinf);
    fclose(dboutf);
    destroy_db(db);
    free(db);

    return rc;
}
