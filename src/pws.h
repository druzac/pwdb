#ifndef _PWS_DB_
#define _PWS_DB_

#include <uuid/uuid.h>

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

struct db {
    struct db_header header;
    struct record *records;
};

void
print_db(struct db *db);

void
destroy_db(struct db *db);

int
read_pwsdb(struct db *db, const char *pw, FILE *dbf);

struct db *
pwsdb_open(const char *pw, const char *dbpath);

/* use rename to replace file atomically */
int
pwsdb_save(const struct db *db, const char *pw, char *dbpath);

int
pwsdb_create_new(const char *pw, char *dbpath);

/* make a new db */
/* needs to set up db header with a version field */
void
pwsdb_init(struct db *db);

int
pwsdb_add_record(struct db *db,
                 const char *title,
                 const char *pass,
                 const char *user,
                 const char *url);

char *
pwsdb_get_pass(struct db *db, const uuid_t uuid);

int
pwsdb_remove_record(struct db *db, const uuid_t uuid);

#endif
