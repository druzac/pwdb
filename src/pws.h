#ifndef _PWS_DB_
#define _PWS_DB_

#include <uuid/uuid.h>

struct db_header {
    short version;
    struct field *fields;
};

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

struct db *
pwsdb_open(const char *pw, const char *dbpath);

/* use rename to replace file atomically */
int
pwsdb_save(const struct db *db, const char *pw, char *dbpath);

int
pwsdb_create_new(const char *pw, char *dbpath);

/* initialize a new db obj in memory */
/* needs to set up db header with a version field */
void
pwsdb_init(struct db *db);

int
pwsdb_add_record(struct db *db,
                 const char *title,
                 const char *pass,
                 const char *user,
                 const char *url,
                 uuid_t uuid);  /* OUT */

char *
pwsdb_get_pass(struct db *db, const uuid_t uuid);

int
pwsdb_remove_record(struct db *db, const uuid_t uuid);

#endif
