#ifndef _PWS_DB_
#define _PWS_DB_

#include <uuid/uuid.h>

struct db;

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
int
pwsdb_init(struct db *db);

int
pwsdb_add_record(struct db *db, const char *title, const char *pass);

char *
pwsdb_get_pass(struct db *db, const uuid_t uuid);

int
pwsdb_remove_record(struct db *db, const uuid_t uuid);

#endif
