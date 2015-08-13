#ifndef _PWDB_DB_
#define _PWDB_DB_

struct pwdb_accnt {
    char *uid;
    char *domain;
};

struct pwdb_entry {
    struct pwdb_accnt *accnt;
    char *pwd;
    struct pwdb_entry *next;
};

/* password db struct
   just use the defined functions */
struct pwdb {
    struct pwdb_entry *head;
};

/* initialize db */
void
pwdb_init(struct pwdb *db);

/* free db */
void
pwdb_destroy(struct pwdb *db);

/* return null, or the password */
char *
pwdb_lookup(struct pwdb *db, char *uid, char *domain);

/* insert new entry
   returns 0 on success, -1 on failure
   fails if there is already an entry for this uid, domain combination
   */
int
pwdb_insert(struct pwdb *db, char *uid, char *domain, char *pwd);

/* returns 0 if key is found
   -1 if key is not in there */
int
pwdb_delete(struct pwdb *db, char *uid, char *domain);

/* get all accounts the db has
   shallow copy!!!
   */
struct pwdb_accnt *
pwdb_list(struct pwdb *db, int *n_accnts);

unsigned char *
pwdb_serialize(struct pwdb *db, int *blen);

struct pwdb *
pwdb_deserialize(unsigned char *buf, unsigned int len);

#endif
