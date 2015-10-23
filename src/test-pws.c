#include <stdio.h>
#include <assert.h>
#include <uuid/uuid.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "pws.h"

void
test_rw_empty()
{
    struct db db, *dbp;
    char *pw = "foo";
    char dbpath[] = "/tmp/pwdb_test.XXXXXX";

    printf("started test_rw_empty\n");
    assert(mktemp(dbpath));
    pwsdb_init(&db);
    assert(!db.records);
    assert(!(pwsdb_save(&db, pw, dbpath)));
    assert((dbp = pwsdb_open(pw, dbpath)));
    assert(!dbp->records);

    destroy_db(&db);
    destroy_db(dbp);
    free(dbp);
}

void
test_rw_singleton()
{
    struct db db, *dbp;
    char *pw = "foo";
    char dbpath[] = "/tmp/pwdb_test.XXXXXX";
    char *title = "title";
    char *pass = "pass";
    uuid_t uuid;
    struct record *rec;

    printf("started test_rw_singleton\n");
    assert(mktemp(dbpath));
    pwsdb_init(&db);
    assert(!pwsdb_add_record(&db, title, pass, NULL, NULL, uuid));
    assert(!pwsdb_save(&db, pw, dbpath));
    assert((dbp = pwsdb_open(pw, dbpath)));
    assert((rec = dbp->records));
    assert(!uuid_compare(uuid, rec->uuid) && !strcmp(title, rec->title) &&
           !strcmp(pass, rec->password) && !rec->url && !rec->username);

    destroy_db(&db);
    destroy_db(dbp);
    free(dbp);
}

void
test_memory_singleton()
{
    struct db db;
    char *user = "user";
    char *pass = "password";
    char *url = "www.url.com";
    char *title = "test-entry";
    struct record *rec;
    uuid_t uuid;

    printf("started test_memory_singleton\n");
    pwsdb_init(&db);
    assert(!(db.records));
    assert(!pwsdb_add_record(&db, title, pass, user, url, uuid));
    assert(db.records);
    assert(db.records->next == db.records);
    assert(db.records->prev == db.records);

    rec = db.records;
    assert(!uuid_is_null(rec->uuid));
    assert(!strcmp(rec->username, user));
    assert(!strcmp(rec->password, pass));
    assert(!strcmp(rec->title, title));
    assert(!strcmp(rec->url, url));
    destroy_db(&db);
}

void
test_get_pass()
{
    struct db db;
    char *passwords[] = {"pass1", "pass2", "pass3"};
    char *titles[] = {"title1", "title2", "title3"};
    char *pass_res;
    int i;
    uuid_t uuids[3];

    printf("started test_get_pass\n");
    pwsdb_init(&db);
    assert(!(db.records));
    for (i = 0; i < 3; i++) {
        assert(!pwsdb_add_record(&db, titles[i], passwords[i], NULL, NULL, uuids[i]));
    }

    for (i = 0; i < 3; i++) {
        size_t l;
        assert((pass_res = pwsdb_get_pass(&db, uuids[i])));
        l = strlen(passwords[i]);
        assert(!strncmp(pass_res, passwords[i], l));
    }

    destroy_db(&db);
}

int
main()
{
    printf("testing...\n");
    test_memory_singleton();
    test_get_pass();
    test_rw_empty();
    test_rw_singleton();
}
