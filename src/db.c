#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "db.h"

/* struct pwdb_entry { */
/*     struct pwdb_accnt *accnt; */
/*     char *pwd; */
/*     struct pwdb_entry *next; */
/* }; */

/* struct pwdb { */
/*     struct pwdb_entry *head; */
/* }; */

/* struct pwdb_accnt { */
/*     char *uid; */
/*     char *domain; */
/* }; */

void
pwdb_init(struct pwdb *db)
{
    db->head = NULL;
}

void
pwdb_destroy(struct pwdb *db)
{
    if (db) {
        /* do stuff */
    }
    /* XXX */
}


char *
pwdb_lookup(struct pwdb *db, char *uid, char *domain)
{
    char *pwd;
    struct pwdb_entry *p;

    pwd = NULL;
    p = db->head;
    while (p) {
        if (!strcmp(p->accnt->uid, uid) && !(strcmp(p->accnt->domain, domain))) {
            pwd = p->pwd;
            break;
        }
        p = p->next;
    }
    return pwd;
}

int
pwdb_insert(struct pwdb *db, char *uid, char *domain, char *pwd)
{
    int rc;
    struct pwdb_accnt *accnt;
    struct pwdb_entry *entry;
    char *d_cpy, *u_cpy, *p_cpy;

    accnt = NULL;
    entry = NULL;
    d_cpy = u_cpy = p_cpy = NULL;
    rc = -1;
    if (pwdb_lookup(db, uid, domain))
        goto out;

    accnt = malloc(sizeof(*accnt));
    entry = malloc(sizeof(*entry));
    u_cpy = strdup(uid);
    d_cpy = strdup(domain);
    p_cpy = strdup(pwd);

    if (!accnt || !entry || !entry || !u_cpy || !d_cpy || !p_cpy)
        goto out;

    *accnt = (struct pwdb_accnt) {
        .uid = u_cpy,
        .domain = d_cpy,
    };

    *entry = (struct pwdb_entry) {
        .accnt = accnt,
        .pwd = p_cpy,
        .next = db->head,
    };

    db->head = entry;
    rc = 0;

 out:
    return rc;
}

int
pwdb_delete(struct pwdb *db, char *uid, char *domain)
{
    return -1;
}


/* makes a _shallow_ copy of the accnts */
struct pwdb_accnt *
pwdb_list(struct pwdb *db, int *n_accnts)
{
    struct pwdb_accnt *accnts, *p;
    struct pwdb_entry *entry;
    int err, cnt;

    err = -1;
    cnt = 0;
    accnts = NULL;
    entry = db->head;

    printf("entering loop\n");

    while (entry) {
        char *u, *d;
        p = realloc(accnts, (cnt + 1) * sizeof(*accnts));
        if (!p)
            goto out;
        accnts = p;
        printf("assigning to array \n");
        accnts[cnt++] = (struct pwdb_accnt) {
            .uid = entry->accnt->uid,
            .domain = entry->accnt->domain,
        };
        entry = entry->next;
    }

    err = 0;
    *n_accnts = cnt;
    printf("got to the end\n");
 out:
    if (err) {
        free(accnts);
        accnts = NULL;
    }
    return accnts;
}

/* on disk format:
   length prefixed strings
   length, string
   so:
   uid, domain, pwd
   length is 1 byte
 */
unsigned char *
pwdb_serialize(struct pwdb *db, int *blen)
{
    int bw, err;
    unsigned char *buf;
    struct pwdb_entry *entry;

    buf = NULL;
    bw = 0;
    entry = db->head;
    err = -1;

    while (entry) {
        unsigned char *p;
        int entry_len;
        size_t u_len, d_len, p_len;

        u_len = strlen(entry->accnt->uid);
        d_len = strlen(entry->accnt->domain);
        p_len = strlen(entry->pwd);
        entry_len = u_len + d_len + p_len + 3; /* 1 extra byte per string */
        printf("reallocing, buf is at: %p, bw is: %d\n", buf, bw);
        p = realloc(buf, sizeof(*buf) * (entry_len + bw));
        if (!p)
            goto out;
        buf = p;
        buf[bw++] = (unsigned char) u_len;
        memcpy(buf + bw, entry->accnt->uid, u_len);
        bw += u_len;
        buf[bw++] = (unsigned char) d_len;
        memcpy(buf + bw, entry->accnt->domain, d_len);
        bw += d_len;
        buf[bw++] = (unsigned char) p_len;
        memcpy(buf + bw, entry->pwd, p_len);
        bw += p_len;
        entry = entry->next;
    }
    printf("got to the end\n");
    err = 0;
    *blen = bw;
 out:
    if (err)
        free(buf);
    return buf;
}

char *
_str_from_buf(unsigned char *b, unsigned int slen)
{
    char *s;

    s = malloc(sizeof(*s) * (slen + 1));
    if (!s)
        goto out;
    memcpy(s, b, slen);
    s[slen] = '\0';
 out:
    return s;
}

/* b - ptr into buffer
   blen - total length of buff
 */
char *
_des_str_from_buf(unsigned char *b, unsigned int blen, int *br)
{
    char *s;
    int slen;

    s = NULL;
    slen = b[(*br)++];
    if (slen + *br > blen)
        goto out;
    s = _str_from_buf(b + *br, slen);
    if (!s)
        goto out;
    *br += slen;
 out:
    return s;
}


struct pwdb *
pwdb_deserialize(unsigned char *buf, unsigned int len)
{
    int err, br;
    struct pwdb *db;
    char *s;
    struct pwdb_entry *entry, **curr;
    struct pwdb_accnt *accnt;

    err = -1;
    br = 0;
    s = NULL;
    entry = NULL;
    accnt = NULL;
    db = malloc(sizeof(*db));
    if (!db)
        goto out;
    curr = &db->head;
    while (br < len) {
        int slen;

        printf("doing a loop\n");
        accnt = malloc(sizeof(*accnt));
        if (!accnt)
            goto out;
        entry = calloc(1, sizeof(*entry));
        if (!entry)
            goto out;

        s = _des_str_from_buf(buf, len, &br);
        if (!s)
            goto out;
        accnt->uid = s;

        s = _des_str_from_buf(buf, len, &br);
        if (!s)
            goto out;
        accnt->domain = s;

        s = _des_str_from_buf(buf, len, &br);
        if (!s)
            goto out;
        entry->pwd = s;

        entry->accnt = accnt;
        *curr = entry;
        printf("read: %s, %s, %s\n", accnt->uid, accnt->domain, entry->pwd);
        curr = &entry->next;
    }
    printf("all good for des\n");
    err = 0;
 out:
    if (err) {
        pwdb_destroy(db);
        free(s);
        free(entry);
        free(accnt);
        free(db);
        db = NULL;
    }
    return db;
}

/* just a test function, really */
void
pwdb_print_accnts(struct pwdb *db)
{
    struct pwdb_accnt *accnts;
    int cnt;

    accnts = pwdb_list(db, &cnt);
    if (accnts) {
        int i;
        for (i = 0; i < cnt; ++i)
            printf("user: %s, domain: %s\n", accnts[i].uid, accnts[i].domain);
    }
    free(accnts);
}

int
main(void)
{
    struct pwdb db, *dbp;
    char *res;

    dbp = &db;
    pwdb_init(dbp);

    res = pwdb_lookup(dbp, "john", "google");
    if (res)
        printf("lookup on empty db failed\n");

    if (pwdb_insert(dbp, "john", "google", "goodpass"))
        printf("insert failed\n");

    res = pwdb_lookup(dbp, "john", "google");
    printf("first lookup: %s\n", res);
    if (strcmp(res, "goodpass"))
        printf("lookup failed\n");

    if (pwdb_insert(dbp, "mary", "linkedin", "betterpass"))
        printf("FAIL: 2nd insert\n");

    res = pwdb_lookup(dbp, "john", "google");
    if (strcmp(res, "goodpass"))
        printf("FAIL: lookup\n");

    res = pwdb_lookup(dbp, "mary", "linkedin");
    if (strcmp(res, "betterpass"))
        printf("FAIL: lookup\n");

    if (pwdb_insert(dbp, "sue", "amazon", "bestpass"))
        printf("FAIL: insert\n");
    pwdb_print_accnts(dbp);

    unsigned char *buf;
    int blen;
    blen = 0;
    printf("serializing\n");
    buf = pwdb_serialize(dbp, &blen);
    if (!buf)
        printf("FAIL: serialize\n");

    int i;
    for (i = 0; i < blen; i++) {
        putchar(buf[i]);
    }
    printf("\n");
    struct pwdb *cpy;
    cpy = pwdb_deserialize(buf, blen);
    printf("deserialized:\n");
    if (cpy)
        pwdb_print_accnts(cpy);
}
