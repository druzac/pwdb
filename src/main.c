#include <stdio.h>
#include <argp.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>

#include "util.h"
#include "file_encrypt.h"
#include "db.h"
#include "pws.h"


#define MAX_PASS_LENGTH 64

static char *NO_DB_FILE = "missing db file argument";
static char *GET_PASS_FAIL = "couldn't get password";
static char *PASS_PROMPT = "enter db password:";

/* cmdline interface: */
/* insert password */
/* generate password */
/* fetch password */
/* list accounts in db */

/* so: needs 1 of: -i, -r, -g, -l */

/* or: */
/* -i insert */
/* -r retrieve */
/* -g gen */
/* -l list */

/* -b database, takes an arg */
/* for get, put */
/* -u user */
/* -t title */

/* gen */
/* -c length of generated password */
/* -s use symbols */

typedef enum {CMD_LIST, CMD_INSERT, CMD_RETRIEVE, CMD_GENERATE, CMD_INIT} cmd_t;

static struct argp_option options[] = {
    {"list", 'l', 0, 0, "list entries in db", 0},
    {"insert", 'i', 0, 0, "put new entry into db", 0},
    {"retrieve", 'r', 0, 0, "get a password from db", 0},
    {"generate", 'g', 0, 0, "generate a password", 0},
    {"initialize", 'z', 0, 0, "initialize a new db file", 0},

    {"symbol", 's', 0, 0, "allow symbols in password", 0},
    {"count", 'c', "COUNT", 0, "length for generated password", 0},
    {"user", 'u', "USER", 0, "username for entry", 0},
    {"title", 't', "TITLE", 0, "title for entry", 0},
    {"database", 'b', "DBFILE", 0, "password database file", 0},
    {0}
};

struct arguments
{
    char *user, *title, *dbfile;
    bool symbol;
    int count;
    cmd_t cmd;
    /* char *args[2];                /\* arg1 & arg2 *\/ */
    /* int silent, verbose; */
    /* char *output_file; */
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *argstt = state->input;
  char *p;
  int cnt;

  switch (key) {
  case 'l':
      if (argstt->cmd)
          argp_usage(state);
      argstt->cmd = CMD_LIST;
      break;
  case 'i':
      if (argstt->cmd)
          argp_usage(state);
      argstt->cmd = CMD_INSERT;
      break;
  case 'r':
      if (argstt->cmd)
          argp_usage(state);
      argstt->cmd = CMD_RETRIEVE;
      break;
  case 'g':
      if (argstt->cmd)
          argp_usage(state);
      argstt->cmd = CMD_GENERATE;
      break;
  case 'z':
      if (argstt->cmd)
          argp_usage(state);
      argstt->cmd = CMD_INIT;
      break;
  case 's':
      argstt->symbol = true;
      break;
  case 'c':
      /* try to convert number */
      cnt = (int) strtol(arg, (char **)NULL, 10);
      if (!cnt)
          argp_usage(state);
      argstt->count = cnt;
      break;
  case 'u':
      argstt->user = arg;
      break;
  case 't':
      argstt->title = arg;
      break;
  case 'b':
      argstt->dbfile = arg;
      break;
  default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static char doc[] =
    "pwd - password database";

static struct argp argp = {options, parse_opt, 0, doc};

int
cmd_init(struct arguments *args)
{
    int rc;
    char pass[MAX_PASS_LENGTH + 1];

    rc = -1;

    /* for this, we just need a dbfile arg */
    if (!args->dbfile) {
        fprintf(stderr, "%s\n", NO_DB_FILE);
        goto out;
    }

    if (get_pass(PASS_PROMPT, pass, MAX_PASS_LENGTH + 1, stdin)) {
        fprintf(stderr, "%s\n", GET_PASS_FAIL);
        goto out;
    }

    rc = pwsdb_create_new(pass, args->dbfile);
 out:
    return rc;
}

int
open_db(const char *dbpath, const char *mode, FILE **db, struct pwdb **pdb, char *pbuf, int pbuflen)
{
    FILE *ldb;
    char *buf;
    struct pwdb *lpwdb;
    int rc;
    unsigned int blen;

    rc = -1;
    ldb = NULL;
    buf = NULL;

    if (!dbpath) {
        fprintf(stderr, "%s\n", NO_DB_FILE);
        goto out;
    }

    ldb = fopen(dbpath, mode);
    if (!db) {
        perror("couldn't open db");
        goto out;
    }

    if (get_pass(PASS_PROMPT, pbuf, pbuflen, stdin)) {
        fprintf(stderr, "%s\n", GET_PASS_FAIL);
        goto out;
    }

    buf = decrypt_file(pbuf, strlen(pbuf), ldb, &blen);
    if (!buf) {
        fprintf(stderr, "couldn't open db\n");
        goto out;
    }

    lpwdb = pwdb_deserialize((unsigned char *) buf, blen);
    if (!lpwdb) {
        fprintf(stderr, "couldn't deserialize db\n");
        goto out;
    }

    *db = ldb;
    *pdb = lpwdb;
    rc = 0;

 out:
    if (rc)
        fclose(ldb);
    free(buf);
    return rc;
}

int
cmd_list(struct arguments *args)
{
    int rc;
    FILE *dbf;
    struct db *db;
    char pass[MAX_PASS_LENGTH + 1];
    
    rc = -1;
    db = NULL;
    dbf = NULL;

    if (!args->dbfile) {
        fprintf(stderr, "%s\n", NO_DB_FILE);
        goto out;
    }

    if (get_pass(PASS_PROMPT, pass, MAX_PASS_LENGTH + 1, stdin)) {
        fprintf(stderr, "%s\n", GET_PASS_FAIL);
        goto out;
    }

    if (!(dbf = fopen(args->dbfile, "r"))) {
        perror("failed to open db");
        goto out;
    }

    if (!(db = read_pwsdb(pass, dbf))) {
        goto out;
    }

    print_db(db);

    rc = 0;
 out:
    fclose(dbf);
    destroy_db(db);
    free(db);
    return rc;
}

/* TODO
   add an option to automatically generate a new password here
   */
int
cmd_insert(struct arguments *args)
{
    int rc;
    FILE *dbf;
    struct db *db;
    char master_pass[MAX_PASS_LENGTH + 1];
    char new_pass[MAX_PASS_LENGTH + 1];

    rc = -1;
    db = NULL;
    dbf = NULL;

    if (!args->title || !args->dbfile) {
        fprintf(stderr, "missing arguments for insert\n");
        goto out;
    }

    if (get_pass(PASS_PROMPT, master_pass, MAX_PASS_LENGTH + 1, stdin)) {
        fprintf(stderr, "%s\n", GET_PASS_FAIL);
        goto out;
    }

    if (!(dbf = fopen(args->dbfile, "r")) ||
        !(db = read_pwsdb(master_pass, dbf))) {
        perror("failed to open db");
        goto out;
    }

    if (get_pass("enter password for account:",
                 new_pass,
                 sizeof(new_pass)/sizeof(*new_pass),
                 stdin))
        goto out;

    if (pwsdb_add_record(db, args->title, new_pass)) {
        fprintf(stderr, "failed to insert into db\n");
        goto out;
    }

    if (pwsdb_save(db, master_pass, args->dbfile)) {
        fprintf(stderr, "couldn't save db");
        goto out;
    }

    rc = 0;
 out:
    fclose(dbf);
    destroy_db(db);
    free(db);

    return rc;
}

int
cmd_retrieve(struct arguments *args)
{
    int rc;

    rc = -1;

    return rc;
}

int
main(int argc, char **argv)
{
    struct arguments args;
    int rc;

    rc = -1;
    memset(&args, 0, sizeof(args));
    argp_parse(&argp, argc, argv, 0, 0, &args);
    switch (args.cmd) {
    case CMD_INIT:
        rc = cmd_init(&args);
        break;
    case CMD_LIST:
        rc = cmd_list(&args);
        break;
    case CMD_INSERT:
        rc = cmd_insert(&args);
        break;
    default:
        fprintf(stderr, "invalid command\n");
        goto out;
    }

 out:
    exit(rc);
}
