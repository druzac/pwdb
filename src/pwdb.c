#include <stdio.h>
#include <argp.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>

#include "util.h"
#include "pws.h"
#include "clipb.h"
#include "pwcurs.h"

#define MAX_PASS_LENGTH 64
#define DEFAULT_PASS_LENGTH 13

#define CLI_URL_CODE 256
#define CLI_INTERACTIVE_CODE 257

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
/* -k kill  */


/* -b database, takes an arg */
/* for get, put */
/* -u user */
/* -t title */

/* gen */
/* -c length of generated password */
/* -s use symbols */

typedef enum {CMD_LIST,
              CMD_INSERT,
              CMD_RETRIEVE,
              CMD_GENERATE,
              CMD_INIT,
              CMD_KILL,
              CMD_INTERACTIVE} cmd_t;

static struct argp_option options[] = {
    {"list", 'l', 0, 0, "list entries in db", 0},
    {"insert", 'i', 0, 0, "put new entry into db", 0},
    {"retrieve", 'r', 0, 0, "get a password from db", 0},
    {"generate", 'g', 0, 0, "generate a password", 0},
    {"init", 'z', 0, 0, "initialize a new db file", 0},
    {"kill", 'k', 0, 0, "remove an entry from the db", 0},
    {"interactive", CLI_INTERACTIVE_CODE, 0, 0, "run ncurses app", 0},

    {"symbol", 's', 0, 0, "allow symbols in password", 0},
    {"count", 'c', "COUNT", 0, "length for generated password", 0},
    {"user", 'u', "USER", 0, "username for entry", 0},
    {"url", CLI_URL_CODE, "URL", 0, "url for entry", 0},
    {"uuid", 'd', "UUID", 0, "uuid for entry", 0},
    {"title", 't', "TITLE", 0, "title for entry", 0},
    {"database", 'b', "DBFILE", 0, "password database file", 0},
    {0}
};

struct arguments
{
    char *user, *title, *dbfile, *url;
    bool symbol;
    bool gen_pass;
    uuid_t uuid;
    int count;
    cmd_t cmd;
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
  case 'k':
      if (argstt->cmd)
          argp_usage(state);
      argstt->cmd = CMD_KILL;
      break;
  case 'r':
      if (argstt->cmd)
          argp_usage(state);
      argstt->cmd = CMD_RETRIEVE;
      break;
  case 'g':
      argstt->gen_pass = true;
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
  case 'd':
      if (uuid_parse(arg, argstt->uuid))
          argp_usage(state);
  case 't':
      argstt->title = arg;
      break;
  case 'b':
      argstt->dbfile = arg;
      break;
  case CLI_URL_CODE:
      argstt->url = arg;
      break;
  case CLI_INTERACTIVE_CODE:
      if (argstt->cmd)
          argp_usage(state);
      argstt->cmd = CMD_INTERACTIVE;
      break;
  default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static char doc[] = "pwd - password database";

static struct argp argp = {options, parse_opt, 0, doc};

int
cmd_init(struct arguments *args)
{
    int rc;
    char pass[MAX_PASS_LENGTH + 1];

    rc = -1;

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
cmd_list(struct arguments *args)
{
    int rc;
    struct db *db;
    char pass[MAX_PASS_LENGTH + 1];

    rc = -1;
    db = NULL;

    if (!args->dbfile) {
        fprintf(stderr, "%s\n", NO_DB_FILE);
        goto out;
    }

    if (get_pass(PASS_PROMPT, pass, MAX_PASS_LENGTH + 1, stdin)) {
        fprintf(stderr, "%s\n", GET_PASS_FAIL);
        goto out;
    }

    if (!(db = pwsdb_open(pass, args->dbfile))) {
        fprintf(stderr, "bad list\n");
        goto out;
    }

    print_db(db);

    rc = 0;
 out:
    destroy_db(db);
    return rc;
}

int
cmd_insert(struct arguments *args)
{
    int rc;
    struct db *db;
    char master_pass[MAX_PASS_LENGTH + 1];
    char new_pass[MAX_PASS_LENGTH + 1];
    uuid_t uuid;

    rc = -1;
    db = NULL;

    if (!args->title || !args->dbfile) {
        fprintf(stderr, "missing arguments for insert\n");
        goto out;
    }

    if (get_pass(PASS_PROMPT, master_pass, MAX_PASS_LENGTH + 1, stdin)) {
        fprintf(stderr, "%s\n", GET_PASS_FAIL);
        goto out;
    }

    if (!(db = pwsdb_open(master_pass, args->dbfile))) {
        perror("failed to open db");
        goto out;
    }

    if (args->gen_pass) {
        if (gen_pass(new_pass, DEFAULT_PASS_LENGTH, true)) {
            fprintf(stderr, "failed to gen pass\n");
            goto out;
        }
    } else if (get_pass("enter password for account:",
                 new_pass,
                 sizeof(new_pass)/sizeof(*new_pass),
                 stdin))
        goto out;

    if (pwsdb_add_record(db, args->title, new_pass, args->user, args->url, uuid)) {
        fprintf(stderr, "failed to insert into db\n");
        goto out;
    }

    if (pwsdb_save(db, master_pass, args->dbfile)) {
        fprintf(stderr, "couldn't save db\n");
        goto out;
    }

    rc = 0;
 out:
    destroy_db(db);
    free(db);
    return rc;
}

int
cmd_retrieve(struct arguments *args)
{
    int rc;
    struct db *db;
    char pass[MAX_PASS_LENGTH + 1], *fndpass;

    rc = -1;
    db = NULL;

    if (uuid_is_null(args->uuid) || !args->dbfile) {
        fprintf(stderr, "missing arguments for retrieve\n");
        goto out;
    }

    if (get_pass(PASS_PROMPT, pass, MAX_PASS_LENGTH + 1, stdin)) {
        fprintf(stderr, "%s\n", GET_PASS_FAIL);
        goto out;
    }

    if (!(db = pwsdb_open(pass, args->dbfile))) {
        fprintf(stderr, "couldn't open db\n");
        goto out;
    }

    if (!(fndpass = pwsdb_get_pass(db, args->uuid))) {
        fprintf(stderr, "couldn't find pass\n");
        goto out;
    }

    pb_write(fndpass);

    rc = 0;
 out:
    destroy_db(db);
    free(db);
    return rc;
}

int
cmd_kill(struct arguments *args)
{
    int rc;
    struct db *db;
    char pass[MAX_PASS_LENGTH + 1];

    rc = -1;
    db = NULL;

    if (uuid_is_null(args->uuid) || !args->dbfile) {
        fprintf(stderr, "missing arguments for kill\n");
        goto out;
    }

    if (get_pass(PASS_PROMPT, pass, MAX_PASS_LENGTH + 1, stdin)) {
        fprintf(stderr, "%s\n", GET_PASS_FAIL);
        goto out;
    }

    if (!(db = pwsdb_open(pass, args->dbfile))) {
        fprintf(stderr, "couldn't open db\n");
        goto out;
    }

    if (pwsdb_remove_record(db, args->uuid)) {
        fprintf(stderr, "failed to remove entry from db\n");
        goto out;
    }

    if (pwsdb_save(db, pass, args->dbfile)) {
        fprintf(stderr, "couldn't save db");
        goto out;
    }

    rc = 0;
 out:
    destroy_db(db);
    free(db);
    return rc;

}

int
cmd_interactive(struct arguments *args)
{
    int rc;
    struct db *db;
    char pass[MAX_PASS_LENGTH + 1];

    rc = -1;
    db = NULL;

    if (!args->dbfile) {
        fprintf(stderr, "missing db path\n");
        goto out;
    }

    if (get_pass(PASS_PROMPT, pass, MAX_PASS_LENGTH + 1, stdin)) {
        fprintf(stderr, "%s\n", GET_PASS_FAIL);
        goto out;
    }

    if (!(db = pwsdb_open(pass, args->dbfile))) {
        fprintf(stderr, "couldn't open db\n");
        goto out;
    }

    rc = pwcurs_start(args->dbfile, pass, db);

    print_db(db);

 out:
    destroy_db(db);
    free(db);
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
    case CMD_RETRIEVE:
        rc = cmd_retrieve(&args);
        break;
    case CMD_KILL:
        rc = cmd_kill(&args);
        break;
    case CMD_INTERACTIVE:
        rc = cmd_interactive(&args);
        break;
    default:
        fprintf(stderr, "invalid command\n");
        goto out;
    }

 out:
    return rc;
}
