#include <stdio.h>
#include <argp.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

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
/* -d domain */
/* -c length of generated password */

/* gen */
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
    {"domain", 'd', "DOMAIN", 0, "domain for entry", 0},
    {"database", 'b', "DBFILE", 0, "password database file", 0},
    {0}
};

struct arguments
{
    char *user, *domain, *dbfile;
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
  case 'd':
      argstt->domain = arg;
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

/* struct arguments */
/* { */
/*     char *user, *domain, *dbfile; */
/*     bool symbol; */
/*     int count; */
/*     cmd_t cmd; */
/*     /\* char *args[2];                /\\* arg1 & arg2 *\\/ *\/ */
/*     /\* int silent, verbose; *\/ */
/*     /\* char *output_file; *\/ */
/* }; */

int
main(int argc, char **argv)
{
    struct arguments args;
    memset(&args, 0, sizeof(args));
    argp_parse(&argp, argc, argv, 0, 0, &args);
    printf("args:\n"
           "user: %s\n"
           "domain: %s\n"
           "dbfile: %s\n"
           "count: %d\n"
           "cmd: %d\n",
           args.user ?: "",
           args.domain ?: "",
           args.dbfile ?: "",
           args.count,
           args.cmd);

    
    exit(0);
}
