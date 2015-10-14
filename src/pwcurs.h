#ifndef _PWDB_CURS_
#define _PWDB_CURS_

/* interactive terminal app using ncurses */

int
pwcurs_start(const char *dbpath, char *pass, struct db *db);

#endif
