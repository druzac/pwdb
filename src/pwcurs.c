#include <menu.h>
#include <ncurses.h>
#include <stdlib.h>
#include <errno.h>

#include "util.h"
#include "pws.h"
#include "clipb.h"
#include "pwcurs.h"

/* first crack
   just list the title of every entry in the db
   */

int
pwcurs_start(const char *dbpath, char *pass, struct db *db)
{
    int rc, e_cnt, c, i;
    struct record *rec;
    MENU *entries_menu;
    ITEM **rec_items;

    rc = -1;
    e_cnt = 0;
    rec_items = NULL;
    entries_menu = NULL;

    /* TODO do these have error codes? */
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    rec = db->records;
    if (db->records)
        do {
            ++e_cnt;
        } while ((rec = rec->next) != db->records);

    rec_items = malloc((e_cnt + 1) * sizeof(ITEM *));
    if (!rec_items)
        goto out;

    if ((rec = db->records)) {
        i = 0;
        do {
            /* TODO check null */
            rec_items[i++] = new_item(rec->title, "");
        } while ((rec = rec->next) != db->records);
    }

    rec_items[e_cnt] = NULL;

    entries_menu = new_menu((ITEM **) rec_items);
    mvprintw(LINES - 2, 0, "q to exit");
    post_menu(entries_menu);
    refresh();

    /* event loop for entries menu */
    while ((c = getch()) != 'q') {
        switch (c) {
        case KEY_DOWN:
            menu_driver(entries_menu, REQ_DOWN_ITEM);
            break;
        case KEY_UP:
            menu_driver(entries_menu, REQ_UP_ITEM);
            break;
        }
    }

    rc = 0;
 out:
    /* TODO error path is questionable */
    /* what happens with null args? */
    unpost_menu(entries_menu);
    free_menu(entries_menu);
    for (i = 0; i < e_cnt; ++i)
        free_item(rec_items[i]);
    free(rec_items);
    endwin();
    return rc;
}
