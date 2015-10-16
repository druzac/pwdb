#include <menu.h>
#include <form.h>
#include <ncurses.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "util.h"
#include "pws.h"
#include "clipb.h"
#include "pwcurs.h"

#define WIDTH 64
#define N_FIELDS 6

#define STARTX 15
#define STARTY 4

static
int
record_screen(struct record *rec, FORM *rec_form, FIELD **fields)
{
    int rc, ch;
    uuid_string_t uuid_s;

    rc = -1;

    uuid_unparse(rec->uuid, uuid_s);
    set_field_buffer(fields[0], 0, rec->title);
    set_field_buffer(fields[1], 0, rec->username);
    set_field_buffer(fields[2], 0, rec->password);
    set_field_buffer(fields[3], 0, rec->url);
    set_field_buffer(fields[4], 0, uuid_s);

    post_form(rec_form);
    form_driver(rec_form, REQ_END_LINE);
    while ((ch = getch()) != KEY_F(1)) {
        switch (ch) {
        case KEY_DOWN:
            form_driver(rec_form, REQ_NEXT_FIELD);
            form_driver(rec_form, REQ_END_LINE);
            break;
        case KEY_UP:
            form_driver(rec_form, REQ_PREV_FIELD);
            form_driver(rec_form, REQ_END_LINE);
            break;
        default:
            break;
        }
    }
    unpost_form(rec_form);

    rc = 0;
    return rc;
}

int
pwcurs_start(const char *dbpath, char *pass, struct db *db)
{
    int rc, e_cnt, c, i;
    struct record *rec;
    MENU *entries_menu;
    ITEM **rec_items, *curr_item;
    FORM *rec_form;
    FIELD *fields[N_FIELDS];

    rc = -1;
    e_cnt = 0;
    rec_items = NULL;
    entries_menu = NULL;
    rec_form = NULL;
    memset(fields, 0, sizeof(fields[0]) * N_FIELDS);

    /* TODO do these have error codes? */
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    for (i = 0; i < N_FIELDS - 1; ++i) {
        fields[i] = new_field(1, WIDTH, STARTY + i * 2, STARTX, 0, 0);
        /* TODO check rc */
    }

    rec_form = new_form(fields);
    /* TODO check rc */

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
            rec_items[i] = new_item(rec->title, "");
            set_item_userptr(rec_items[i++], rec);
        } while ((rec = rec->next) != db->records);
    }

    rec_items[e_cnt] = NULL;

    /* TODO check null */
    entries_menu = new_menu((ITEM **) rec_items);
    mvprintw(LINES - 2, 0, "q to exit");
    post_menu(entries_menu);

    /* event loop for entries menu */
    while ((c = getch()) != 'q') {
        switch (c) {
        case KEY_DOWN:
            menu_driver(entries_menu, REQ_DOWN_ITEM);
            break;
        case KEY_UP:
            menu_driver(entries_menu, REQ_UP_ITEM);
            break;
        case 10:
            curr_item = current_item(entries_menu);
            rec = item_userptr(curr_item);
            unpost_menu(entries_menu);
            record_screen(rec, rec_form, fields);
            post_menu(entries_menu);
            break;
        }
    }

    unpost_menu(entries_menu);
    rc = 0;
 out:
    /* TODO error path is questionable */
    /* what happens with null args? */

    free_form(rec_form);
    for (i = 0; i < N_FIELDS - 1; ++i)
        free_field(fields[i]);

    free_menu(entries_menu);
    for (i = 0; i < e_cnt; ++i)
        free_item(rec_items[i]);
    free(rec_items);
    endwin();

    return rc;
}
