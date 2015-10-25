README
======

this is a passwordsafe (v3.30) compatible library and cli program.
there's also a start on an ncurses frontend, but it doesn't write to
the db file yet.  my goal was *nix compatibility, but this only
compiles on OS X right now.

it will choke on pwsafe db versions past v3.30, but that's
unnecessary.  the logic is all there to preserve fields it doesn't
understand across read, update, write operations.

currently, i am concerned about the security of writing to the
pasteboard/clipboard.  on OS X, at least, it appears that there's no
event system for the pasteboard, so any kind of malware that
periodically polls the pasteboard can steal all sorts of juicy
passwords if you use this program.

my current thinking is the only safe way to write a password manager
is to just embed yourself in the browser via an extension. this
project was more an exercise in using C and other greybeard technology
than an attempt to write a rock-solid password manager, so i've lost
momentum for now. another approach is to show the user the password,
and generate memorable passwords. this is weak to the
over-the-shoulder attack and irritating to users.

DEPENDENCIES
------------
* argp (can be installed with brew)
* xcode command line tools / whatever apple is calling their command line clang bundle now

BUILD
-----

libtomcrypt is a submodule to grab required crypto routines:
hmac and twofish, off the top of my head.
yeah it's a little weird, but twofish is a hard algorithm to find.

    git submodule update --init
    make

EXAMPLES
--------

these are just some of the commands.  there are additional options,
for example a primitive password generator.  the cli is not the most
intuitive - a rewrite to eliminate the argp dependency and introduce
subcommands would clean things up.

### init a new db: ###

    $ ./pwdb -z -b test_db
      enter db password:****

### add a new entry: ###

    $ ./pwdb --insert -t blah -b test_db
      enter db password:****
      enter password for account:*******

### list all entries in the db: ###

    $ ./pwdb --list -b test_db
      enter db password:****
      version: 0x310
      blah:
        password: blah
        uuid: A80BFA5F-5ECE-4E7E-8EEA-BAB41B202AA1

yes, it just dumps your passwords to stdout. probably not super usable yet.

### write password to pasteboard: ###

    $ ./pwdb -r --uuid A80BFA5F-5ECE-4E7E-8EEA-BAB41B202AA1 -b test_db
      enter db password:****
      change count is: 1335

the password should now be in your clipboard
