#include <CoreFoundation/CoreFoundation.h>
#include <objc/objc.h>
#include <objc/objc-runtime.h>
#include <stdio.h>

/* how to compile: gcc -framework Cocoa -o test1 test1.c */

extern int NSRunAlertPanel(CFStringRef strTitle, CFStringRef strMsg,
                           CFStringRef strButton1, CFStringRef strButton2, 
                           CFStringRef strButton3, ...);

/* NSPasteboard *pasteboard = <#Get a pasteboard#>;  */

/* NSArray *classes = [[NSArray alloc] initWithObjects:[NSString class], nil]; */

/* NSDictionary *options = [NSDictionary dictionary]; */

/* NSArray *copiedItems = [pasteboard readObjectsForClasses:classes options:options]; */

/* can use core foundation to obviate a lot of this boilerplate shit
   hurray!
*/

int pb_read() {
    /* try to print something from pasteboard to standard out */
    id pbc, gpb;
    id arr, dict;
    id class_arr, res_arr;
    int rc;
    Class str_c;

    rc = -1;
    pbc = (id)objc_getClass("NSPasteboard");
    if (!pbc)
        goto out;

    str_c = objc_getClass("NSString");
    if (!str_c)
        goto out;
    class_arr = (id)objc_getClass("NSArray");
    if (!class_arr) {
        printf("ack\n");
        goto out;
    }
    class_arr = objc_msgSend(class_arr, sel_registerName("alloc"));
    if (!class_arr) {
        printf("ack1\n");
        goto out;
    }
    class_arr = objc_msgSend(class_arr, sel_registerName("initWithObjects:"), str_c, NULL);
    if (!class_arr) {
        printf("ack2\n");
        goto out;
    }
    dict = objc_msgSend((id)objc_getClass("NSDictionary"), sel_registerName("dictionary"));
    if (!dict) {
        printf("dict\n");
        goto out;
    }
    gpb = objc_msgSend(pbc, sel_registerName("generalPasteboard"));
    if (!gpb) {
        printf("gpb\n");
        goto out;
    }
    res_arr = objc_msgSend(gpb,
                           sel_registerName("readObjectsForClasses:options:"), class_arr, dict);
    if (!res_arr) {
        printf("gpb read\n");
        goto out;
    }
    id res;
    res = objc_msgSend(res_arr,
                       sel_registerName("objectAtIndex:"), 0);
    if (!res) {
        printf("getting res\n");
        goto out;
    }
    printf("I got: %s\n", object_getClassName(res));
    char *finally;
    finally = (char *)objc_msgSend(res, sel_registerName("UTF8String"));
    if (finally)
        printf("got %s\n", finally);

    rc = 0;
 out:
    if (rc)
        printf("failed\n");
    else
        printf("got to the end\n");
    return rc;
}

int pb_write(char *s)
{
    id pbc, gpb;
    id arr;
    int rc;
    Class str_c, arr_c;
    /* NSPasteboard *pasteboard = [NSPasteboard generalPasteboard]; */
    /* NSInteger changeCount = [pasteboard clearContents]; */
    /* NSArray *objectsToCopy = <#An array of objects#>; */
    /* BOOL OK = [pasteboard writeObjects:objectsToCopy]; */
    rc = -1;
    pbc = (id)objc_getClass("NSPasteboard");
    if (!pbc)
        goto out;
    gpb = objc_msgSend(pbc, sel_registerName("generalPasteboard"));
    int cc;
    cc = (int) objc_msgSend(gpb, sel_registerName("clearContents"));
    printf("change count is: %d\n", cc);

    /* id  */
    id nsstr;
    str_c = objc_getClass("NSString");
    nsstr = objc_msgSend((id)str_c, sel_registerName("alloc"));
    nsstr = objc_msgSend(nsstr,
                         sel_registerName("initWithUTF8String:"),
                         s);
    if (!nsstr)
        goto out;
    arr_c = objc_getClass("NSArray");
    arr = objc_msgSend((id)arr_c, sel_registerName("alloc"));
    arr = objc_msgSend(arr,
                       sel_registerName("initWithObjects:"),
                       nsstr,
                       NULL);
    BOOL ok;
    ok = (BOOL) objc_msgSend(gpb,
                             sel_registerName("writeObjects:"),
                             arr);
    rc = 0;
 out:
    if (rc)
        printf("failed\n");
    else
        printf("got to the end\n");
    return rc;
}

int main(int argc, char** argv)
{
    id app = NULL;
    id pool = (id)objc_getClass("NSAutoreleasePool");
    id alert = NULL;
    int result;
    int rc;

    rc = -1;
    if (!pool)
    {
        printf("Unable to get NSAutoreleasePool!\nAborting\n");
        return -1;
    }
    pool = objc_msgSend(pool, sel_registerName("alloc"));
    if (!pool)
    {
        printf("Unable to create NSAutoreleasePool...\nAborting...\n");
        return -1;
    }
    pool = objc_msgSend(pool, sel_registerName("init"));

    /* app = objc_msgSend((id)objc_getClass("NSApplication"), */
    /*                    sel_registerName("sharedApplication")); */

    /* alert = (id)objc_getClass("NSAlert"); */
    /* if (!alert) { */
    /*     printf("what the beef, no alert\n"); */
    /* } */
    /* alert = objc_msgSend(alert, sel_registerName("alloc")); */
    /* if (!alert) { */
    /*     printf("ack1\n"); */
    /* } */
    /* alert = objc_msgSend(alert, sel_registerName("init")); */
    /* result = NSRunAlertPanel(CFSTR("Testing"), */
    /*                 CFSTR("This is a simple test to display NSAlertPanel."), */
    /*                 CFSTR("OK"), NULL, NULL); */
    /* printf("got back: %d\n", result); */

    /* pb_read(); */
    if (argc != 2) {
        printf("usage: <me> str-to-paste\n");
        goto out;
    }
        
    pb_write(argv[1]);
    rc = 0;
 out:
    
    objc_msgSend(pool, sel_registerName("release"));
    return rc;
}
