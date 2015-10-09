#include <CoreFoundation/CoreFoundation.h>
#include <objc/objc.h>
#include <objc/objc-runtime.h>

#include "clipb.h"

/* TODO
   just prints to stdout now
   */
int pb_read() {
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
    return rc;
}
