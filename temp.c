/*
 *	Author: Mihir J. Vegad
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

static int hello_init(void)
{
	char string[] = "R 1:2:3:4:5:6 1.2.3.4";
    const char *stringp = string;
    const char *delim = " ";
    char *token;

    // stringp is updated to point to the next token 'B'
    token = strsep(&stringp, delim);
    printk(KERN_ALERT "token = '%s', ", token);

    // stringp is updated to point to the next token 'C'
    token = strsep(&stringp, delim);
    printk(KERN_ALERT "token = '%s', ", token);

    // In case no delimiter was found, stringp is made NULL.
    token = strsep(&stringp, delim);
    printk(KERN_ALERT "token = '%s', ", token);


        printk(KERN_ALERT "tfilter working.\n");
        return 0;

}

static void hello_exit(void)
{
	printk(KERN_ALERT "exiting testing module.\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("MIHIR");
MODULE_DESCRIPTION("Testing module");



