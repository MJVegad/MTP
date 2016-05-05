/*
 *	Author: Mihir J. Vegad
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/neighbour.h>
#include <net/arp.h>
#include <linux/export.h>
#include <linux/rculist.h>
#include <linux/time.h>
#include <linux/random.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/kfifo.h>


int intToBinary(int num);

void tostring(char str[], int num);

/* mutex for middlebox state linked list access */
struct mutex mbllmutex;

extern int (*bridge_filter)(struct sk_buff *);

/* To get commnad from middlebox */
extern struct Mbinfo* mymb; 

// head node of middlebox linked list
extern struct mbState mbState_list;
//EXPORT_SYMBOL(mbState_list);

/* return value - 1 (drop the packet) | 0 (forward the packet) */
static int do_bfilter(struct sk_buff *skb)
{
	struct iphdr* iph = ip_hdr(skb);
	struct ethhdr* mh = eth_hdr(skb);
	struct tcphdr* tcph = tcp_hdr(skb);

	// traversing linkedlist of the registered middleboxes 
	struct list_head *ptr;
	struct mbState *entry;

	list_for_each(ptr,&mbState_list.list) {
		entry = list_entry(ptr, struct mbState, list);
		//printk(KERN_ALERT "bfilter_check for dest:%s\n", &(entry->macaddr));
        //printk(KERN_ALERT "MAC Addr matched:%d\n", strcmp(entry->macaddr,mh->h_dest));
        unsigned char t1[18];
        snprintf(t1,18,"%pM",&(mh->h_dest));
		if (strcmp(entry->macaddr,t1)==0)
		{
            printk(KERN_ALERT "MAC Addr matched:%pM\n", &(entry->macaddr));
			if(entry->ipfilters==0 && entry->macfilters==0 && entry->ipfilters==0)
			{
				return 0;
			}	
			else
			{
				//  To match ip header fields 
				if(entry->ipfilters!=0)
				{
                    printk(KERN_ALERT "ipfilter not zero for dest:%pM\n", &(entry->macaddr));
					int temp = intToBinary(entry->ipfilters);
					char filters[5];
					tostring(filters, temp);  

                    printk(KERN_ALERT "ipfilters:%s\n", filters);
					if (filters[3]=='1') {
                        unsigned char t[16];
                        snprintf(t,16,"%pI4",&(iph->saddr));
						if (strcmp(entry->srcip,t)!=0) 
							return 0;							
					}
					if (filters[2]=='1') {
                        printk(KERN_ALERT "dest ip address filter set for:%pM\n", &(entry->macaddr));
                        unsigned char t[16];
                        snprintf(t,16,"%pI4",&(iph->daddr));
                        if (strcmp(entry->ipaddr,t)!=0)
                            return 0;
                    }
					if (filters[1]=='1') {
                        if (entry->tos != iph->tos)
                            return 0;
                    }
					if (filters[0]=='1') {
                        if (entry->protocol != iph->protocol)
                            return 0;
                    }
				}

				//  To match Mac header fields 
				 if(entry->macfilters!=0)
                {
                    int temp = intToBinary(entry->macfilters);
                    char filters[5];
                    tostring(filters, temp);
                    if (filters[3]=='1') {
                        unsigned char t1[18];
                        snprintf(t1,18,"%pM",&(mh->h_source));
                        if (strcmp(entry->srcmac,t1)!=0)
                            return 0;
                    }
                    if (filters[2]=='1') {
                        //if (strcmp(entry->macaddr,mh->h_dest)!=0)
                        //    return 0;
                    }
                    if (filters[1]=='1') {
                        if (entry->ethprotocol != mh->h_proto)
                            return 0;
                    }    
                }

				//  To match Tcp/Udp header fields 
				 if(entry->tcpfilters!=0)
                {
                    int temp = intToBinary(entry->tcpfilters);
                    char filters[5];
                    tostring(filters, temp);
                    if (filters[3]=='1') {
                        if (tcph->source != entry->srcport)
                            return 0;
                    }
                    if (filters[2]=='1') {
                        if (tcph->dest != entry->dstport)
                            return 0;
                    }
                }
            printk(KERN_ALERT "packet dropped by bfilter.\n");    
			return 1;
			}
		}
	}	

	//printk(KERN_ALERT "IP header details==> SrcIP:%pI4, DstIP:%pI4, TOS:%c, PROTOCOL:%c, TTL:%c\n", &(iph->saddr), &(iph->daddr), iph->tos, iph->protocol, iph->ttl);
	//printk(KERN_ALERT "MAC header details==> SrcMAC:%pM, DstMAC:%pM, PROTOCOL_TYPE:%d\n", &(mh->h_source), &(mh->h_dest), mh->h_proto);
        //printk(KERN_ALERT "TRANSPORT header details==> Srcport:%d, Dstport:%d, Sequence no.:%2d, Window:%d\n", tcph->source, tcph->dest, tcph->seq, tcph->window);

	return 0;
}
/*static int do_bfilter(struct sk_buff *skb)
{
    struct iphdr* iph = ip_hdr(skb);
    struct ethhdr* mh = eth_hdr(skb);
    struct tcphdr* tcph = tcp_hdr(skb);

    char *tok = "52:54:00:12:34:56";
    unsigned char macaddr[18];
    unsigned char t[18];
    snprintf(t,18,"%pM",&(mh->h_dest));
    strcpy(macaddr,tok);

    printk(KERN_ALERT "macaddr:%s\n",macaddr);
    printk(KERN_ALERT "t:%s, strcmp:%d\n",t,strcmp(macaddr,t));
    //printk(KERN_ALERT "strcmp:%d\n",strcmp(macaddr,mh->h_dest));
    if(strcmp(macaddr,t)==0)
        return 1;

    return 0;
} */   


static int filter_init(void)
{
        //To initialize the mutex for the linked list
	//mutex_init(&mbllmutex);

	//To initialize the mbState linked list;
	INIT_LIST_HEAD(&mbState_list.list);
	printk("Linked list initialized.\n");
    bridge_filter = do_bfilter;
    return 0;
}

static void filter_exit(void)
{
        bridge_filter = NULL;
}


/* utility functions */
int intToBinary(int num)
{
    int remainder, base = 1, binary = 0;
    
    while (num > 0)
    {
        remainder = num % 2;
        binary = binary + remainder * base;
        num = num / 2;
        base = base * 10;
    }
    return binary;
}

void tostring(char str[], int num)
{
    int i, rem, len = 0, n;
    char filters[5];
    n = num;
    while (n != 0)
    {
        len++;
        n /= 10;
    }
    for (i = 0; i < len; i++)
    {
        rem = num % 10;
        num = num / 10;
        filters[len - (i + 1)] = rem + '0';
    }
    filters[len] = '\0';

    if(strlen(filters)<4)
    {
        int t2=4-strlen(filters);
        int t3,t4=0;
        for(t3=0;t3<t2;t3++)
            str[t3]='0';
        for(;t3<4;t3++)
        {    
            str[t3]=filters[t4];
            t4++;
        }    
        str[t3]='\0';
    }  
    else
        strcpy(str,filters);  
}


/*void tostring(char str[], int num)
{
    int i, rem, len = 0, n;

    n = num;
    while (n != 0)
    {
        len++;
        n /= 10;
    }
    for (i = 0; i < len; i++)
    {
        rem = num % 10;
        num = num / 10;
        str[len - (i + 1)] = rem + '0';
    }
    str[len] = '\0';
}*/

module_init(filter_init);
module_exit(filter_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("MIHIR");
MODULE_DESCRIPTION("Filter testing.");

