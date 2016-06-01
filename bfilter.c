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
//extern struct mutex mbllmutex;

extern int (*bridge_filter)(struct sk_buff *);

/* To get commnad from middlebox */
extern struct Mbinfo* mymb; 

// head node of middlebox linked list
extern struct mbState mbState_list;
//EXPORT_SYMBOL(mbState_list);

extern struct mbState1 mbState_list1;

/* return value - 1 (drop the packet) | 0 (forward the packet) */
static int do_bfilter(struct sk_buff *skb)
{
	struct iphdr* iph = ip_hdr(skb);
	struct ethhdr* mh = eth_hdr(skb);
	struct tcphdr* tcph = tcp_hdr(skb);

	//To filter with percentage
/*	float filterpercentage = 50;
        int fp = (int)filterpercentage;
	long tem=0,decider=0;
        tem=(current_kernel_time()).tv_nsec;
        decider = tem % 100;
*/
    

	// traversing linkedlist of the registered middleboxes 
	struct list_head *ptr;
	struct mbState *entry;

	list_for_each(ptr,&mbState_list.list) {
		entry = list_entry(ptr, struct mbState, list);
		//printk(KERN_ALERT "bfilter_check for dest:%s\n", &(entry->macaddr));
        //printk(KERN_ALERT "MAC Addr matched:%d\n", strcmp(entry->macaddr,mh->h_dest));
        unsigned char t1[18];
        snprintf(t1,18,"%pM",&(mh->h_dest));

        // flags for non-recursive mutexes
        int m1=0;
        mutex_lock(&entry->node);
		if (strcmp(entry->macaddr,t1)==0)
		{
            m1=1;
            mutex_unlock(&entry->node);
           // printk(KERN_ALERT "MAC Addr matched:%pM\n", &(entry->macaddr));
            mutex_lock(&entry->node);
			if(entry->ipfilters==0 && entry->macfilters==0 && entry->ipfilters==0)
			{
                mutex_unlock(&entry->node);
				return 0;
			}	
			else
			{
				//  To match ip header fields
                int m3=0; 
				if(entry->ipfilters!=0)
				{
                    m3=1;
                    mutex_unlock(&entry->node);
                   // printk(KERN_ALERT "ipfilter not zero for dest:%pM\n", &(entry->macaddr));
                    mutex_lock(&entry->node);
					int temp = intToBinary(entry->ipfilters);
                    mutex_unlock(&entry->node);
					char filters[5];
					tostring(filters, temp);  

                   // printk(KERN_ALERT "ipfilters:%s\n", filters);
					if (filters[3]=='1') {
                      //  printk(KERN_ALERT "source ip address filter set for:%pM\n", &(entry->macaddr));
                        unsigned char t[16];
                        snprintf(t,16,"%pI4",&(iph->saddr));
                        int m2=0;
                        mutex_lock(&entry->node);
						if (strcmp(entry->srcip,t)!=0)
                        { 
                            m2=1;
                            mutex_unlock(&entry->node);
							return 0;
                        }
                        if (m2==0)
                            mutex_unlock(&entry->node);    							
					}
					if (filters[2]=='1') {
                        //printk(KERN_ALERT "dest ip address filter set for:%pM\n", &(entry->macaddr));
                        unsigned char t[16];
                        snprintf(t,16,"%pI4",&(iph->daddr));
                        int m2=0;
                        mutex_lock(&entry->node);
                        if (strcmp(entry->ipaddr,t)!=0)
                        {
                            m2=1;
                            mutex_unlock(&entry->node);    
                            return 0;
                        }    
                        if(m2==0)
                            mutex_unlock(&entry->node);
                    }
					if (filters[1]=='1') {
                        int m2=0;
                        mutex_lock(&entry->node);
                        if (entry->tos != iph->tos)
                        {
                            m2=1;
                            mutex_unlock(&entry->node);    
                            return 0;
                        }    
                        if (m2==0)
                            mutex_unlock(&entry->node);
                    }
					if (filters[0]=='1') {
                        //printk(KERN_ALERT "IP protocol filter set for:%pM\n", &(entry->macaddr));
                        //printk(KERN_ALERT "ll val:%ld, iph->proto:%ld\n", entry->protocol, iph->protocol);
                        // flags for non-recursive mutexes
                        int m2=0;   
                        mutex_lock(&entry->node);
                        if (entry->protocol != iph->protocol)
                        {
                            m2=1;
                            mutex_unlock(&entry->node);    
                            return 0;
                        }    
                        if (m2==0)
                            mutex_unlock(&entry->node);
                    }
				}

				//  To match Mac header fields
                int m4=0;
                if(m3==1) 
                    mutex_lock(&entry->node);                    
				 if(entry->macfilters!=0)
                {
                     m4=1;  
                    int temp = intToBinary(entry->macfilters);
                    mutex_unlock(&entry->node);
                    char filters[5];
                    tostring(filters, temp);
                    if (filters[3]=='1') {
                        unsigned char t1[18];
                        snprintf(t1,18,"%pM",&(mh->h_source));
                        int m2=0;
                        mutex_lock(&entry->node);
                        if (strcmp(entry->srcmac,t1)!=0)
                        {
                            m2=1;
                            mutex_unlock(&entry->node);
                            return 0;
                        }        
                        if(m2==0)
                            mutex_unlock(&entry->node);
                    }
                    if (filters[2]=='1') {
                        //if (strcmp(entry->macaddr,mh->h_dest)!=0)
                        //    return 0;
                    }
                    if (filters[1]=='1') {
                        int m2=0;
                        mutex_lock(&entry->node);
                        if (entry->ethprotocol != mh->h_proto)
                        {
                            m2=1;
                            mutex_unlock(&entry->node);    
                            return 0;
                        }    
                        if(m2==0)
                            mutex_unlock(&entry->node);
                    }    
                }

				//  To match Tcp/Udp header fields
                int m5=0;
                if(m4==1) 
                    mutex_lock(&entry->node);
				 if(entry->tcpfilters!=0)
                {
                    m5=1;
                    int temp = intToBinary(entry->tcpfilters);
                    mutex_unlock(&entry->node);
                    char filters[5];
                    tostring(filters, temp);
                    if (filters[3]=='1') {
                        int m2=0;
                        mutex_lock(&entry->node);
                        if (tcph->source != entry->srcport)
                        { 
                            m2=1;
                            mutex_unlock(&entry->node);   
                            return 0;
                        }   
                        if(m2==0)
                            mutex_unlock(&entry->node);
                    }
                    if (filters[2]=='1') {
                        int m2=0;
                        mutex_lock(&entry->node);
                        if (tcph->dest != entry->dstport)
                        {
                            m2=1;
                            mutex_unlock(&entry->node);    
                            return 0;
                        }    
                        if(m2==0)
                            mutex_unlock(&entry->node);
                    }
                }
                if(m5==0)
                    mutex_unlock(&entry->node);    
            //printk(KERN_ALERT "packet dropped by bfilter.\n");
	//	if(decider>=0 && decider <fp)    
			return 1;
	//	else
	//		return 0;
			}
		}
        if(m1==0)
            mutex_unlock(&entry->node);
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
	printk("Firewall linked list initialized.\n");
    INIT_LIST_HEAD(&mbState_list1.list);
    printk("Load balancer linked list initialized.\n");
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

