#include "rangeop.h"
#include "readroute.h"

#define MAX_RULE 10000

struct ENTRY {
    unsigned short ID;
    struct RULE* list;
};

struct RULE {
    unsigned int srcIP, dstIP, srcmask, dstmask, srclen, dstlen;
    unsigned int dstPort[2], proto, action;
    struct RULE* next;
};

struct RULETABLE {
    unsigned int  srcIP, srclen, dstIP, dstlen;
    unsigned int  port[2], proto, rule_b, rbID;
    unsigned int  itv_src, itv_dst, itv_prt;
    unsigned char group, action, use;
};

extern int num_acl, rule_none;
extern int rule_behavior[MAX_BEHAVIOR], num_rule_b;
extern struct RULETABLE rule_table[MAX_RULE];
extern struct RULITV rule_itv;

void rule2all(char *);
