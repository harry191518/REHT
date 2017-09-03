#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "readrule.h"
#include "readroute.h"
#include "rangeop.h"

int num_acl, rule_none;
int rule_behavior[MAX_BEHAVIOR], num_rule_b;
struct RULETABLE rule_table[MAX_RULE];
struct RULITV rule_itv;

static void set_rule(char *str, int *num_entry, struct ENTRY *table, int id) {
    char *s, tok[] = "',";
    int  c;

    str += 2;
    table[*num_entry].ID = id;

    struct RULE head;
    struct RULE *listPtr = &head;
    s = strtok(str, tok);

    while(1) {
        c = 0;

        if(!strcmp(s, "transport_src_end")) {
            listPtr->next = (struct RULE *) malloc (sizeof(struct RULE));
            listPtr->next->next = NULL;
        }
        if(!strcmp(s, "ip_protocol"        )) c = 1;
        if(!strcmp(s, "src_ip"             )) c = 2;
        if(!strcmp(s, "dst_ip"             )) c = 3;
        if(!strcmp(s, "src_ip_mask"        )) c = 4;
        if(!strcmp(s, "dst_ip_mask"        )) c = 5;
        if(!strcmp(s, "transport_dst_begin")) c = 6;
        if(!strcmp(s, "transport_dst_end"  )) c = 7;
        if(!strcmp(s, "action"             )) c = 8;

        s = strtok(NULL, tok);
        s += 2;

        switch(c) {
            case 1:
                listPtr = (listPtr->next) ? listPtr->next : listPtr;
                sscanf(s, "%u", &listPtr->proto);
                break;
            case 2:
                sscanf(s, "%u", &listPtr->srcIP);
                break;
            case 3:
                sscanf(s, "%u", &listPtr->dstIP);
                break;
            case 4:
                sscanf(s, "%u", &listPtr->srcmask);
                break;
            case 5:
                sscanf(s, "%u", &listPtr->dstmask);
                break;
            case 6:
                sscanf(s, "%u", &listPtr->dstPort[0]);
                break;
            case 7:
                sscanf(s, "%u", &listPtr->dstPort[1]);
                break;
            case 8:
                listPtr->action = (!strcmp(s, "True")) ? 1 : 0;
                break;
            default:
                break;
        }

        s = strtok(NULL, tok);
        s = strtok(NULL, tok);

        if(!s) break;
    }

    if(listPtr->next) listPtr->next = NULL;
    table[*num_entry].list = head.next;
    (*num_entry)++;
}

static void read_rule(char *table_name, int *num_entry, struct ENTRY **table) {
    FILE *fp = fopen(table_name, "r");
    char str[50000];

    while(fgets(str, 50000, fp) != NULL) {
        (*num_entry)++;
    }

    rewind(fp);
    
    *table = (struct ENTRY *) malloc ((*num_entry - 2) / 2 * sizeof(struct ENTRY));
    *num_entry = 0;

    fgets(str, 50000, fp);

    while(fgets(str, 50000, fp) != NULL) {
        if(str[0] == '=') break;
            
        if(str[0] != '[') {
            int id = atoi(str);

            fgets(str, 50000, fp);
            set_rule(str, num_entry, *table, id);
        }
    }

    close(fp);
}

static int rule_check(struct RULE *p) {
    int i;

    for(i = 0; i < num_acl; i++) {
        if(p->srcIP == rule_table[i].srcIP && p->srclen == rule_table[i].srclen && p->dstIP == rule_table[i].dstIP && p->dstlen == rule_table[i].dstlen
           && p->dstPort[0] == rule_table[i].port[0] && p->dstPort[1] == rule_table[i].port[1] && p->proto == rule_table[i].proto && p->action == rule_table[i].action) {
            return i;
        }   
    }

    return -1;
}

static void integrate_rule(int num_entry, struct ENTRY *table, int tableID) {
    int i;

    for(i = 0; i < num_entry; i++) {
    //printf("%d %d\n", table[i].ID, table[i].list);
        struct RULE *ptr = table[i].list;
        unsigned int m, l, r;
        int len;

        while(ptr) {
            len = 32;
            m = ptr->srcmask;

            while(m) {
                len--;
                m >>= 1;
            }

            ptr->srclen = len;

            len = 32;
            m = ptr->dstmask;

            while(m) {
                len--;
                m >>= 1;
            }
            
            ptr->dstlen = len;

            int g = 0;

            g += (ptr->srclen) ? 8 : 0;
            g += (ptr->dstlen) ? 4 : 0;
            g += (ptr->dstPort[1] - ptr->dstPort[0] != 65535) ? 2 : 0;
            g += (ptr->proto)  ? 1 : 0;

            if(g <= 1) ptr->action = 0;

            int c = rule_check(ptr);
            
            if(c == -1) {
                rule_table[num_acl  ].srcIP   = ptr->srcIP;
                rule_table[num_acl  ].srclen  = ptr->srclen;
                rule_table[num_acl  ].dstIP   = ptr->dstIP;
                rule_table[num_acl  ].dstlen  = ptr->dstlen;
                rule_table[num_acl  ].port[0] = ptr->dstPort[0];
                rule_table[num_acl  ].port[1] = ptr->dstPort[1];
                rule_table[num_acl  ].proto   = ptr->proto;
                rule_table[num_acl  ].group   = g;
                rule_table[num_acl  ].action  = ptr->action;
                rule_table[num_acl++].rule_b |= 1 << (num_router - 1 - tableID);
            }
            else {
                rule_table[c].rule_b |= 1 << (num_router - 1 - tableID);
            }

            ptr = ptr->next;
        }
    }
}

static void set_filter(char *table_name, int tableID) {
    int num_entry = 0;
    struct ENTRY *table;

    read_rule(table_name, &num_entry, &table);
    integrate_rule(num_entry, table, tableID);
}

static void read_filter(char *input_file) {
    FILE *fp;
    char str[100];
    int  i;

    if(!name_set) {
        num_router = 0;
        fp = fopen(input_file, "r");

        while(fgets(str, 100, fp) != NULL) {
            router_name[num_router] = (char *) malloc (20 * sizeof(char));
            sscanf(str, "%s\n", router_name[num_router]);
            sprintf(str, "route/%s", router_name[num_router++]);
        }

        close(fp);
    }   

    for(i = 0; i < num_router; i++) {
        sprintf(str, "rule/%s", router_name[i]);
        
        fp = fopen(str, "r");
        if(fp == NULL) {
            rule_none = 1;
            return;
        }

        set_filter(str, i);
    }
}

static void compute_rule_b() {
    if(rule_none) return;

    int i, j, permit_acl = 0, num_group[MAX_ROUTER] = {0};
    num_rule_b = 0;

    for(i = 0; i < num_acl; i++) {
        if(rule_table[i].action) {
            num_group[rule_table[i].group]++;

            for(j = 0; j < num_rule_b; j++) {
                if(rule_table[i].rule_b == rule_behavior[j]) {
                    rule_table[i].rbID = j;
                    break;
                }
            }

            if(j == num_rule_b) {
                rule_table[i].rbID = num_rule_b;
                rule_behavior[num_rule_b++] = rule_table[i].rule_b;
            }
        }
    }

    printf("number of rules\n");

    for(i = 0; i < num_router; i++) {
        printf("group %-2d: %d\n", i, num_group[i]);
        permit_acl += num_group[i];
    }

    printf("\nnumber of integrate rules (permit): %d\n", permit_acl);
    printf("number of rule behaviors: %d\n\n", num_rule_b);
}

static void set_range() {
    int i;

    rule_itv.src = (unsigned int *) malloc ((num_acl * 2 + 1) * sizeof(unsigned int));
    rule_itv.dst = (unsigned int *) malloc ((num_acl * 2 + 1) * sizeof(unsigned int));
    rule_itv.prt = (unsigned int *) malloc ((num_acl * 2 + 1) * sizeof(unsigned int));
    rule_itv.pro = (unsigned int *) malloc ((num_acl * 2 + 1) * sizeof(unsigned int));
    rule_itv.all = (unsigned int *) malloc ((num_acl * 2 + 1 + route_itv.n) * sizeof(unsigned int));

    rule_itv.srcn = 1;
    rule_itv.dstn = 1;
    rule_itv.prtn = 1;
    rule_itv.pron = 1;
    rule_itv.alln = 1;

    if(route_itv.n) {
        for(i = 1; i < route_itv.n; i++) {
            rule_itv.all[rule_itv.alln++] = route_itv.interval[i];
        }
    }

    if(rule_none) return;

    for(i = 0; i < num_acl; i++) {
        unsigned int l, r;

        if(!rule_table[i].action) continue;
            
        l = (rule_table[i].srcIP == 0)  ?  0 : rule_table[i].srcIP - 1;
        r = (rule_table[i].srclen == 0) ? -1 : (((rule_table[i].srcIP >> (32 - rule_table[i].srclen)) + 1) << (32 - rule_table[i].srclen)) - 1;

        if(l || r) add_endpoint(rule_itv.src, &rule_itv.srcn, l, r);

        l = (rule_table[i].dstIP == 0)  ?  0 : rule_table[i].dstIP - 1;
        r = (rule_table[i].dstlen == 0) ? -1 : (((rule_table[i].dstIP >> (32 - rule_table[i].dstlen)) + 1) << (32 - rule_table[i].dstlen)) - 1;

        if(l || r) {
            add_endpoint(rule_itv.dst, &rule_itv.dstn, l, r);
            add_endpoint(rule_itv.all, &rule_itv.alln, l, r);
        }

        if(rule_table[i].port[0] == rule_table[i].port[1]) {
            add_endpoint(rule_itv.prt, &rule_itv.prtn, 0, rule_table[i].port[0]);
        }
        else {
            add_endpoint(rule_itv.prt, &rule_itv.prtn, rule_table[i].port[0], rule_table[i].port[1]);
        }

        if(rule_table[i].proto) {
            add_endpoint(rule_itv.pro, &rule_itv.pron, 0, rule_table[i].proto);
        }
    }

    printf("%d %d %d %d %d\n\n", rule_itv.srcn - 1, rule_itv.dstn - 1, rule_itv.prtn - 1, rule_itv.pron - 1, rule_itv.alln - 1);
}

void rule2all(char *input_file) {
    read_filter(input_file);
    compute_rule_b();
    set_range();
}
