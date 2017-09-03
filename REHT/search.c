#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rangeop.h"
#include "readroute.h"
#include "readrule.h"
#include "REHT.h"

inline unsigned long long int rdtsc() {
	unsigned long long int x;
	asm   volatile ("rdtsc" : "=A" (x));
	return x;
}

static void search1(unsigned int srcIP, unsigned int dstIP, unsigned int port, unsigned int proto, int *network_wide_b) {
    struct NODE *ptr_dst = encoder.dst_root;
    int itv_dst = 1, l = 0, *routing_b;

    while(ptr_dst) {
        itv_dst += ptr_dst->offset[(dstIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        ptr_dst  = ptr_dst->ptr[(dstIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        l++;
    }

    routing_b = routing_behavior[route_inform.rbID[itv_dst]];
}

static void search2(unsigned int srcIP, unsigned int dstIP, unsigned int port, unsigned int proto, int *network_wide_b) {
    struct NODE *ptr_src = encoder.src_root, *ptr_dst = encoder.dst_root;
    int itv_src = 1, itv_all = 1, itv_dst, itv_prt, itv_pro;
    int i, j, l, psb_bmp, mask = 32768, *routing_b, rule_b = 0;

    if(proto == rule_itv.pro[1]) itv_pro = 1;
    else if(proto == rule_itv.pro[2]) itv_pro = 2;
    else itv_pro = 0;

    l = 0;
    while(ptr_src) {
        itv_src += ptr_src->offset[(srcIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        ptr_src  = ptr_src->ptr[(srcIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        l++;
    }
    
    l = 0;
    while(ptr_dst) {
        itv_all += ptr_dst->offset[(dstIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        ptr_dst  = ptr_dst->ptr[(dstIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        l++;
    }

    itv_dst = route_inform.all2dst[itv_all];
    itv_prt = encoder.prt2ID[port];

    psb_bmp = inform_table.src[itv_src].psb_bmp & inform_table.dst[itv_dst].psb_bmp & inform_table.prt[itv_prt].psb_bmp;

    for(i = 0; i < 16; i++) {
        if(psb_bmp & mask) {
            int key = (itv_src << hash_table.shift[0]) + (itv_dst << hash_table.shift[1]) + (itv_prt << hash_table.shift[0]) + itv_pro;

            int htf = hash_table.hash_func[i];
            
            for(j = 0; j < 3; j++) {
                if(!hash_table.table[i][key % htf].key[j]) break;
                if(hash_table.table[i][key % htf].key[j] == key) rule_b |= hash_table.table[i][key % htf].rule_b[j];
            }
        }
        
        mask >>= 1;
    }

    mask = 32768;
    routing_b = routing_behavior[route_inform.rbID[itv_all]];

    for(i = 0; i < num_router; i++) {
        if(mask & rule_b) {
            network_wide_b[i] = routing_b[i];
        }
    }
}

static int count_access1(unsigned int srcIP, unsigned int dstIP, unsigned int port, unsigned int proto) {
    struct NODE *ptr_dst = encoder.dst_root;
    int itv_dst = 1, l = 0, access = 0;

    while(ptr_dst) {
        itv_dst += ptr_dst->offset[(dstIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        ptr_dst  = ptr_dst->ptr[(dstIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        l++;
        access++;
    }

    return access;
}

static int count_access2(unsigned int srcIP, unsigned int dstIP, unsigned int port, unsigned int proto) {
    struct NODE *ptr_src = encoder.src_root, *ptr_dst = encoder.dst_root;
    int itv_src = 1, itv_all = 1, itv_dst, itv_prt, itv_pro;
    int i, l, psb_bmp, mask = 32768, access = 0;

    if(proto == rule_itv.pro[1]) itv_pro = 1;
    else if(proto == rule_itv.pro[2]) itv_pro = 2;
    else itv_pro = 0;

    l = 0;
    while(ptr_src) {
        itv_src += ptr_src->offset[(srcIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        ptr_src  = ptr_src->ptr[(srcIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        l++;
        access++;
    }
    
    l = 0;
    while(ptr_dst) {
        itv_all += ptr_dst->offset[(dstIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        ptr_dst  = ptr_dst->ptr[(dstIP >> config[config_ID].shift[l]) & config[config_ID].mask[l]];
        l++;
        access++;
    }

    itv_dst = route_inform.all2dst[itv_all];
    itv_prt = encoder.prt2ID[port];
    access++;

    psb_bmp = inform_table.src[itv_src].psb_bmp & inform_table.dst[itv_dst].psb_bmp & inform_table.prt[itv_prt].psb_bmp;
    access += 3;

    for(i = 0; i < 16; i++) {
        if(psb_bmp & mask) access++;
        mask >>= 1;
    }

    return access;
}

void trace(char *trace_file) {
    FILE *fp = fopen(trace_file, "r");
    char str[100];

    unsigned long long int begin, end, total = 0;
    double total_access = 0;
    int num_trace = 0;

    void (*search) (unsigned int srcIP, unsigned int dstIP, unsigned int port, unsigned int proto, int* network_wide_b) = (rule_none) ? search1 : search2;
    int  (*count_access) (unsigned int srcIP, unsigned int dstIP, unsigned int port, unsigned int proto) = (rule_none) ? count_access1 : count_access2;

    while(fgets(str, 100, fp) != NULL) {
        unsigned int srcIP, dstIP, srcPort, dstPort, proto;
        sscanf(str, "%u %u %u %u %u", &srcIP, &dstIP, &srcPort, &dstPort, &proto);

        begin = rdtsc();
        search(srcIP, dstIP, dstPort, proto, NULL);
        end   = rdtsc();

        total += end - begin;
        total_access += count_access(srcIP, dstIP, dstPort, proto);
        num_trace++;
    }

    printf("average tick for search      : %llu\n", total / num_trace);
    printf("average accesses for search  : %lf\n",  total_access / num_trace);
}
