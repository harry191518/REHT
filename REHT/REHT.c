#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "readroute.h"
#include "readrule.h"
#include "rangeop.h"
#include "REHT.h"

int config_ID;
struct ROUTE   route_inform;
struct CONFIG  config[3];
struct ENCODER encoder;
struct INFOTAB inform_table;
struct HASHTAB hash_table;

static void set_route_inform() {
    int i;

    route_inform.all2dst = (unsigned int *) malloc (rule_itv.alln * sizeof(unsigned int));
    route_inform.rbID    = (unsigned int *) malloc (rule_itv.alln * sizeof(unsigned int));

    for(i = 0; i < rule_itv.alln; i++) {
        route_inform.all2dst[i] = interval_ID(rule_itv.all[i], rule_itv.dstn, rule_itv.dst);
        route_inform.rbID[i]    = route_itv.rbID[interval_ID(rule_itv.all[i], route_itv.n, route_itv.interval)];
    }
}

static void set_port_encoder() {
    int i;

    for(i = 0; i < PORT_ENTRY; i++) {
        encoder.prt2ID[i] = interval_ID(i, rule_itv.prtn, rule_itv.prt);
    }
}

static struct NODE* init_node(int total, int n) {
    struct NODE *new = (struct NODE *) malloc (sizeof(struct NODE));
    int i;

    new->bucket   = (unsigned int**) malloc (n * sizeof(unsigned int*));
    new->bucket_n = (unsigned int *) malloc (n * sizeof(unsigned int));
    new->offset   = (unsigned int *) malloc (n * sizeof(unsigned int));
    new->ptr      = (struct NODE **) malloc (n * sizeof(struct NODE*));

    for(i = 0; i < n; i++) {
        new->bucket[i]   = NULL;
        new->bucket_n[i] = 0;
        new->offset[i]   = 0;
        new->ptr[i]      = NULL;
    }

    new->total_n = total;

    return new;
}

static void init_configuration(int ID) {
    config[0].layer    = 4;
    config[0].shift[0] = 24;   config[0].shift[1] = 16;
    config[0].shift[2] = 8;    config[0].shift[3] = 0;
    config[0].mask[0]  = 255;  config[0].mask[1]  = 255;
    config[0].mask[2]  = 255;  config[0].mask[3]  = 255;

    config[1].layer    = 3;
    config[1].shift[0] = 16;   config[1].shift[1] = 8;
    config[1].shift[2] = 0;    config[1].mask[0]  = 65535;
    config[1].mask[1]  = 255;  config[1].mask[2]  = 255;

    config[2].layer    = 3;
    config[1].shift[0] = 20;   config[1].shift[1] = 10;
    config[1].shift[2] = 0;    config[1].mask[0]  = 4095;
    config[1].mask[1]  = 1023; config[1].mask[2]  = 1023;

    config_ID = ID;
}

static void set_multiway_range_tree(struct NODE **node, int *b, int n, int l, unsigned int *itv, int *num_node, struct CONFIG config) {
    if(l == config.layer) return;

    int i, shift = config.shift[l], mask = config.mask[l];
    (*node) = init_node(n, mask + 1);
    (*num_node)++;

    struct NODE *p = *node;
    for(i = 0; i < n; i++) p->bucket_n[(itv[b[i]] >> shift) & mask]++;

    int off = 0;
    for(i = 0; i < mask + 1; i++) {
        p->offset[i] = off;

        if(p->bucket_n[i]) {
            off += p->bucket_n[i];
            p->bucket[i] = (unsigned int *) malloc (p->bucket_n[i] * sizeof(unsigned int));
            p->bucket_n[i] = 0;
        }
    }

    for(i = 0; i < n; i++) {
        p->bucket[(itv[b[i]] >> shift) & mask][p->bucket_n[(itv[b[i]] >> shift) & mask]++] = b[i];
    }

    for(i = 0; i < mask + 1; i++) {
        if(p->bucket_n[i]) set_multiway_range_tree(&p->ptr[i], p->bucket[i], p->bucket_n[i], l + 1, itv, num_node, config);
    }
}

static int set_ip_encoder(struct NODE **root, unsigned int *itv, int n, struct CONFIG config) {
    int i, num_node = 0;
    int *root_bucket = (int *) malloc (n * sizeof(int));

    for(i = 0; i < n; i++) root_bucket[i] = i + 1;

    set_multiway_range_tree(root, root_bucket, n, 0, itv, &num_node, config);
   
    return num_node;
}

static void set_field_inform(int *num_item) {
    unsigned int l, r;
    int i, j;

    inform_table.src = (struct INFORM *) calloc (rule_itv.srcn, sizeof(struct INFORM));
    inform_table.dst = (struct INFORM *) calloc (rule_itv.dstn, sizeof(struct INFORM));
    inform_table.prt = (struct INFORM *) calloc (rule_itv.prtn, sizeof(struct INFORM));

    for(i = 0; i < num_acl; i++) {
        if(!rule_table[i].action) continue;

        l  = rule_table[i].srcIP;
        r  = (rule_table[i].srclen == 0) ? -1 : (((rule_table[i].srcIP >> (32 - rule_table[i].srclen)) + 1) << (32 - rule_table[i].srclen)) - 1;
        int src_c1 = interval_ID(l, rule_itv.srcn, rule_itv.src);
        int src_c2 = interval_ID(r, rule_itv.srcn, rule_itv.src);
        rule_table[i].itv_src = src_c2 - src_c1 + 1;
        int src_dup = (rule_table[i].srclen) ? rule_table[i].itv_src : 1;

        l  = rule_table[i].dstIP;
        r  = (rule_table[i].dstlen == 0) ? -1 : (((rule_table[i].dstIP >> (32 - rule_table[i].dstlen)) + 1) << (32 - rule_table[i].dstlen)) - 1;
        int dst_c1 = interval_ID(l, rule_itv.dstn, rule_itv.dst);
        int dst_c2 = interval_ID(r, rule_itv.dstn, rule_itv.dst);
        rule_table[i].itv_dst = dst_c2 - dst_c1 + 1;
        int dst_dup = (rule_table[i].dstlen) ? rule_table[i].itv_dst : 1;

        int prt_c1 = interval_ID(rule_table[i].port[0], rule_itv.prtn, rule_itv.prt);
        int prt_c2 = interval_ID(rule_table[i].port[1], rule_itv.prtn, rule_itv.prt);
        rule_table[i].itv_prt = prt_c2 - prt_c1 + 1;
        int prt_dup = (rule_table[i].port[1] - rule_table[i].port[0] == 65535) ? 1 : rule_table[i].itv_prt;
        
        num_item[rule_table[i].group] += src_dup * dst_dup * prt_dup;

        int proID;
        if(rule_table[i].proto == rule_itv.pro[1]) proID = 1;
        else if(rule_table[i].proto == rule_itv.pro[2]) proID = 2;
        else proID = 0;

        rule_table[i].use = 1;

        if(rule_table[i].group == 3) {
            for(j = prt_c1; j <= prt_c2; j++) inform_table.prt[j].rule_b[proID] = rule_table[i].rule_b;
            rule_table[i].use = 0;
        }

        if(rule_table[i].group == 4 || rule_table[i].group == 5) {
            for(j = dst_c1; j <= dst_c2; j++) {
                if(proID) {
                    inform_table.dst[j].rule_b[proID] = rule_table[i].rule_b;
                }
                else {
                    inform_table.dst[j].rule_b[0] = rule_table[i].rule_b;
                    inform_table.dst[j].rule_b[1] = rule_table[i].rule_b;
                    inform_table.dst[j].rule_b[2] = rule_table[i].rule_b;
                }
            }

            rule_table[i].use = 0;
        }

        if(rule_table[i].group == 8 || rule_table[i].group == 9) {
            for(j = src_c1; j <= src_c2; j++) {
                if(proID) {
                    inform_table.src[j].rule_b[proID] = rule_table[i].rule_b;
                }
                else {
                    inform_table.src[j].rule_b[0] = rule_table[i].rule_b;
                    inform_table.src[j].rule_b[1] = rule_table[i].rule_b;
                    inform_table.src[j].rule_b[2] = rule_table[i].rule_b;
                }
            }

            rule_table[i].use = 0;
        }
    }
}

static int set_hash_table(int *num_item, int HTsize) {
    unsigned int l, r;
    int i, j, k, m, p;
    int num_all_item = 0;

    for(i = 0; i < NUM_HASHTABLE; i++) {
        hash_table.table[i] = (struct HASHENTRY *) calloc (num_item[i] * HTsize + 1, sizeof(struct HASHENTRY));
        hash_table.hash_func[i] = num_item[i] * HTsize + 1;
    }

    hash_table.shift[2] = 2;
    hash_table.shift[1] = hash_table.shift[2] + count_bit(rule_itv.prtn);
    hash_table.shift[0] = hash_table.shift[1] + count_bit(rule_itv.dstn);

    for(i = 0; i < num_acl; i++) {
        if(!rule_table[i].use) continue;

        l  = rule_table[i].srcIP;
        r  = (rule_table[i].srclen == 0) ? -1 : (((rule_table[i].srcIP >> (32 - rule_table[i].srclen)) + 1) << (32 - rule_table[i].srclen)) - 1;
        int src_c1 = interval_ID(l, rule_itv.srcn, rule_itv.src);
        int src_c2 = interval_ID(r, rule_itv.srcn, rule_itv.src);
        if(!rule_table[i].srclen) {src_c1 = 0; src_c2 = 0;}

        l  = rule_table[i].dstIP;
        r  = (rule_table[i].dstlen == 0) ? -1 : (((rule_table[i].dstIP >> (32 - rule_table[i].dstlen)) + 1) << (32 - rule_table[i].dstlen)) - 1;
        int dst_c1 = interval_ID(l, rule_itv.dstn, rule_itv.dst);
        int dst_c2 = interval_ID(r, rule_itv.dstn, rule_itv.dst);
        if(!rule_table[i].dstlen) {dst_c1 = 0; dst_c2 = 0;}

        int prt_c1 = interval_ID(rule_table[i].port[0], rule_itv.prtn, rule_itv.prt);
        int prt_c2 = interval_ID(rule_table[i].port[1], rule_itv.prtn, rule_itv.prt);
        if(rule_table[i].port[1] - rule_table[i].port[0] == 65535) {prt_c1 = 0; prt_c2 = 0;}

        int proID;
        if(rule_table[i].proto == rule_itv.pro[1]) proID = 1;
        else if(rule_table[i].proto == rule_itv.pro[2]) proID = 2;
        else proID = 0;

        for(j = src_c1; j <= src_c2; j++) {
            for(k = dst_c1; k <= dst_c2; k++) {
                for(m = prt_c1; m <= prt_c2; m++) {
                    int key = (j << hash_table.shift[0]) + (k << hash_table.shift[1]) + (m << hash_table.shift[2]) + proID;
                    int grp = rule_table[i].group;
                    int htf = hash_table.hash_func[grp];

                    for(p = 0; p < 3; p++) {
                        if(!hash_table.table[grp][key % htf].key[p]) {
                            hash_table.table[grp][key % htf].key[p]    = key;
                            hash_table.table[grp][key % htf].rule_b[p] = rule_table[i].rule_b;
                            break;
                        }
                    }

                    if(p == 3) printf("Hash table overload!\n");

                    if(j) inform_table.src[j].psb_bmp |= 1 << (NUM_HASHTABLE - 1 - grp);
                    if(k) inform_table.dst[k].psb_bmp |= 1 << (NUM_HASHTABLE - 1 - grp);
                    if(m) inform_table.prt[m].psb_bmp |= 1 << (NUM_HASHTABLE - 1 - grp);

                    num_all_item++;
                }
            }
        }
    }

    printf("total items in hash table: %d\n", num_all_item++);
    return num_all_item;
}

static encoder_size(struct NODE *node, int ptr_l, int l) {
    unsigned  int total = 0;
    int i, num = 0;

    for(i = 0; i < config[config_ID].mask[l] + 1; i++) {
        if(node->ptr[i] != NULL) {
            total += encoder_size(node->ptr[i], ptr_l, l + 1);
            num++;
        }
    }

    total += (config[config_ID].mask[l] + 1) * (count_bit(num) + 1);
    total += num * (count_bit(node->total_n) + ptr_l);

    return total;
}

static compute_size(int num_all_item) {
    int i, j, route_b_size = 0;
    double src_enc, dst_enc, prt_enc;
    double be_tol, src_tol, dst_tol, prt_tol, hsh_tol, tol;

    for(i = 0; i < num_router; i++) {
        int max_port = 0;
        for(j = 1; j < route_itv.n; j++) if(route_itv.route_b[j][i] > max_port) max_port = route_itv.route_b[j][i];

        route_b_size += count_bit(max_port);
    }

    src_enc = encoder_size(encoder.src_root, count_bit(encoder.num_src_node), 0);
    dst_enc = encoder_size(encoder.dst_root, count_bit(encoder.num_dst_node), 0) + (rule_itv.alln) * (count_bit(num_routing_b) + count_bit(rule_itv.dstn));
    be_tol  = num_routing_b * route_b_size;
    src_tol = rule_itv.srcn * (3 * num_router + 5);
    dst_tol = rule_itv.dstn * (3 * num_router + 5);
    prt_enc = PORT_ENTRY * count_bit(rule_itv.prtn);
    prt_tol = rule_itv.prtn * (3 * num_router + 5);
    hsh_tol = (num_all_item * 3 + 1) * (hash_table.shift[0] + count_bit(rule_itv.srcn) + count_bit(num_acl)) * 3;
    tol     = be_tol + src_enc + dst_enc + src_tol + dst_tol + prt_enc + prt_tol + hsh_tol;
    if(rule_none) tol = be_tol + dst_enc + dst_tol;

    if(rule_none) {
        printf("routing behavior table: %5f KB\n", be_tol  / 8192); 
        printf("dst IP encoder        : %5f KB\n", dst_enc / 8192); 
        printf("dst IP inform table   : %5f KB\n", dst_tol / 8192); 
        printf("total memory          : %5f KB\n\n", tol / 8192);
    }
    else {
        printf("routing behavior table: %5f KB\n", be_tol  / 8192); 
        printf("src IP encoder        : %5f KB\n", src_enc / 8192); 
        printf("dst IP encoder        : %5f KB\n", dst_enc / 8192); 
        printf("dst port encoder      : %5f KB\n", prt_enc / 8192); 
        printf("src IP inform table   : %5f KB\n", src_tol / 8192); 
        printf("dst IP inform table   : %5f KB\n", dst_tol / 8192); 
        printf("dst port inform table : %5f KB\n", prt_tol / 8192); 
        printf("hash table            : %5f KB\n", hsh_tol / 8192);
        printf("total memory          : %5f KB\n\n", tol / 8192);
    }
}

void build_REHT() {
    set_route_inform();
    set_port_encoder();

    init_configuration(0);
    encoder.num_src_node = set_ip_encoder(&encoder.src_root, rule_itv.src, rule_itv.srcn - 1, config[config_ID]);
    encoder.num_dst_node = set_ip_encoder(&encoder.dst_root, rule_itv.all, rule_itv.alln - 1, config[config_ID]);

    int num_item[NUM_HASHTABLE] = {0}, num_all_item;
    set_field_inform(num_item);
    num_all_item = set_hash_table(num_item, 3);

    compute_size(num_all_item);
}
