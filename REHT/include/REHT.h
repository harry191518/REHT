#define PORT_ENTRY 65536
#define NUM_HASHTABLE 16
#define NUM_ITEM_OF_HASHENTRY 3

struct ROUTE {
    unsigned int *all2dst, *rbID;
};

struct NODE {
    unsigned int **bucket, *bucket_n, *offset, total_n;
    struct NODE  **ptr;
};

struct ENCODER {
    unsigned short prt2ID[PORT_ENTRY];
    struct NODE *src_root, *dst_root;
    int num_src_node, num_dst_node;
};

struct CONFIG {
    unsigned int layer;
    unsigned int shift[4], mask[4];
};

struct INFORM {
    unsigned int psb_bmp, rule_b[3];
};

struct INFOTAB {
    struct INFORM *src, *dst, *prt;
};

struct HASHENTRY {
    unsigned int key[NUM_ITEM_OF_HASHENTRY], rule_b[NUM_ITEM_OF_HASHENTRY];
};

struct HASHTAB {
    struct HASHENTRY *table[NUM_HASHTABLE];
    unsigned int  hash_func[NUM_HASHTABLE];
    unsigned char shift[3];
};

extern int config_ID;
extern struct ROUTE   route_inform;
extern struct CONFIG  config[3];
extern struct ENCODER encoder;
extern struct INFOTAB inform_table;
extern struct HASHTAB hash_table;

void build_REHT();
