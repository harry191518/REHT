#include "rangeop.h"

#ifndef READROUTE_H
#define READROUTE_H

#define MAX_ROUTER   30
#define MAX_BEHAVIOR 10000

struct PREFIX {
    unsigned int  IP;
    unsigned char len, portID;
    char *interface;
};

extern int  num_router, name_set;
extern int  *routing_behavior[MAX_BEHAVIOR], num_routing_b;
extern char *router_name[MAX_ROUTER];
extern struct ROUITV route_itv; 

void route2all(char *);
void read_all_route();

#endif
