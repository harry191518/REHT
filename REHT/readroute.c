#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "readroute.h"
#include "rangeop.h"

int  num_router, name_set;
int  *routing_behavior[MAX_BEHAVIOR], num_routing_b;
char *router_name[MAX_ROUTER];
struct ROUITV elementary_itv[MAX_ROUTER], route_itv;

static void set_prefix(char *str, int *num_prefix, int *uni_port, struct PREFIX *table, char **port) {
    int i, c = 0;

    for(i = 0; i < 100; i++) {
        if(str[i] == '\'') {
            if(c == 1) {
                str[i] = '\0';
                break;
            }
            else {
                c = 1;
            }
        }
    }
    str++;

    table[*num_prefix].interface = (char *) malloc (100 * sizeof(char));
    sscanf(str, "%u, %u, '%s", &table[*num_prefix].IP, &table[*num_prefix].len, table[*num_prefix].interface);

    if(!strlen(table[*num_prefix].interface)) {
        table[*num_prefix].portID = 0;
    }
    else {
        for(i = 0; i < *uni_port; i++) {
            if(!strcmp(table[*num_prefix].interface, port[i])) {
                table[*num_prefix].portID = i + 1;
                break;
            }
        }

        if(i == *uni_port) {
            port[*uni_port] = table[*num_prefix].interface;
            table[*num_prefix].portID = ++(*uni_port);
        }
    }

    (*num_prefix)++;
}

static void read_prefix(char *table_name, int *num_prefix, int *uni_port, struct PREFIX **table, char **port) {
    FILE *fp = fopen(table_name, "r");
    char str[100];
    int  i;
    
    while(fgets(str, 100, fp) != NULL) {
        (*num_prefix)++;
    }

    rewind(fp);
    
    *table = (struct PREFIX *) malloc ((*num_prefix) * sizeof(struct PREFIX));
    *num_prefix = 0;

    for(i = 0; i < 6; i++) {
        fgets(str, 100, fp);
    }

    while(fgets(str, 100, fp) != NULL) {
        set_prefix(str, num_prefix, uni_port, *table, port);
    }

    fclose(fp);
}

static void set_range(int num_prefix, struct PREFIX *table, int tableID, int uni_port) {
    unsigned int l, r;
    int i;

    elementary_itv[tableID].interval = (unsigned int *) calloc ((num_prefix * 2 + 1), sizeof(unsigned int ));
    elementary_itv[tableID].outport  = (unsigned char*) calloc ((num_prefix * 2 + 1), sizeof(unsigned char));
    elementary_itv[tableID].priority = (unsigned char*) calloc ((num_prefix * 2 + 1), sizeof(unsigned char));
    elementary_itv[tableID].n = 1;

    for(i = 0; i < num_prefix; i++) {
        l = (table[i].IP == 0) ? 0 : table[i].IP - 1;
        r = (table[i].len == 0) ? -1 : (((table[i].IP >> (32 - table[i].len)) + 1) << (32 - table[i].len)) - 1;

        if(l || r) add_endpoint(elementary_itv[tableID].interval, &elementary_itv[tableID].n, l, r);
    }

    for(i = 0; i < num_prefix; i++) {
        interval_op1(table[i].portID, table[i].IP, table[i].len, elementary_itv[tableID].n, elementary_itv[tableID].interval, elementary_itv[tableID].outport, elementary_itv[tableID].priority);
    }

    int distinct = 1;

    for(i = 1; i < elementary_itv[tableID].n; i++) {
        if(elementary_itv[tableID].outport[i] == elementary_itv[tableID].outport[distinct]) {
            elementary_itv[tableID].outport[distinct] = elementary_itv[tableID].outport[i];
            elementary_itv[tableID].interval[distinct]  = elementary_itv[tableID].interval[i];
        }
        else {
            elementary_itv[tableID].outport[++distinct] = elementary_itv[tableID].outport[i];
            elementary_itv[tableID].interval[distinct]  = elementary_itv[tableID].interval[i];
        }
    }

    elementary_itv[tableID].n = distinct + 1;
    printf("%s: %-4d %-3d\n", router_name[tableID], elementary_itv[tableID].n - 1, uni_port);
}

static void set_route(char *table_name, int tableID) {
    char *port[100];
    int  num_prefix = 0, uni_port = 0;
    struct PREFIX *table;

    read_prefix(table_name, &num_prefix, &uni_port, &table, port);
    set_range(num_prefix, table, tableID, uni_port);
}

static void read_route(char *input_file) {
    FILE *fp = fopen(input_file, "r");
    char str[100];

    num_router = 0;

    while(fgets(str, 100, fp) != NULL) {
        router_name[num_router] = (char *) malloc (20 * sizeof(char));
        sscanf(str, "%s\n", router_name[num_router]);
        sprintf(str, "route/%s", router_name[num_router]);
        set_route(str, num_router++);
    }

    name_set = 1;

    close(fp);
}

static void range2all() {
    int i, j, m, num = 0;

    for(i = 0; i < num_router; i++) 
        num += elementary_itv[i].n;

    route_itv.interval = (unsigned int *)  malloc (num * sizeof(unsigned int));
    route_itv.rbID     = (unsigned int *)  malloc (num * sizeof(unsigned int));
    route_itv.route_b  = (unsigned char**) malloc (num * sizeof(unsigned char*));
    
    for(i = 0; i < num; i++) {
        route_itv.route_b[i] = (unsigned char *) malloc (num_router * sizeof(unsigned char));
    }

    route_itv.n = 1;

    for(i = 0; i < num_router; i++) {
        for(j = 1; j < elementary_itv[i].n; j++) {
            add_endpoint(route_itv.interval, &route_itv.n, 0, elementary_itv[i].interval[j]);
        }
    }

    unsigned int l, r, pre = 0;
    for(i = 0; i < num_router; i++) {
        for(j = 1; j < elementary_itv[i].n; j++) {
            l = pre;
            r = elementary_itv[i].interval[j];

            interval_op2(elementary_itv[i].outport[j], l, r, route_itv.n, route_itv.interval, route_itv.route_b, i);

            pre = r + 1;
        }
    }
}

void compute_routing_b() {
    int i, j, m;

    num_routing_b = 0;

    for(i = 1; i < route_itv.n; i++) {
        for(j = 0; j < num_routing_b; j++) {
            for(m = 0; m < num_router; m++) {
                if(route_itv.route_b[i][m] != routing_behavior[j][m]) {
                    break;
                }
            }

            if(m == num_router) {
                break;
            }
        }

        if(j == num_routing_b) {
            route_itv.rbID[i] = num_routing_b;
            routing_behavior[j] = (int *) malloc (num_router * sizeof(int));
            for(m = 0; m < num_router; m++) {
                routing_behavior[j][m] = route_itv.route_b[i][m];
            }

            num_routing_b++;
        }
    }

    printf("total: %-4d %-3d\n\n", route_itv.n - 1, num_routing_b);
}

static void output_route() {
    FILE *fp;
    char file_name[30];
    int i, j;
    
    sprintf(file_name, "route/all.txt");

    fp = fopen(file_name, "w");
    fprintf(fp, "Endpoint      Output Port     %d \n", route_itv.n - 1);

    for(i = 1; i < route_itv.n; i++) {
        fprintf(fp, "%-14u%", route_itv.interval[i]);
        
        for(j = 0; j < num_router; j++) {
            fprintf(fp, "%-4d", route_itv.route_b[i][j]);
        }

        fprintf(fp, "\n");
    }

    close(fp);
}

void route2all(char *input_file) {
    read_route(input_file);
    range2all();
    compute_routing_b();
    output_route();
}

static int router_n(char *str) {
    char tok[] = " \n", *s;
    int  n = 0;

    s = strtok(str, tok);

    while(s) {
        s = strtok(NULL, tok);
        n++;
    }

    return n - 1;
}

static void set_route_b(char *str) {
    char tok[] = " \n", *s;
    int  i;

    s = strtok(str, tok);
    sscanf(s, "%u", &route_itv.interval[route_itv.n]);

    for(i = 0; i < num_router; i++) {
        s = strtok(NULL, tok);
        sscanf(s, "%d", &route_itv.route_b[route_itv.n][i]);
    }

    route_itv.n++;
}

void read_all_route() {
    FILE *fp = fopen("route/all.txt", "r");
    char str[100];
    int  i, num = 0;

    num_router = 0;

    while(fgets(str, 100, fp) != NULL) {
        num++;
    }

    num_router = router_n(str);

    route_itv.interval = (unsigned int *)  malloc (num * sizeof(unsigned int));
    route_itv.rbID     = (unsigned int *)  malloc (num * sizeof(unsigned int));
    route_itv.route_b  = (unsigned char**) malloc (num * sizeof(unsigned char*));
    
    for(i = 0; i < num; i++) {
        route_itv.route_b[i] = (unsigned char *) malloc (num_router * sizeof(unsigned char));
    }

    route_itv.n = 1;
    
    rewind(fp);
    fgets(str, 100, fp);

    while(fgets(str, 100, fp) != NULL) {
        set_route_b(str);
    }

    compute_routing_b();
}
