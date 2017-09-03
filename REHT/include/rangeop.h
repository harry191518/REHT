#ifndef RANGEOP_H
#define RANGEOP_H

struct ROUITV { /* interval structure for routing table */
    unsigned int  *interval, n, *rbID;
    unsigned char *outport, *priority;
    unsigned char **route_b; /* routing behavior */
};

struct RULITV { /* interval structure for rule table */
    unsigned int *src, *dst, srcn, dstn;
    unsigned int *prt, *pro, prtn, pron;
    unsigned int *all, alln;
};

void add_endpoint(unsigned int *, int *, unsigned int, unsigned int);
void interval_op1(int, unsigned int, int, int, unsigned int *, unsigned char*, unsigned char *);
void interval_op2(int, unsigned int, unsigned int, int, unsigned int*, unsigned char **, int);
int  interval_ID(int, int, unsigned int *);
int  count_bit(int);

#endif 
