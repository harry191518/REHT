#include "readroute.h"

void add_endpoint(unsigned int *array, int *n, unsigned int a, unsigned int b){
    int i, j, c = 0;
    
    for(i = 0; i < *n; i++){
        if(a == array[i]){
            if(c == 0){
                a = b;
                c = 1;
            }
            else
                break;
        }
        else if(a < array[i]){
            for(j = *n; j > i; j--){
                array[j] = array[j - 1];
            }
            array[i] = a;
            (*n)++;
            if(c == 0){
                c = 1;
                a = b;
            }
            else
                break;
        }
        if(i == *n - 1){
            array[(*n)++] = a;
            if(c == 0){
                c = 1;
                a = b;
            }
            else
                break;
        }
    }
}

void interval_op1(int portID, unsigned int ip, int len, int N, unsigned int *endpoint, unsigned char *outport, unsigned char *priority){
    unsigned int l, r;
    int i, c = 0;
    
    l = ip;
    r = (len == 0) ? -1 : (((ip >> (32 - len)) + 1) << (32 - len)) - 1;

    for(i = 1; i < N; i++){
        if(c == 0 && endpoint[i] >= l)
            c = 1;
        if(c == 1){
            if(priority[i] <= len) {
                priority[i] = len;
                outport[i]  = portID;
            }
        }
        if(c == 1 && endpoint[i] >= r)
            break;
    }
}

void interval_op2(int portID, unsigned int l, unsigned int r, int N, unsigned int *endpoint, unsigned char **outport, int p){
    int i, c = 0;
    
    for(i = 1; i < N; i++){
        if(c == 0 && endpoint[i] >= l)
            c = 1;
        if(c == 1){
            outport[i][p]  = portID;
        }
        if(c == 1 && endpoint[i] >= r)
            break;
    }
}

int interval_ID(int value, int N, unsigned int *endpoint) {
    int i;

    for(i = 1; i < N; i++) {
        if(endpoint[i] >= value)
            return i;
    }
}

int count_bit(int i) {
    return (i) ? count_bit(i / 2) + 1 : 0;
}
