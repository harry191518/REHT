#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rangeop.h"
#include "readroute.h"
#include "readrule.h"
#include "REHT.h"

int main(int argc, char *argv[]) {
    //route2all(argv[1]);
    read_all_route();
    rule2all(argv[1]);

    build_REHT();
    trace(argv[2]);

    return 0;
}
