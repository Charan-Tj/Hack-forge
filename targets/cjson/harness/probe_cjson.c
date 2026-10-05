/* Behaviour probe for cJSON (G5). Prints a canonical observation of the
 * parse result (accepted/rejected + a shape summary). Not part of patch scope. */
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int count_nodes(const cJSON *n) {
    int c = 0;
    const cJSON *child = n ? n->child : NULL;
    for (; child; child = child->next) c += 1 + count_nodes(child);
    return c;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc(n > 0 ? (size_t)n + 1 : 1);
    size_t got = fread(buf, 1, (size_t)(n > 0 ? n : 0), f); fclose(f);
    buf[got] = '\0';
    cJSON *json = cJSON_Parse(buf);
    if (!json) {
        printf("rc=1 parse=reject\n");
    } else {
        printf("rc=0 parse=accept nodes=%d root=%d\n", count_nodes(json), json->type);
        cJSON_Delete(json);
    }
    free(buf);
    return 0;
}
