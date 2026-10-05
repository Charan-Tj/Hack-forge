#include "urlparse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv){
    if(argc<2) return 2; FILE*f=fopen(argv[1],"rb"); if(!f) return 2;
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char*buf=(unsigned char*)malloc(n>0?(size_t)n:1); size_t got=fread(buf,1,(size_t)n,f); fclose(f);
    urlinfo out; memset(&out, 0, sizeof(out));
    long rc=(long)urlparse(buf, got, &out);
    printf("rc=%ld\n", rc);
    return 0;
}
