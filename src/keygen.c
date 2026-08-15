#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <openssl/sha.h>

int main(int argc, char const *argv[])
{
    unsigned char entropy[32];
    if (getentropy(entropy, sizeof(entropy)) != 0) {
        perror("Error reading entropy");
        return 1;
    }


    return 0;
}
