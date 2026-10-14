#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int Diag_LoadConfig(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[64];
    if (f == NULL) { return -1; }
    if (fgets(line, sizeof(line), f) == NULL) { return -2; }
    return atoi(line);
}

uint32_t Diag_Factorial(uint32_t n)
{
    if (n <= 1U) { return 1U; }
    return n * Diag_Factorial(n - 1U);
}

void Diag_GenSeed(uint8_t *seed, uint8_t len)
{
    uint8_t i;
    for (i = 0U; i < len; i++) { seed[i] = (uint8_t)rand(); }
}
