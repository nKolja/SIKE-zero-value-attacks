#include "randombytes.h"

int randombytes(uint8_t *obuf, size_t len)
{
    size_t i;
    
    for(i =0;i<len;++i)
    {
        obuf[i] = 0x04; // Obtained from a fair die throw 
    }

    return 0;
}
