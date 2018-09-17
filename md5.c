/*########################
21.08.2018 - Lars Munaf
########################*/

/*
    char must be explicitly set to unsigned (because by default CHAR_MIN equals -128)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BLKSIZE 512

#define F(x,y,z) ((x & y) | ((~x) & z))
#define G(x,y,z) ((x & z) | (y & (~z)))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | (~z)))

#define lrot(x,s) ((x << s) | (x >> ((32) - s)))

#define FF(a,b,c,d,M_j,s,t_i)\
{\
    a += F(b,c,d) + M_j + t_i;\
    a = lrot(a,s);\
    a += b;\
}
#define GG(a,b,c,d,M_j,s,t_i)\
{\
    a += G(b,c,d) + M_j + t_i;\
    a = lrot(a,s);\
    a += b;\
}
#define HH(a,b,c,d,M_j,s,t_i)\
{\
    a += H(b,c,d) + M_j + t_i;\
    a = lrot(a,s);\
    a += b;\
}
#define II(a,b,c,d,M_j,s,t_i)\
{\
    a += I(b,c,d) + M_j + t_i;\
    a = lrot(a,s);\
    a += b;\
}

uint32_t A;
uint32_t B;
uint32_t C;
uint32_t D;

/*###############
start of auxiliary functions
################*/

/* print binary representation of input */
void print512BitStringToBin (unsigned char* text)
{
    printf ("binary: ");
    for (int i = 0; i < BLKSIZE / 8; i++) // iterate through each char 8 times
    {
        unsigned char currentChar = *(text + i);

        for (int j = 0; j < 8 * sizeof (char); j++)
        {
            printf ("%i", !!(currentChar & 0x80)); // get the bit on the left
            currentChar <<= 1; // shift left by 1 bit
        }
        printf (" ");
    }
}

/* select a byte of a string and set it to 00000000 or 10000000 */
void setByteOfString (unsigned char* text, int byte, int value)
{
    if (value == 1) // write 1
    {
        *(text + byte) |= 0x80; // TODO: all others bits except the one that is set can have random values -> set all others bits to zero
    }

    else // write 0
    {
        *(text + byte) &= 0x00;
    }
}

uint32_t get32BitBlock (unsigned char* message, int index)
{
    return *(((uint32_t*) message) + index);
}

uint32_t swapByte32 (uint32_t num)
{
    //printf ("before: %x\n", num);
    uint32_t byte4 = num & 0x000000FF;
    uint32_t byte3 = (num & 0x0000FF00) >> 8;
    uint32_t byte2 = (num & 0x00FF0000) >> 16;
    uint32_t byte1 = (num & 0xFF000000) >> 24;

    num = 0;

    num += byte4 << 24;
    num += byte3 << 16;
    num += byte2 << 8;
    num += byte1;
    //printf ("after: %x\n", num);

    return num;
}

/*##############
end of auxiliary functions
################*/

/* step 1: make the plain text congruent to 448 % 51 2
   step 2: append length to last 64 bits of string*/
unsigned char* appendPaddingBitsToLastBlock (unsigned char* plainText)
{
    int bytesWritten;
    uint64_t oldLength;
    unsigned char* paddedPlainText = malloc (BLKSIZE);
    strcpy ((char*) paddedPlainText, (char*) plainText);
    bytesWritten = strlen ((char*) paddedPlainText);
    oldLength = bytesWritten * 8; // length before padding is needed to append the length representation in bits !!!

    /* add the 1-bit */
    setByteOfString (paddedPlainText, bytesWritten++, 1);

    /* add padding zeros */
    while (BLKSIZE / 8 - bytesWritten > 0)
    {
        setByteOfString (paddedPlainText, bytesWritten++, 0);
    }

    /* append length */
    for (int i = 8; i > 0; i--)
    {
        *(paddedPlainText + (bytesWritten - i)) = (char) ((oldLength >> (8 - i) * 8) & 0x00000000000000FF);
    }

    return paddedPlainText;
}

/* step 3: initialize MD buffer */
void initMDBuffer ()
{
    /* assign chaining variables which are in global scope */
    A = 0x67452301; // true order!
    B = 0xefcdab89;
    C = 0x98badcfe;
    D = 0x10325476;
}

/* step 4: main mD5 function */
void md5 (unsigned char* message)
{
    /* copy chaining variables */
    uint32_t a = A;
    uint32_t b = B;
    uint32_t c = C;
    uint32_t d = D;

    /* Round 1 */
    FF (a, b, c, d, get32BitBlock (message, 0), 7, 0xd76aa478); /* 1 */
    FF (d, a, b, c, get32BitBlock (message, 1), 12, 0xe8c7b756); /* 2 */
    FF (c, d, a, b, get32BitBlock (message, 2), 17, 0x242070db); /* 3 */
    FF (b, c, d, a, get32BitBlock (message, 3), 22, 0xc1bdceee); /* 4 */
    FF (a, b, c, d, get32BitBlock (message, 4), 7, 0xf57c0faf); /* 5 */
    FF (d, a, b, c, get32BitBlock (message, 5), 12, 0x4787c62a); /* 6 */
    FF (c, d, a, b, get32BitBlock (message, 6), 17, 0xa8304613); /* 7 */
    FF (b, c, d, a, get32BitBlock (message, 7), 22, 0xfd469501); /* 8 */
    FF (a, b, c, d, get32BitBlock (message, 8), 7, 0x698098d8); /* 9 */
    FF (d, a, b, c, get32BitBlock (message, 9), 12, 0x8b44f7af); /* 10 */
    FF (c, d, a, b, get32BitBlock (message, 10), 17, 0xffff5bb1); /* 11 */
    FF (b, c, d, a, get32BitBlock (message, 11), 22, 0x895cd7be); /* 12 */
    FF (a, b, c, d, get32BitBlock (message, 12), 7, 0x6b901122); /* 13 */
    FF (d, a, b, c, get32BitBlock (message, 13), 12, 0xfd987193); /* 14 */
    FF (c, d, a, b, get32BitBlock (message, 14), 17, 0xa679438e); /* 15 */
    FF (b, c, d, a, get32BitBlock (message, 15), 22, 0x49b40821); /* 16 */

    /* Round 2 */
    GG (a, b, c, d, get32BitBlock (message, 1), 5, 0xf61e2562); /* 17 */
    GG (d, a, b, c, get32BitBlock (message, 6), 9, 0xc040b340); /* 18 */
    GG (c, d, a, b, get32BitBlock (message, 11), 14, 0x265e5a51); /* 19 */
    GG (b, c, d, a, get32BitBlock (message, 0), 20, 0xe9b6c7aa); /* 20 */
    GG (a, b, c, d, get32BitBlock (message, 5), 5, 0xd62f105d); /* 21 */
    GG (d, a, b, c, get32BitBlock (message, 10), 9,  0x2441453); /* 22 */
    GG (c, d, a, b, get32BitBlock (message, 15), 14, 0xd8a1e681); /* 23 */
    GG (b, c, d, a, get32BitBlock (message, 4), 20, 0xe7d3fbc8); /* 24 */
    GG (a, b, c, d, get32BitBlock (message, 9), 5, 0x21e1cde6); /* 25 */
    GG (d, a, b, c, get32BitBlock (message, 14), 9, 0xc33707d6); /* 26 */
    GG (c, d, a, b, get32BitBlock (message, 3), 14, 0xf4d50d87); /* 27 */
    GG (b, c, d, a, get32BitBlock (message, 8), 20, 0x455a14ed); /* 28 */
    GG (a, b, c, d, get32BitBlock (message, 13), 5, 0xa9e3e905); /* 29 */
    GG (d, a, b, c, get32BitBlock (message, 2), 9, 0xfcefa3f8); /* 30 */
    GG (c, d, a, b, get32BitBlock (message, 7), 14, 0x676f02d9); /* 31 */
    GG (b, c, d, a, get32BitBlock (message, 12), 20, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH (a, b, c, d, get32BitBlock (message, 5), 4, 0xfffa3942); /* 33 */
    HH (d, a, b, c, get32BitBlock (message, 8), 11, 0x8771f681); /* 34 */
    HH (c, d, a, b, get32BitBlock (message, 11), 16, 0x6d9d6122); /* 35 */
    HH (b, c, d, a, get32BitBlock (message, 14), 23, 0xfde5380c); /* 36 */
    HH (a, b, c, d, get32BitBlock (message, 1), 4, 0xa4beea44); /* 37 */
    HH (d, a, b, c, get32BitBlock (message, 4), 11, 0x4bdecfa9); /* 38 */
    HH (c, d, a, b, get32BitBlock (message, 7), 16, 0xf6bb4b60); /* 39 */
    HH (b, c, d, a, get32BitBlock (message, 10), 23, 0xbebfbc70); /* 40 */
    HH (a, b, c, d, get32BitBlock (message, 13), 4, 0x289b7ec6); /* 41 */
    HH (d, a, b, c, get32BitBlock (message, 0), 11, 0xeaa127fa); /* 42 */
    HH (c, d, a, b, get32BitBlock (message, 3), 16, 0xd4ef3085); /* 43 */
    HH (b, c, d, a, get32BitBlock (message, 6), 23,  0x4881d05); /* 44 */
    HH (a, b, c, d, get32BitBlock (message, 9), 4, 0xd9d4d039); /* 45 */
    HH (d, a, b, c, get32BitBlock (message, 12), 11, 0xe6db99e5); /* 46 */
    HH (c, d, a, b, get32BitBlock (message, 15), 16, 0x1fa27cf8); /* 47 */
    HH (b, c, d, a, get32BitBlock (message, 2), 23, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II (a, b, c, d, get32BitBlock (message, 0), 6, 0xf4292244); /* 49 */
    II (d, a, b, c, get32BitBlock (message, 7), 10, 0x432aff97); /* 50 */
    II (c, d, a, b, get32BitBlock (message, 14), 15, 0xab9423a7); /* 51 */
    II (b, c, d, a, get32BitBlock (message, 5), 21, 0xfc93a039); /* 52 */
    II (a, b, c, d, get32BitBlock (message, 12), 6, 0x655b59c3); /* 53 */
    II (d, a, b, c, get32BitBlock (message, 3), 10, 0x8f0ccc92); /* 54 */
    II (c, d, a, b, get32BitBlock (message, 10), 15, 0xffeff47d); /* 55 */
    II (b, c, d, a, get32BitBlock (message, 1), 21, 0x85845dd1); /* 56 */
    II (a, b, c, d, get32BitBlock (message, 8), 6, 0x6fa87e4f); /* 57 */
    II (d, a, b, c, get32BitBlock (message, 15), 10, 0xfe2ce6e0); /* 58 */
    II (c, d, a, b, get32BitBlock (message, 6), 15, 0xa3014314); /* 59 */
    II (b, c, d, a, get32BitBlock (message, 13), 21, 0x4e0811a1); /* 60 */
    II (a, b, c, d, get32BitBlock (message, 4), 6, 0xf7537e82); /* 61 */
    II (d, a, b, c, get32BitBlock (message, 11), 10, 0xbd3af235); /* 62 */
    II (c, d, a, b, get32BitBlock (message, 2), 15, 0x2ad7d2bb); /* 63 */
    II (b, c, d, a, get32BitBlock (message, 9), 21, 0xeb86d391); /* 64 */

    A += a;
    B += b;
    C += c;
    D += d;
}

/* step 5: output */
void output (uint32_t d, uint32_t c, uint32_t b, uint32_t a)
{
    a = swapByte32 (a);
    b = swapByte32 (b);
    c = swapByte32 (c);
    d = swapByte32 (d);
    unsigned char* result = malloc (129);
    result[0] = '\0';
    sprintf ((char*) result, "%08X%08X%08X%08X", (unsigned int) a, (unsigned int) b, (unsigned int) c, (unsigned int) d);
    printf ("md5: %s\n", result);
}

int main ()
{
    unsigned char* result;
    unsigned char* plainTextExample = (unsigned char*) "B";

    printf ("message: %s\n", plainTextExample);

    /* step 1 + 2: append padding bits */
    result = appendPaddingBitsToLastBlock (plainTextExample);
    printf ("after appending padding bits and length: ");
    for (int i = 0; i < 64; i++)
    {
        printf ("%c", *(result + i));
    }
    printf ("\n");
    print512BitStringToBin (result);
    printf ("\n");

    /* step 3: initialize MD buffer */
    initMDBuffer ();

    /* step 4: main MD5 function */
    md5 (result);

    /* step 5: output */
    output (D, C, B, A);

    return 0;
}
