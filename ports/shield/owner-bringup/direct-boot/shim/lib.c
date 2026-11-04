/* Minimal freestanding C library for the shim. */
#include <string.h>
#include <stdlib.h>
void *memcpy(void *d, const void *s, size_t n){unsigned char*a=d;const unsigned char*b=s;while(n--)*a++=*b++;return d;}
void *memmove(void *d, const void *s, size_t n){unsigned char*a=d;const unsigned char*b=s;if(a<b){while(n--)*a++=*b++;}else if(a>b){a+=n;b+=n;while(n--)*--a=*--b;}return d;}
void *memset(void *d, int c, size_t n){unsigned char*a=d;while(n--)*a++=(unsigned char)c;return d;}
int memcmp(const void *x, const void *y, size_t n){const unsigned char*a=x,*b=y;for(;n;n--,a++,b++)if(*a!=*b)return *a-*b;return 0;}
void *memchr(const void *s, int c, size_t n){const unsigned char*a=s;for(;n;n--,a++)if(*a==(unsigned char)c)return (void*)a;return 0;}
size_t strlen(const char *s){size_t n=0;while(s[n])n++;return n;}
size_t strnlen(const char *s, size_t m){size_t n=0;while(n<m&&s[n])n++;return n;}
char *strchr(const char *s, int c){for(;;s++){if(*s==(char)c)return (char*)s;if(!*s)return 0;}}
char *strrchr(const char *s, int c){const char*r=0;for(;;s++){if(*s==(char)c)r=s;if(!*s)return (char*)r;}}
int strcmp(const char *a, const char *b){while(*a&&*a==*b){a++;b++;}return (unsigned char)*a-(unsigned char)*b;}
int strncmp(const char *a, const char *b, size_t n){for(;n;n--,a++,b++){if(*a!=*b)return (unsigned char)*a-(unsigned char)*b;if(!*a)return 0;}return 0;}
unsigned long strtoul(const char *s, char **end, int base){unsigned long v=0;
 if(base==0){base=10;if(s[0]=='0'&&(s[1]=='x'||s[1]=='X')){base=16;s+=2;}}
 else if(base==16&&s[0]=='0'&&(s[1]=='x'||s[1]=='X'))s+=2;
 for(;;s++){int d;char c=*s;if(c>='0'&&c<='9')d=c-'0';else if(c>='a'&&c<='f')d=c-'a'+10;else if(c>='A'&&c<='F')d=c-'A'+10;else break;if(d>=base)break;v=v*base+d;}
 if(end)*end=(char*)s;return v;}
