#include <func.h>

void _start()
{
    int i = 0;
    int j = 94;

    while(1)
    {
        int a = add(i,j);
        int b = sub(j,i);
        int c = mul(i,j);
        int d = div(j,i);
        
        i+=5;
        j+=13;
    }
}
