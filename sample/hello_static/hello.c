#include <stdio.h>
#include <stdlib.h>

static int bss_var;
static int data_var = 0xbef03e; //before

int main()
{
  bss_var = 0x13371337;
  int stack_var = 0xcafecafe;
  int *heap_var = (int *) malloc(sizeof(int));
  *heap_var = 0xabcdabcd;

  printf("bss_var....[%p]=0x%08x\n", &bss_var, bss_var);
  printf("data_var...[%p]=0x%08x\n", &data_var, data_var);
  printf("stack_var..[%p]=0x%08x\n", &stack_var, stack_var);
  printf("heap_var...[%p]=0x%08x\n", heap_var, *heap_var);

  data_var = 0xaf7e3;   //after
  
  getc(stdin);

  return 0;
}
