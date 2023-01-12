#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

int target_func(char* bf, int size) {
  char* buf = (char*)malloc(size);
  memcpy(buf, bf, size);

  switch (buf[0]) {
    case 1:
      if(buf[1]=='\x44') {
         *(char*)(0) = 1;
      }
      break;
    case '\xfe':
      if(buf[4]=='\xf0') {
          assert(0);
      }
      break;
    case 0xff:
      if(buf[2]=='\xff') {
        sleep(2);
      }
      break;
    case  'a':
      buf[2] = 23;
      if (buf[1] == 'b') return 20;
    default:
      break;
  }

  free(buf);
  return 1;
}

int main(int argc, char* argv[]) {
  if (argc < 2) exit(-1);
  
  target_func(argv[1], strlen(argv[1]));
  while (1)
    sleep(1);

  return 0;

}

