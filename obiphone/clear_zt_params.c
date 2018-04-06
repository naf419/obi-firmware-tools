//gcc clear_zt_params.c -o clear_zt_params
// *or*
//arm-unknown-linux-gnueabi-gcc clear_zt_params.c -o clear_zt_params -I/path/to/cross-obi1000/buildroot-2013.05/output/build/openssl-1.0.1e/include -lcrypto

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>
#include <string.h>
#include <time.h>
#include <openssl/rc4.h>
#include <openssl/bio.h> 


int main()
{
    int i;

    FILE* fd_mtd11 = fopen("/dev/mtd11ro", "rb");

    unsigned char mac[6];
    fseek(fd_mtd11, 0x300100, SEEK_SET);
    fread(mac, sizeof(mac), 1, fd_mtd11);

    unsigned char hw_vers[4];
    fseek(fd_mtd11, 0x300010, SEEK_SET);
    fread(hw_vers, sizeof(hw_vers), 1, fd_mtd11);

    fclose(fd_mtd11);




    mtd_info_t mtd_info;
    int fd = open("/dev/mtd2", O_RDWR);
    ioctl(fd, MEMGETINFO, &mtd_info);
    //int fd = open("mtd2test", O_RDWR);
 
    printf("MTD type: %u\n", mtd_info.type);
    printf("MTD total size : %u bytes\n", mtd_info.size);
    printf("MTD erase size : %u bytes\n", mtd_info.erasesize);

    printf("mac: %02x%02x%02x%02x%02x%02x, hw_vers: %02x%02x%02x%02x\n", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           hw_vers[0], hw_vers[1], hw_vers[2], hw_vers[3]);

    typedef enum { false, true } bool;

    bool need_mask;
    if (hw_vers[0] == 0x00 && hw_vers[1] == 0x01 && hw_vers[3] == 0xff) {
      if (hw_vers[2] == 0x03)
        need_mask = true;
      else {
        printf("WARN: unknown hw_vers. assuming need_mask = true\n");
        need_mask = true;
      }
    } else {
      printf("unknown hw_vers\n");
      return 1;
    }
 
    printf("using mac as rc4 key mask: %s\n", need_mask ? "true" : "false"); 

    static const int CUSTOM_OFFSET=0x180000;

    static const int LEN = 0x20000;
    unsigned char buf[LEN]; // = (unsigned char*) malloc(LEN);
    lseek(fd, CUSTOM_OFFSET, SEEK_SET);
    read(fd, buf, sizeof(buf));

    //only keep header
    for(i = 0x100; i < LEN; ++i)
      buf[i] = 0xff;

    int* payload_len = (int*)&buf[0xC];
    *payload_len = 0x100;

    unsigned char plaintext_payload[0x100];
    for (i = 0; i < 0x100; ++i)
      plaintext_payload[i] = 0xff;

int b = 0;
plaintext_payload[b++] = 0xA7;
plaintext_payload[b++] = 0x80;
plaintext_payload[b++] = 0xDD;
plaintext_payload[b++] = 0xDB;
plaintext_payload[b++] = 0x09;
plaintext_payload[b++] = 0x00;
plaintext_payload[b++] = 0x00;
plaintext_payload[b++] = 0x01;
plaintext_payload[b++] = 0x38;
plaintext_payload[b++] = 0x35;
plaintext_payload[b++] = 0x34;
plaintext_payload[b++] = 0x32;
plaintext_payload[b++] = 0x37;
plaintext_payload[b++] = 0x33;
plaintext_payload[b++] = 0x35;
plaintext_payload[b++] = 0x34;
plaintext_payload[b++] = 0x00;
plaintext_payload[b++] = 0x31;
plaintext_payload[b++] = 0x8C;
plaintext_payload[b++] = 0x16;
plaintext_payload[b++] = 0xD1;
plaintext_payload[b++] = 0x04;
plaintext_payload[b++] = 0x00;
plaintext_payload[b++] = 0x00;
plaintext_payload[b++] = 0x03;
plaintext_payload[b++] = 0x01;
plaintext_payload[b++] = 0x00;
plaintext_payload[b++] = 0x00;
plaintext_payload[b++] = 0x00;
plaintext_payload[b++] = 0x25;
plaintext_payload[b++] = 0xA4;
plaintext_payload[b++] = 0xED;
plaintext_payload[b++] = 0x70;
plaintext_payload[b++] = 0x08;
plaintext_payload[b++] = 0x00;
plaintext_payload[b++] = 0x00;
plaintext_payload[b++] = 0x01;
plaintext_payload[b++] = 0x47;
plaintext_payload[b++] = 0x65;
plaintext_payload[b++] = 0x6E;
plaintext_payload[b++] = 0x65;
plaintext_payload[b++] = 0x72;
plaintext_payload[b++] = 0x69;
plaintext_payload[b++] = 0x63;
plaintext_payload[b++] = 0x00;

    char* zt_id = (char*)&plaintext_payload[8];
    srand(time(0));
    sprintf(zt_id, "%08d", rand() % 100000000);

    
    printf("plaintext_payload: ");
    for (i = 0; i < 0x100; ++i)
      printf("%02x", plaintext_payload[i]);
    printf("\n\n");


    unsigned char keytext[15];
    memcpy(&keytext[0], &buf[0], 15);

    keytext[0] = 0xfd;
    if (need_mask) {
      for (i = 0; i < 6; ++i)
        keytext[i] &= mac[i];
    }

    printf("using RC4 key: ");
    for (i = 0; i < 15; ++i)
      printf("%02x", keytext[i]);
    printf("\n");

    RC4_KEY key;
    RC4_set_key(&key, 15, keytext);

    RC4(&key, *payload_len, plaintext_payload, &buf[0x100]);


    printf("new contents: ");
    for (i = 0; i < LEN; ++i)
      printf("%02x", buf[i]);
    printf("\n\n");

    printf("new payload_len = %d\n", *payload_len);



  char answer;
  printf("\nEnter 'y' to write to flash:\n");
  scanf(" %c", &answer);
  if (answer == 'y')
  {
  


    erase_info_t ei;
    ei.length = 0x20000;
    ei.start = CUSTOM_OFFSET;
    
    ioctl(fd, MEMUNLOCK, &ei);
    ioctl(fd, MEMERASE, &ei);
    lseek(fd, CUSTOM_OFFSET, SEEK_SET);
    write(fd, buf, sizeof(buf));
    printf("\nflash written!\n");
  }

    close(fd);

    return 0;
}

