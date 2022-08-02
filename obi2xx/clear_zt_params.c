//gcc clear_zt_params.c -o clear_zt_params -l crypto
// *or*
//arm-unknown-linux-gnueabi-gcc clear_zt_params.c -o clear_zt_params -L /path/to/openssl/lib -I /path/to/openssl/include

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

enum TYPE {
    TYPE_STRING = 0x01,
    TYPE_HEX = 0x03
};

typedef struct Klv {
    char key[4];
    char len;
    char type;
    char val[20];
} Klv;

void add_klv(unsigned char** c, Klv klv);

int main()
{
    int i;

    mtd_info_t mtd_info;
    int fd = open("/dev/mtd6", O_RDWR);
    ioctl(fd, MEMGETINFO, &mtd_info);
    //int fd = open("mtd6test", O_RDWR);
 
    //printf("MTD type: %u\n", mtd_info.type);
    //printf("MTD total size : %u bytes\n", mtd_info.size);
    //printf("MTD erase size : %u bytes\n", mtd_info.erasesize);

    unsigned char mac[6];
    lseek(fd, 0x40100, SEEK_SET);
    read(fd, mac, sizeof(mac));

    unsigned char hw_vers[4];
    lseek(fd, 0x40010, SEEK_SET);
    read(fd, hw_vers, sizeof(hw_vers));

    printf("mac: %02x%02x%02x%02x%02x%02x, hw_vers: %02x%02x%02x%02x\n", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           hw_vers[0], hw_vers[1], hw_vers[2], hw_vers[3]);

    typedef enum { false, true } bool;

    bool mask;
    if (hw_vers[0] == 0x00 && hw_vers[1] == 0x01 && hw_vers[3] == 0xff) {
      if (hw_vers[2] == 0x04 || hw_vers[2] == 0x05)
        mask = true;
      else if (hw_vers[2] == 0x00 || hw_vers[2] == 0x01 || hw_vers[2] == 0x02 || hw_vers[2] == 0x03)
        mask = false;
      else {
        printf("unknown hw_vers\n");
        return 1;
      }
    } else {
      printf("unknown hw_vers\n");
      return 1;
    }
    
    printf("using mac as rc4 key mask: %s\n", mask ? "true" : "false"); 


    static const int LEN = 0x200;
    unsigned char buf[LEN];
    lseek(fd, 0x460000, SEEK_SET);
    read(fd, buf, sizeof(buf));

    int* payload_len = (int*)&buf[0xC];
    *payload_len = 0x100;

    unsigned char plaintext_payload[0x100];
    for (i = 0; i < 0x100; ++i)
      plaintext_payload[i] = 0xff;

    unsigned char* c = plaintext_payload;

    Klv klv1 = {{0xA7, 0x80, 0xDD, 0xDB}, 9, TYPE_STRING, "xxxxxxxx"};
    srand(time(0));
    sprintf(&klv1.val[0], "%08d", rand() % 100000000);
    add_klv(&c,klv1);

    Klv klv2 = {{0x31, 0x8C, 0x16, 0xD1}, 4, TYPE_HEX, {0x01, 0x00, 0x00, 0x00}};
    add_klv(&c,klv2);

    Klv klv3 = {{0x25, 0xA4, 0xED, 0x70}, 8, TYPE_STRING, "Generic"};
    add_klv(&c,klv3);

    printf("plaintext_payload: ");
    for (i = 0; i < 0x100; ++i)
      printf("%02x", plaintext_payload[i]);
    printf("\n\n");


    unsigned char keytext[15];
    memcpy(&keytext[0], &buf[0], 15);

    keytext[0] = 0xfd;
    if (mask) {
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
        ei.length = 0x10000;
        ei.start = 0x460000;
    
        ioctl(fd, MEMUNLOCK, &ei);
        ioctl(fd, MEMERASE, &ei);
        lseek(fd, 0x460000, SEEK_SET);
        write(fd, buf, sizeof(buf));
        printf("\nflash written!\n");
    }

    close(fd);

    return 0;
}

void add_klv(unsigned char** c, Klv klv)
{
    char lt[] = {klv.len, 0x00, 0x00, klv.type};
    memcpy(&((*c)[0]),&klv.key,4);
    memcpy(&((*c)[4]),&lt,4);
    memcpy(&((*c)[8]),&klv.val,klv.len);
    *c+=8+klv.len;
}

