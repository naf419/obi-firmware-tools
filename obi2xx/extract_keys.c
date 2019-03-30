// arm-unknown-linux-gnueabi-gcc extract_keys.c -o extract_keys -l:/path/to/static/openssl/lib/libcrypto.a -I /path/to/static/openssl/include
// *or*
// gcc extract_keys.c -o extract_keys -lcrypto

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/rc4.h>
#include <openssl/bio.h>
#include <openssl/md5.h>

static const int OFFSET_UNIT_INFO = 0x40000;
static const int UNIT_INFO_HEADER_LEN = 0x60;

void write_bytes(const char* fname, unsigned char* bytes, int offset, int len)
{
    FILE* of = fopen(fname, "wb");
    fwrite(&bytes[offset], 1, len, of);
    fclose(of);
    printf("wrote %s\n", fname);
}

int main(int argc, char** argv)
{
    int i;

    FILE* fd;
    if (argc < 2)
      fd = fopen("/dev/mtd6ro", "rb");
    else
      fd = fopen(argv[1], "rb");


    unsigned char temp_header[UNIT_INFO_HEADER_LEN];
    fseek(fd, OFFSET_UNIT_INFO, SEEK_SET);
    fread(temp_header, UNIT_INFO_HEADER_LEN, 1, fd);

    int tot_length = ntohl(*(unsigned int*)&temp_header[0x28]);
    int enc_offset = ntohl(*(unsigned int*)&temp_header[0x34]);

    int enc_len = tot_length - enc_offset;
    int header_len = enc_offset;

    static const char* SALT = "thisisthesecretofobihaimfd";
    static const int SALT_LEN = 26;

    unsigned char* headertext = (unsigned char*) malloc(header_len+SALT_LEN);
    unsigned char* ciphertext = (unsigned char*) malloc(enc_len);
    unsigned char* plaintext  = (unsigned char*) malloc(enc_len);

    fseek(fd, OFFSET_UNIT_INFO, SEEK_SET);
    fread(headertext, header_len, 1, fd);

    fseek(fd, OFFSET_UNIT_INFO+enc_offset, SEEK_SET);
    fread(ciphertext, enc_len, 1, fd);

    
    memcpy(&headertext[header_len], SALT, SALT_LEN);
    for (i = 0x14; i < 0x24; ++i)
      headertext[i] = 0xff;
    unsigned char md5[16];


    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, headertext, header_len+SALT_LEN);
    MD5_Final(md5, &c);
    

    static const int KEY_LENGTH = 15;
    unsigned char keytext[KEY_LENGTH];
    memcpy(keytext, md5, KEY_LENGTH);

    RC4_KEY key;
    RC4_set_key(&key, KEY_LENGTH, keytext);
    RC4(&key, enc_len, ciphertext, plaintext);

    int key_off = ntohl(*(unsigned int*)&headertext[0x40]);
    int key_len = ntohl(*(unsigned int*)&headertext[0x44]);
    
    write_bytes("/var/tmp/client.der.key", plaintext,
                key_off-enc_offset, key_len);


    int crt_off = ntohl(*(unsigned int*)&headertext[0x4c]);
    int crt_len = ntohl(*(unsigned int*)&headertext[0x50]);

    write_bytes("/var/tmp/client.der.crt", plaintext, 
                crt_off-enc_offset, crt_len);

    free(headertext);
    free(ciphertext);
    free(plaintext);
}

