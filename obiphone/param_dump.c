// arm-unknown-linux-gnueabi-g++ param_dump.c -o param_dump -I/path/to/buildroot-2013.05/output/build/openssl-1.0.1e/include -static -lcrypto
// *or*
// g++ param_dump.c -o param_dump -lcrypto


#include <stdio.h>
#include <cstring>
#include <string>
#include <map>
#include <memory>
#include <openssl/rc4.h>
#include <openssl/bio.h>

using namespace std;

map<string,string> init_map() {
 map<string,string> m;
 //manual
 m["f5e1d7f1"] = "DHCP/DefaultGateway";
 m["4d56eeaf"] = "X_GApiAccessToken";
 m["e261b32a"] = "VS1.VP1.L1.X_GApiRefreshToken";
 //auto
#include "param_dump_keys.h" 
 return m;
};

/*
template<typename ... Args>
string string_format_c11(const string& format, Args ... args)
{
    size_t size = snprintf(nullptr, 0, format.c_str(), args ...) + 1;
    unique_ptr<char[]> buf(new char[size]); 
    snprintf(buf.get(), size, format.c_str(), args ...);
    return string(buf.get(), buf.get() + size - 1);
}
*/

std::string string_format(const string& format, size_t size_man, ...)
{
    va_list args;
    va_start(args, size_man);
    //snprintf returns 20 instead of 8 for "%02x%02x%02x%02x". wtf?
    size_t size = size_man + 1; //snprintf(nullptr, 0, format.c_str(), args) + 1;
    char* buf = new char[size]; 
    vsnprintf(buf, size, format.c_str(), args);
    string str(buf, buf + size - 1);
    delete buf;
    return str;
    va_end(args);
}

void dump_section(FILE* file, size_t location, unsigned char mask[6]);
void dump_section_zt(FILE* file, size_t location, unsigned char mask[6]);

map<string,string> m = init_map();

int main(void)
{
    const char* mtd_name = "/dev/mtd11ro";
    const char* obiparam_name = "/scratch/obiparam.dat";

    static int PARAM_OFFSET = 0x20000;
    static int MTD_ZT_OFFSET = 0x340000;

    FILE* fd_mtd = fopen(mtd_name, "rb");

    if (!fd_mtd) {
      printf("ERROR: cannot open %s\n", mtd_name);
      return 1;
    }

    unsigned char mac[6];
    fseek(fd_mtd, 0x300100, SEEK_SET);
    fread(mac, sizeof(mac), 1, fd_mtd);

    unsigned char hw_vers[4];
    fseek(fd_mtd, 0x300010, SEEK_SET);
    fread(hw_vers, sizeof(hw_vers), 1, fd_mtd);

    printf("mac: %02x%02x%02x%02x%02x%02x, hw_vers: %02x%02x%02x%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           hw_vers[0], hw_vers[1], hw_vers[2], hw_vers[3]);

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

    unsigned char mask[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (need_mask) {
      memcpy(&mask[0], &mac[0], 6);
    }

    FILE* fd_param = fopen(obiparam_name, "rb");
    if (!fd_param) {
      printf("WARN: cannot open %s\n", obiparam_name);
    } else {
      dump_section(fd_param, PARAM_OFFSET, mask);
      fclose(fd_param);
    }

    dump_section_zt(fd_mtd, MTD_ZT_OFFSET, mask);
    
    fclose(fd_mtd);

    return 0;
}

void print_param(unsigned char* p)
{
        string param_key = string_format("%02x%02x%02x%02x", 8,
                  p[3], p[2], p[1], p[0]);

        string param_name = param_key + " (\?\?\?)";
        if (m.find(param_key) != m.end())
        {
          param_name = param_key + " (" + m[param_key] + ")";
        }

        for (int i = 0; i < 4; ++i)
             printf("%02x", p[i]);
        printf(" ");
        for (int i = 4; i < 8; ++i)
             printf("%02x", p[i]);

        printf(": ");
        printf(param_name.c_str());
        printf(" = ");

        int len = (p[5] << 8 | p[4]);
        int type = p[7];

        if (type == 1 || type == 4 || type == 5) {
            printf("\"%.*s\"", len, &p[8]);
        } else if (type == 2 || type == 3) {
            printf("0x");
            for (int i = 0; i < len; ++i)
              printf("%02x", p[i+8]);
        } else {
            printf("<<<bad format!>>>");
        }

        printf("\n");

}

void dump_section(FILE* file, size_t location, unsigned char mask[6])
{
    printf("-- params at %08x --\n", location);
    fseek( file, location + 0x100, SEEK_SET );

    int header_len  = 16;
    int payload_len = 240;

    unsigned char*  ciphertext = (unsigned char*) malloc(sizeof(char) * payload_len);
    unsigned char*  plaintext  = (unsigned char*) malloc(sizeof(char) * payload_len);
    unsigned char*  keytext    = (unsigned char*) malloc(sizeof(char) * header_len);

    while (fread(keytext, 1, header_len, file) == header_len &&
           keytext[0] != 0xFF) {

        fread(ciphertext, 1, payload_len, file);

        //little endian obi200
        if (keytext[0] == 0xFC)
          keytext[0] = 0xFE;
        else
          printf("WARN: unknown encrpytion type = %02x\n", keytext[0]);
 
        for (int i = 0; i < 6; ++i)
          keytext[i] &= mask[i];

        RC4_KEY key;
        RC4_set_key(&key, 15, keytext);

        RC4(&key, payload_len, ciphertext, plaintext);

        print_param(plaintext);
    }

    free(ciphertext);
    free(plaintext);
    free(keytext);
}

void dump_section_zt(FILE* file, size_t location, unsigned char mask[6])
{
    printf("-- params at %08x", location);
    fseek( file, location, SEEK_SET );

    int header_len = 256;

    unsigned char*  keytext    = (unsigned char*) malloc(sizeof(char) * header_len);

    fread(keytext, 1, header_len, file);

    int payload_len = keytext[15] << 24 |
                      keytext[14] << 16 |
                      keytext[13] << 8 |
                      keytext[12];

    printf("(length %d) --\n", payload_len);

    if (keytext[0] == 0xFF || payload_len < 0) {

      printf("no params found\n");

    } else {

        unsigned char*  ciphertext = (unsigned char*) malloc(sizeof(char) * payload_len);
        unsigned char*  plaintext  = (unsigned char*) malloc(sizeof(char) * payload_len);

        fread(ciphertext, 1, payload_len, file);

        //little endian obi200
        keytext[0] = 0xFD;

        for (int i = 0; i < 6; ++i)
          keytext[i] &= mask[i];

        //printf("payload length %d  using key: ", payload_len);
        //for (int i = 0; i < 15; ++i)
        //  printf("%02x", keytext[i]);
        //printf("\n");

        RC4_KEY key;
        RC4_set_key(&key, 15, keytext);

        RC4(&key, payload_len, ciphertext, plaintext);

        unsigned char* current = plaintext;
        while (current < plaintext + payload_len && current[0] != 0xff)
        {
          print_param(current);
          int len = 8 + (current[5] << 8 | current[4]);
          current += len;
        }

        printf("\n");

        free(ciphertext);
        free(plaintext);
    }

    free(keytext);

}
