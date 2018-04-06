// arm-unknown-linux-gnueabi-g++ -static param_dump.c -o param_dump -l:/path/to/static/openssl/lib/libcrypto.a -I /path/to/static/openssl/include
// *or*
// g++ param_dump.c -o param_dump -lcrypto


#include <stdio.h>
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

void dump_section(FILE* file, size_t location);

int header_len  = 16;
int payload_len = 240;
map<string,string> m = init_map();

int main(void)
{
    FILE* file;
    file = fopen("/dev/mtd6ro", "rb");
    //file = fopen("mtd6ro", "rb");
    dump_section(file, 0x400000);
    dump_section(file, 0x420000);
    dump_section(file, 0x460000);
    fclose(file);

    return 0;
}

void dump_section(FILE* file, size_t location)
{
    printf("-- params at %08x --\n", location);
    fseek( file, location + 0x100, SEEK_SET );

    unsigned char*  ciphertext = (unsigned char*) malloc(sizeof(char) * payload_len);
    unsigned char*  plaintext  = (unsigned char*) malloc(sizeof(char) * payload_len);
    unsigned char*  keytext    = (unsigned char*) malloc(sizeof(char) * header_len);


    while (fread(keytext, 1, header_len, file) == header_len &&
           keytext[0] != 0xFF) {

        fread(ciphertext, 1, payload_len, file);

        //little endian obi200
        keytext[0] = 0xFE;
    
        //big endian obi100
        //keytext[3] = 0xFE;

        RC4_KEY key;
        RC4_set_key(&key, 15, keytext);

        RC4(&key, payload_len, ciphertext, plaintext);

        string param_key = string_format("%02x%02x%02x%02x", 8,
                  plaintext[3], plaintext[2], plaintext[1], plaintext[0]);

        
        string param_name = param_key + "???";
        if (m.find(param_key) != m.end())
        {
          param_name = m[param_key];
        }

        for (int i = 0; i < 4; ++i)
             printf("%02x", plaintext[i]); 
        printf(" ");
        for (int i = 4; i < 8; ++i)
             printf("%02x", plaintext[i]);
 
        printf(": ");
        printf(param_name.c_str());
        printf("=");

        if (plaintext[7] == 1) {
            plaintext[239] = 0;
            printf("%s", &plaintext[8]);
        } else {
            for (int i = 0; i < 4; ++i)
            printf("%02x", plaintext[i+8]);
        }

        printf("\n");    
    }

    free(ciphertext);
    free(plaintext);
    free(keytext);
}
