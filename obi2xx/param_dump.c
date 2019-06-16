// arm-unknown-linux-gnueabi-g++ -static param_dump.c -o param_dump -l:/path/to/static/openssl/lib/libcrypto.a -I /path/to/static/openssl/include
// *or*
// g++ param_dump.c -o param_dump -lcrypto

#include <stdio.h>
#include <string>
#include <map>
#include <memory>
#include <openssl/rc4.h>
#include <openssl/bio.h>
#include <cstring>

using namespace std;

void dump_section(FILE* file, size_t location, unsigned char mask[6]);
map<string,string> init_map();
string string_format(const string& format, size_t size_man, ...);
int print_param(unsigned char* p);
void print_params(unsigned char* plaintext, int payload_len);

static const int OFFSET_MAC = 0x40100;
static const int OFFSET_HWVERS = 0x40010;
static const int OFFSET_PARAM_1 = 0x400000;
static const int OFFSET_PARAM_2 = 0x420000;
static const int OFFSET_PARAM_ZT = 0x460000;
static bool debug = false;

map<string,string> m = init_map();

int main(int argc, char** argv)
{
    FILE* fd;

    if (argc < 2)
      fd = fopen("/dev/mtd6ro", "rb");
    else
      fd = fopen(argv[1], "rb");

    unsigned char mac[6];
    fseek(fd, OFFSET_MAC, SEEK_SET);
    fread(mac, sizeof(mac), 1, fd);

    unsigned char hw_vers[4];
    fseek(fd, OFFSET_HWVERS, SEEK_SET);
    fread(hw_vers, sizeof(hw_vers), 1, fd);

    printf("mac: %02x%02x%02x%02x%02x%02x, hw_vers: %02x%02x%02x%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           hw_vers[0], hw_vers[1], hw_vers[2], hw_vers[3]);

    bool need_mask;
    if (hw_vers[0] == 0x00 && hw_vers[1] == 0x01 && hw_vers[3] == 0xff) {
      if (hw_vers[2] == 0x04)
        need_mask = true;
      else if (hw_vers[2] == 0x00 || hw_vers[2] == 0x01 || hw_vers[2] == 0x02 || hw_vers[2] == 0x03)
        need_mask = false;
      else {
        printf("unknown hw_vers\n");
        return 1;
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

    dump_section(fd, OFFSET_PARAM_1, mask);
    dump_section(fd, OFFSET_PARAM_2, mask);
    dump_section(fd, OFFSET_PARAM_ZT, mask);
    
    fclose(fd);

    return 0;
}

unsigned long djb2(const char* str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

void addHash(map<string, string>& m, const char* val)
{
    char hash[9];
    sprintf(hash, "%08x", djb2(val));
    m[hash] = val;

    if (debug)
        printf("%s = %s\n", hash, val);
}

map<string,string> init_map() {
    map<string,string> m;
    //hidden or non-backup params
    addHash(m, "VoiceService.1.VoiceProfile.1.GVSIP");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.1.X_GApiRefreshToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.1.X_GApiAccessToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.1.X_GApiInitAccessToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.1.X_GoogleClientInfo");
    addHash(m, "VoiceService.1.VoiceProfile.2.GVSIP");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.2.X_GApiRefreshToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.2.X_GApiAccessToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.2.X_GApiInitAccessToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.2.X_GoogleClientInfo");
    addHash(m, "VoiceService.1.VoiceProfile.3.GVSIP");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.3.X_GApiRefreshToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.3.X_GApiAccessToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.3.X_GApiInitAccessToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.3.X_GoogleClientInfo");
    addHash(m, "VoiceService.1.VoiceProfile.4.GVSIP");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.4.X_GApiRefreshToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.4.X_GApiAccessToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.4.X_GApiInitAccessToken");
    addHash(m, "VoiceService.1.VoiceProfile.1.Line.4.X_GoogleClientInfo");
    //params in backup
    #include "param_dump_keys.h"
    return m;
};

string string_format(const string& format, size_t size_man, ...)
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

int print_param(unsigned char* p)
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

    int len = p[4] | p[5] << 8;
    //printf("[len %u] ", len);
    int type = p[7];

    if (type == 1 || type == 4 || type == 5) {
        printf("\"%.*s\"", len, &p[8]);
    } else {
        printf("0x");
        for (int i = 0; i < len; ++i)
            printf("%02x", p[i+8]);
    }

    printf("\n");

    return 8+len;
}

void print_params(unsigned char* plaintext, int payload_len)
{
    unsigned char* current = plaintext;
    while (current < plaintext + payload_len && 
           !(current[0] == 0xFF && current[1] == 0xFF && current[2] == 0xFF && current[3] == 0xFF))
    {
        current += print_param(current);
        //int len = 8 + (current[4] | p[current] << 8));
        //current += len;
    }
}

void dump_section(FILE* file, size_t location, unsigned char mask[6])
{
    printf("-- params at %08x --\n", location);

    static const int KEY_LENGTH = 15;
    unsigned char keytext[KEY_LENGTH];

    fseek( file, location, SEEK_SET );
    size_t current_loc = location;

    //first, read packed params at begninning

    static const int SECTION_HEADER_LEN = 256;
    unsigned char section_header[SECTION_HEADER_LEN];

    current_loc += fread(section_header, 1, SECTION_HEADER_LEN, file);

    int section_payload_len = section_header[15] << 24 |
                              section_header[14] << 16 |
                              section_header[13] << 8 |
                              section_header[12];

    unsigned char* section_ciphertext = (unsigned char*) malloc(section_payload_len);
    unsigned char* section_plaintext  = (unsigned char*) malloc(section_payload_len);

    current_loc += fread(section_ciphertext, 1, section_payload_len, file);

    memcpy(keytext, section_header, KEY_LENGTH);

    keytext[0] = 0xFD;
    for (int i = 0; i < 6; ++i)
        keytext[i] &= mask[i];

    RC4_KEY key;
    RC4_set_key(&key, KEY_LENGTH, keytext);

    RC4(&key, section_payload_len, section_ciphertext, section_plaintext);


    if (debug) {
        printf("raw section header: ", SECTION_HEADER_LEN);
        for (int i = 0; i < SECTION_HEADER_LEN; ++i)
          printf("%02x", section_header[i]);
        printf("\n");

        printf("raw section payload: ", section_payload_len);
        int checksum = 0;
        for (int i = 0; i < section_payload_len; ++i) {
            printf("%02x", section_plaintext[i]);
            checksum += *((signed char*)&section_plaintext[i]);
        }
        printf("\n");

        printf("checksum: %08x\n", checksum);
    }

    print_params(section_plaintext, section_payload_len);

    free(section_ciphertext);
    free(section_plaintext);




    //then, read remaining unpacked params

    static const int PARAM_HEADER_LEN = 16;
    unsigned char param_header[PARAM_HEADER_LEN];

    while (fread(param_header, 1, PARAM_HEADER_LEN, file) == PARAM_HEADER_LEN &&
           param_header[0] != 0xFF) {

        int param_payload_len = param_header[11] << 24 |
                                param_header[10] << 16 |
                                param_header[9] << 8 |
                                param_header[8];

        memcpy(keytext, param_header, KEY_LENGTH);

        unsigned char* param_ciphertext = (unsigned char*) malloc(param_payload_len);
        unsigned char* param_plaintext  = (unsigned char*) malloc(param_payload_len);

        fread(param_ciphertext, 1, param_payload_len, file);

        keytext[0] = 0xFE;
        for (int i = 0; i < 6; ++i)
          keytext[i] &= mask[i];

        RC4_KEY key;
        RC4_set_key(&key, KEY_LENGTH, keytext);

        RC4(&key, param_payload_len, param_ciphertext, param_plaintext);

        if (debug) {
            printf("@ %08x\n", current_loc);

            printf("raw header: ", PARAM_HEADER_LEN);
            for (int i = 0; i < PARAM_HEADER_LEN; ++i)
              printf("%02x", param_header[i]);
            printf("\n");

            printf("raw payload: ", param_payload_len);
            int checksum = 0;
            for (int i = 0; i < param_payload_len; ++i) {
                printf("%02x", param_plaintext[i]);
                checksum += *((signed char*)&param_plaintext[i]);
            }
            printf("\n");

            printf("checksum: %08x\n", checksum);
        }

        print_params(param_plaintext, param_payload_len);

        free(param_ciphertext);
        free(param_plaintext);

        current_loc += PARAM_HEADER_LEN + param_payload_len;
    }
}

