// arm-unknown-linux-gnueabi-gcc param_dump.c -o param_dump -L /path/to/openssl/lib -l crypto -I /path/to/openssl/include
// *or*
// gcc param_dump.c -o param_dump -lcrypto

#define _GNU_SOURCE //for asprintf

#include <stdio.h>
#include <openssl/rc4.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdlib.h>

typedef struct Map Map;
void map_init();
const char* map_get(Map* table, const unsigned int key);
int map_insert(Map* table, const unsigned int key, const char* value);
void map_free(Map* table);
Map m;

void dump_section(FILE* file, size_t location, unsigned char mask[6]);

static const int OFFSET_MAC = 0x40100;
static const int OFFSET_HWVERS = 0x40010;
static const int OFFSET_PARAM_1 = 0x400000;
static const int OFFSET_PARAM_2 = 0x420000;
static const int OFFSET_PARAM_ZT = 0x460000;
static int debug = 0;

int main(int argc, char** argv)
{
    map_init();

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

    int need_mask;
    if (hw_vers[0] == 0x00 && hw_vers[1] == 0x01 && hw_vers[3] == 0xff) {
      if (hw_vers[2] == 0x04 || hw_vers[2] == 0x05)
        need_mask = 1;
      else if (hw_vers[2] == 0x00 || hw_vers[2] == 0x01 || hw_vers[2] == 0x02 || hw_vers[2] == 0x03)
        need_mask = 0;
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

    map_free(&m);

    return 0;
}

int print_param(unsigned char* p)
{
    unsigned int param_key = p[3] << 24 | p[2] << 16 | p[1] << 8 | p[0];

    const char* param_key_name = map_get(&m, param_key);

    int i;
    for (i = 0; i < 4; ++i)
         printf("%02x", p[i]);
    printf(" ");
    for (i = 4; i < 8; ++i)
         printf("%02x", p[i]);
    printf(": ");

    printf("%08x (%s)", param_key, param_key_name != NULL ? param_key_name : "");
    printf(" = ");

    int len = p[4] | p[5] << 8;
    //printf("[len %u] ", len);
    int type = p[7];

    if (type == 1 || type == 4 || type == 5) {
        printf("\"%.*s\"", len, &p[8]);
    } else {
        printf("0x");
        for (i = 0; i < len; ++i)
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

    unsigned char* section_ciphertext = malloc(section_payload_len);
    unsigned char* section_plaintext  = malloc(section_payload_len);

    current_loc += fread(section_ciphertext, 1, section_payload_len, file);

    memcpy(keytext, section_header, KEY_LENGTH);

    keytext[0] = 0xFD;
    int i;
    for (i = 0; i < 6; ++i)
        keytext[i] &= mask[i];

    RC4_KEY key;
    RC4_set_key(&key, KEY_LENGTH, keytext);

    RC4(&key, section_payload_len, section_ciphertext, section_plaintext);


    if (debug) {
        printf("raw section header: ", SECTION_HEADER_LEN);
        for (i = 0; i < SECTION_HEADER_LEN; ++i)
          printf("%02x", section_header[i]);
        printf("\n");

        printf("raw section payload: ", section_payload_len);
        int checksum = 0;
        for (i = 0; i < section_payload_len; ++i) {
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

        unsigned char* param_ciphertext = malloc(param_payload_len);
        unsigned char* param_plaintext  = malloc(param_payload_len);

        fread(param_ciphertext, 1, param_payload_len, file);

        keytext[0] = 0xFE;
        for (i = 0; i < 6; ++i)
          keytext[i] &= mask[i];

        RC4_KEY key;
        RC4_set_key(&key, KEY_LENGTH, keytext);

        RC4(&key, param_payload_len, param_ciphertext, param_plaintext);

        if (debug) {
            printf("@ %08x\n", current_loc);

            printf("raw header: ", PARAM_HEADER_LEN);
            for (i = 0; i < PARAM_HEADER_LEN; ++i)
              printf("%02x", param_header[i]);
            printf("\n");

            printf("raw payload: ", param_payload_len);
            int checksum = 0;
            for (i = 0; i < param_payload_len; ++i) {
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

//simple hashmap, we dont need no stinkin c++ std::map
#define MAP_BUCKETS 1024
struct MapNode {
    unsigned int key;
    const char* value;
    struct MapNode* next;
};
struct Map {
    struct MapNode* buckets[MAP_BUCKETS];
};

unsigned int djb2(const char* str)
{
    unsigned int hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; // hash * 33 + c

    return hash;
}

void addHash(Map* m, const char* val)
{
    map_insert(m, djb2(val), val);
}

void addHashIndexed(Map* m, const char* fmt, int i)
{
    char* tmp;
    asprintf(&tmp, fmt, i);
    map_insert(m, djb2(tmp), tmp);
    free(tmp);
}

void map_init() {
    //hidden or non-backup params
    int i;
    for (i = 1; i <= 4; ++i) {
      addHashIndexed(&m, "VoiceService.1.VoiceProfile.%d.GVSIP", i);
      addHashIndexed(&m, "VoiceService.1.VoiceProfile.1.Line.%d.X_GApiRefreshToken", i);
      addHashIndexed(&m, "VoiceService.1.VoiceProfile.1.Line.%d.X_GApiAccessToken", i);
      addHashIndexed(&m, "VoiceService.1.VoiceProfile.1.Line.%d.X_GApiInitAccessToken", i);
      addHashIndexed(&m, "VoiceService.1.VoiceProfile.1.Line.%d.X_GoogleClientInfo", i);
    }

    addHash(&m, "X_DeviceManagement.License.LicenseURL");

    addHash(&m, "SystemInfo.DisableBT");
    addHash(&m, "SystemInfo.DisableFXO");
    addHash(&m, "SystemInfo.DisableFXS1");
    addHash(&m, "SystemInfo.DisableFXS2");
    addHash(&m, "SystemInfo.DisableGVProv");
    addHash(&m, "SystemInfo.DisableRouterCfg");
    addHash(&m, "SystemInfo.SkypeDisable");
    addHash(&m, "SystemInfo.X_GVAutoSetting");

    addHash(&m, "VoiceService.1.X_OBP.Forbidden");
    addHash(&m, "VoiceService.1.X_OBP.BasicLicense");
    addHash(&m, "VoiceService.1.X_OBP.NoLicense");
    addHash(&m, "VoiceService.1.X_OBP.License");

    for (i = 0; i < 8; ++i) {
        addHashIndexed(&m, "X_DeviceManagement.Provisioning.SPRM%d", i);
        addHashIndexed(&m, "X_DeviceManagement.ITSPProvisioning.SPRM%d", i);
    }

    for (i = 4; i <=31; ++i) {
        addHashIndexed(&m, "X_DeviceManagement.X_UserDefinedMacro.%d.Value", i);
        addHashIndexed(&m, "X_DeviceManagement.X_UserDefinedMacro.%d.ExpandIn", i);
        addHashIndexed(&m, "X_DeviceManagement.X_UserDefinedMacro.%d.SyntaxCheckResult", i);
    }

    //params in backup
    #include "param_dump_keys.h"
};

const char* map_get(Map* table, const unsigned int key)
{
    unsigned int bucket = key % MAP_BUCKETS;
    struct MapNode* node;
    node = table->buckets[bucket];
    while(node) {
        if(key == node->key)
            return node->value;
        node = node->next;
    }
    return NULL;
}

int map_insert(Map* table, const unsigned int key, const char* value)
{
    unsigned int bucket = key % MAP_BUCKETS;
    struct MapNode** node;

    char* value_copy;
    asprintf(&value_copy, "%s", value); //free'd in map_free()

    node = &table->buckets[bucket];
    while(*node)
        node = &(*node)->next;

    *node = malloc(sizeof(struct MapNode)); //free'd in map_free()
    if(*node == NULL)
        return -1;
    (*node)->next = NULL;
    (*node)->key = key;
    (*node)->value = value_copy;

    return 0;
}

void map_free(Map* table)
{
    unsigned int bucket;
    struct MapNode* node;
    struct MapNode* next;
    for (bucket = 0; bucket < MAP_BUCKETS; bucket++) {
        node = table->buckets[bucket];
        while(node) {
            next = node->next;
            free((void*)node->value);
            free(node);
            node = next;
        }
    }
}
