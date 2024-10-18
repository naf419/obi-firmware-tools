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

#if OBI_DEVICE == 200
  #define OFFSET_MAC 0x40100
  #define OFFSET_HWVERS 0x40010
  #define OFFSET_PARAM_1 0x400000
  #define OFFSET_PARAM_2 0x420000
  #define OFFSET_PARAM_ZT 0x460000
  #define MTD_DEV "/dev/mtd6ro"
  #define PARAMS_DEV "/dev/mtd6ro"
#elif OBI_DEVICE == 500
  #define OFFSET_MAC 0xA0100
  #define OFFSET_HWVERS 0xA0010
  #define OFFSET_PARAM_1 0x1F00000
  #define OFFSET_PARAM_2 0x1F80000
  #define OFFSET_PARAM_ZT 0xB0000
  #define MTD_DEV "/dev/mtd5ro"
  #define PARAMS_DEV "/dev/mtd5ro"
#elif OBI_DEVICE == 1000
  #define OFFSET_MAC 0x300100
  #define OFFSET_HWVERS 0x300010
  #define OFFSET_PARAM_1 0x0
  #define OFFSET_PARAM_2 0x20000
  #define OFFSET_PARAM_ZT 0x340000
  #define MTD_DEV "/dev/mtd11ro"
  #define PARAMS_DEV "/scratch/obiparam.dat"
#elif OBI_DEVICE == 2000
  #define OFFSET_MAC 0x100100
  #define OFFSET_HWVERS 0x100010
  #define OFFSET_PARAM_1 0x0
  #define OFFSET_PARAM_2 0x20000
  #define OFFSET_PARAM_ZT 0x180000
  #define MTD_DEV "/dev/mtd2ro"
  #define PARAMS_DEV "/scratch/obiparam.dat"
#elif OBI_DEVICE == 1000
  #define OFFSET_MAC 0x300100
  #define OFFSET_HWVERS 0x300010
  #define OFFSET_PARAM_1 0x0
  #define OFFSET_PARAM_2 0x20000
  #define OFFSET_PARAM_ZT 0x340000
  #define MTD_DEV "/dev/mtd11ro"
  #define PARAMS_DEV "/scratch/obiparam.dat"
#elif OBI_DEVICE == 500
  #define OFFSET_MAC 0xA0100
  #define OFFSET_HWVERS 0xA0010
  #define OFFSET_PARAM_1 0x1F00000
  #define OFFSET_PARAM_2 0x1F80000
  #define OFFSET_PARAM_ZT 0xB0000
  #define MTD_DEV "/dev/mtd5ro"
  #define PARAMS_DEV "/dev/mtd5ro"
#elif OBI_DEVICE == 230
  #define OFFSET_PARAM_1 0x0
  #define OFFSET_PARAM_2 0x80000
  #define OFFSET_PARAM_ZT 0x0
  #define MTD_DEV "/scratch/obizt.dat"
  #define PARAMS_DEV "/scratch/obiparam.dat"
#else
  #error "Must define OBI_DEVICE to be 200/500/1000/2000"
#endif

static int debug = 0;

int main(int argc, char** argv)
{
    map_init();

    char* mtd_name;
    char* obiparam_name;

    FILE* fd_mtd;

    if (argc == 3) {
      mtd_name = argv[1];
      obiparam_name = argv[2];
    } else if (argc == 2) {
      mtd_name = argv[1];
      obiparam_name = argv[1];
    } else {
      mtd_name = MTD_DEV;
      obiparam_name = PARAMS_DEV;
    }

    fd_mtd = fopen(mtd_name, "rb");
    if (!fd_mtd) {
      printf("ERROR: cannot open %s\n", mtd_name);
      return 1;
    }

    int need_mask;
    unsigned char mac[6];
    unsigned char hw_vers[4];
#if OBI_DEVICE != 230
    fseek(fd_mtd, OFFSET_MAC, SEEK_SET);
    fread(mac, sizeof(mac), 1, fd_mtd);

    fseek(fd_mtd, OFFSET_HWVERS, SEEK_SET);
    fread(hw_vers, sizeof(hw_vers), 1, fd_mtd);

    printf("mac: %02x%02x%02x%02x%02x%02x, hw_vers: %02x%02x%02x%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           hw_vers[0], hw_vers[1], hw_vers[2], hw_vers[3]);

    if (!(hw_vers[0] == 0x00 && hw_vers[1] == 0x01 && hw_vers[3] == 0xff)) {
      printf("unknown hw_vers\n");
      return 1;
    }
#endif

#if OBI_DEVICE == 200
    if (hw_vers[2] == 0x04 || hw_vers[2] == 0x05)
      need_mask = 1;
    else if (hw_vers[2] == 0x00 || hw_vers[2] == 0x01 || hw_vers[2] == 0x02 || hw_vers[2] == 0x03)
      need_mask = 0;
    else {
      printf("unknown hw_vers\n");
      return 1;
    }
#elif OBI_DEVICE == 230
    printf("assuming need_mask = false\n");
    need_mask = 0;
#else
    printf("assuming need_mask = true\n");
    need_mask = 1;
#endif

    printf("using mac as rc4 key mask: %s\n", need_mask ? "true" : "false");

    unsigned char mask[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (need_mask) {
      memcpy(&mask[0], &mac[0], 6);
    }

    FILE* fd_param = fopen(obiparam_name, "rb");
    if (!fd_param) {
      printf("WARN: cannot open %s\n", obiparam_name);
    } else {
      dump_section(fd_param, OFFSET_PARAM_1, mask);
      dump_section(fd_param, OFFSET_PARAM_2, mask);
      fclose(fd_param);
    }

    dump_section(fd_mtd, OFFSET_PARAM_ZT, mask);
    
    fclose(fd_mtd);

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
    static int MIN_PARAM_LEN = 8;
    unsigned char* current = plaintext;
    while (current + MIN_PARAM_LEN < plaintext + payload_len && 
           !(current[0] == 0xFF && current[1] == 0xFF && current[2] == 0xFF && current[3] == 0xFF))
    {
        current += print_param(current);
    }
}

void warn_on_checksum_mismatch(unsigned char* data, int len, int expected) {
    int checksum = 0;
    int i;
    for (i = 0; i < len; ++i) {
        checksum += *((signed char*)&data[i]);
    }
    if (expected != checksum) {
        printf("WARN: checksum mismatch. expect=%08x calc=%08x\n", expected, checksum);
    }
}

void dump_section(FILE* file, size_t location, unsigned char mask[6])
{
    int i;
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

    if (debug) {
        printf("raw section header: ", SECTION_HEADER_LEN);
        for (i = 0; i < SECTION_HEADER_LEN; ++i)
          printf("%02x", section_header[i]);
        printf("\n");
    }

    if (section_header[0] == 0xFF && section_header[1] == 0xFF &&
        section_header[2] == 0xFF && section_header[3] == 0xFF) {
        printf("WARN: empty section header\n");
        return;
    } else if (section_header[0] != 0xFD && section_header[0] != 0xFB) {
        printf("ERROR: unknown packed encryption scheme: %02x\n", section_header[0]);
        return;
    }

    unsigned char* section_ciphertext = malloc(section_payload_len);
    unsigned char* section_plaintext  = malloc(section_payload_len);

    current_loc += fread(section_ciphertext, 1, section_payload_len, file);

    memcpy(keytext, section_header, KEY_LENGTH);

    keytext[0] = 0xFD;
    for (i = 0; i < 6; ++i)
        keytext[i] &= mask[i];

    RC4_KEY key;
    RC4_set_key(&key, KEY_LENGTH, keytext);

    RC4(&key, section_payload_len, section_ciphertext, section_plaintext);


    if (debug) {
        printf("raw section payload: ", section_payload_len);
        for (i = 0; i < section_payload_len; ++i) {
            printf("%02x", section_plaintext[i]);
        }
        printf("\n");
    }

    print_params(section_plaintext, section_payload_len);

    int section_checksum = section_header[11] << 24 |
                           section_header[10] << 16 |
                           section_header[9] << 8 |
                           section_header[8];

    warn_on_checksum_mismatch(section_plaintext, section_payload_len, section_checksum);

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

        if (debug) {
            printf("@ %08x\n", current_loc);

            printf("raw header: ", PARAM_HEADER_LEN);
            for (i = 0; i < PARAM_HEADER_LEN; ++i)
              printf("%02x", param_header[i]);
            printf("\n");
        }

        if (param_header[0] != 0xFC) {
            printf("ERROR: unknown unpacked encryption scheme: %02x\n", param_header[0]);
            return;
        }

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
            printf("raw payload: ", param_payload_len);
            for (i = 0; i < param_payload_len; ++i) {
                printf("%02x", param_plaintext[i]);
            }
            printf("\n");
        }

        int param_checksum = param_header[15] << 24 |
                             param_header[14] << 16 |
                             param_header[13] << 8 |
                             param_header[12];

        warn_on_checksum_mismatch(param_plaintext, param_payload_len, param_checksum);

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
