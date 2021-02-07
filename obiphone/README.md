Firmware file starts with a 0x400 byte header, which describes the other sections of the file:

```
000 4f 42 69 50 48 4f 4e 45 5f 46 57 5f 50 4b 47 30  constant "OBiPHONE_FW_PKG0"
010 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
020 09 21 5c 61 94 31 54 0b 8b 00 a6 6e 79 c5 24 34  0x28=md5 of "Goodbye! Reboot Now" + this 0x400-length header with 0x28 zerod out
030 73 b8 ed cc 5d 77 99 ed 78 fe 7d 7e 6f 03 51 16
040 35 2e 31 2e 34 20 28 42 75 69 6c 64 3a 20 34 30  version# string
050 32 37 2e 31 33 31 31 29 00 00 00 00 00 00 00 00
060 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
070 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
080 06 00 00 00 90 09 e1 01 00 00 00 00 00 00 00 00  0x80=#segments, 0x84=total fw file length
090 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0a0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0b0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c0 05 00 00 00 00 04 00 00 00 00 40 00 28 c9 2c 00  type 5 (kernel)
0d0 87 53 9b 1a a2 7d f9 6b f7 4c 54 72 d6 16 95 69  md5 of section payload
0e0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0f0 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00
100 03 01 01 00 28 cd 2c 00 00 00 c0 01 5e 41 3e 00  type 3 (obi)
110 7a 53 41 91 3b 04 b2 49 f5 0a f0 da 91 bd 2e 55
120 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
130 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00
140 0b 01 01 00 86 0e 6b 00 00 00 c0 06 6a d3 98 00  type b (scratch)
150 8c 53 e8 6c 70 7e 41 b4 65 7d 1e 62 2b a2 1e 10
160 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
170 00 00 40 01 00 00 00 00 00 00 00 00 00 00 00 00
180 04 01 01 00 f0 e1 03 01 00 00 80 00 c4 5a d8 00  type 4 (rootfs)
190 11 88 ba 63 60 9d 58 f9 14 93 e8 ee 79 22 08 bf
1a0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
1b0 00 00 40 01 00 00 00 00 00 00 00 00 00 00 00 00
1c0 02 01 00 00 b4 3c dc 01 00 00 00 00 d8 bc 04 00  type 2 (uboot)
1d0 85 9c 94 b8 b6 67 14 45 0b 46 e6 63 74 24 54 f2
1e0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
1f0 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00
200 08 01 00 00 8c f9 e0 01 00 00 1c 00 04 10 00 00  type 8 (devtree)
210 d0 f1 11 52 49 a6 25 24 3a 87 9f 93 07 90 28 5e
220 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
230 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Each section begins with a 0x40 byte header, followed by the section's payload. Payload composition is based on the zlib_flag:
- zlib_flag=0 means raw bytes
- zlib_flag=1 means a big-endian uncompressed size in bytes followed by a zlib stream (see pack.sh):

```
103e1f0 00 00 01 ba 00 00 00 00 00 00 00 00 00 00 00 00  section start constant
103e200 11 88 ba 63 60 9d 58 f9 14 93 e8 ee 79 22 08 bf  md5 of section payload
103e210 ef 89 2e 09 d2 fa ac 0c b3 c9 b1 bd e7 90 d5 f2  md5 of "Goodbye! Reboot Now" + section header with this md5 zerod out + section payload
103e220 04 01 01 00 f0 e1 03 01 00 00 80 00 c4 5a d8 00  (0x0=type, 0x1=zlib_flag, 0x2=ubi_flag), section start position in fw file, decode location, section length (including 0x40 header)
```

ubifs partitions can be extracted to local filesystem via:
```
sudo ubireader_extract_files -k 2CCD6C.obi.ubifs -o ubifs-obi-2CCD6C
```

and un-extracted from the filesystem via:
```
# NOTE: max_leb_cnt (-c) option is different for each image. determined from: 
# ubireader_display_info 2CCD6C.obi.ubifs | grep max_leb_cnt
sudo mkfs.ubifs -F -m 2048 -e 126976 -c 150 -x zlib -r ubifs-rootfs-103E230 -o 103E234.rootfs.ubifs.mod
sudo mkfs.ubifs -F -m 2048 -e 126976 -c 56 -x zlib -r ubifs-obi-2CCD6C -o 2CCD6C.obi.ubifs.mod
```
