Firmware file starts with a 0x400 byte header, which describes the other sections of the file:

```
000 4F 42 69 32 58 58 5F 46 57 5F 50 41 43 4B 30 30  constant OBi2XX_FW_PACK00
010 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
020 0B E1 72 21 40 10 25 16 F0 5C 9F 42 4F 16 9E AA  0x28 = md5 of "Goodbye! Reboot Now" + 0x400 header with this md5 zerod out
030 7B A3 7D 9E FB CA 71 5B 77 9F A6 76 27 73 E4 4C 
040 33 2E 32 2E 31 20 28 42 75 69 6C 64 3A 20 35 37  version# string
050 35 37 45 58 29 00 00 00 00 00 00 00 00 00 00 00
060 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
070 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
080 07 00 00 00 B8 2E D8 00 00 00 00 00 00 00 00 00  0x80=#segments, 0x84=total fw file length
090 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
0a0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
0b0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
0c0 08 00 00 00 00 04 00 00 00 00 2D 00 64 C3 12 00  type 8 (recovery kernel uboot image)
0d0 31 4A 72 A9 22 39 CC 30 BE 81 7F 5D 74 80 B6 28  md5 of section payload
0e0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
0f0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
100 09 00 00 00 64 C7 12 00 00 00 E4 00 40 60 0B 00  type 9 (recovery rootfs squashfs)
110 43 DE AB A9 19 FA A2 C4 B9 29 FC BB DA 89 02 BC 
120 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
130 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
140 03 00 00 00 A4 27 1E 00 00 00 C0 00 40 F0 21 00  type 3 (obi squashfs)
150 37 22 79 F6 97 A6 09 21 BE 90 3B D1 E9 C3 B4 92 
160 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
170 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
180 05 00 00 00 E4 17 40 00 00 00 05 00 64 3B 26 00  type 5 (kernel uboot image)
190 6D 9A A0 DC 47 2C F1 46 78 11 91 ED 52 3C 9C 0D 
1a0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
1b0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
1c0 04 00 00 00 48 53 66 00 00 00 48 00 40 30 5F 00  type 4 (RootFS squashfs)
1d0 FB A5 99 C3 10 04 4A 6B 7D 19 5C D1 A7 EA 6B 5A 
1e0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
1f0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
200 0A 00 00 00 88 83 C5 00 00 00 F0 00 40 00 0F 00  type A (wireless squashfs)
210 DD 4C EC F9 21 DE 88 63 F9 D5 A1 56 08 54 D7 12 
220 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
230 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
240 02 00 00 00 C8 83 D4 00 00 00 00 00 F0 AA 03 00  type 2 (uboot)
250 96 E4 B7 89 2D 2D 84 1E 32 9A 87 26 F5 8A 95 71 
260 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
270 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
280 00 00 00 00 cd 28 8a 42 f3 cd 84 79 c0 4d 47 7d  unknown signed section...
290 74 bb 69 1a 05 39 b7 08 37 a2 03 21 b1 fb f0 01 
2a0 3d da 0f 57 a7 93 3a 64 c7 55 45 7a 35 f1 8b 63 
2b0 54 1a fa 36 c4 01 59 3b 1c b4 70 0a 6e 99 99 60 
2c0 51 31 bf 5e 58 a0 86 4f ff 7a 96 3b 2e ab 6e 67  signature of 0x400 header using obi pki key, len 0x100
...
3c0 00 00 00 00 ba f7 ce 69 a1 fc ee 7a 89 88 4f 61  unknown unsigned section...
3d0 93 15 cc 0e 6a f3 33 16 db ed 8b 79 4f a8 bb 56 
3e0 60 f6 56 18 66 7d 6e 5e 21 f8 00 48 81 77 2a 6c  another unknown signed section...
3f0 da 67 63 24 dd 7c 8e 03 ab 30 56 0b 94 b9 06 7c 
```

Each section begins with a 0x40 byte header followed by the section's payload

```
400 00 00 01 BA 00 00 00 00 00 00 00 00 00 00 00 00  section start constant
410 31 4A 72 A9 22 39 CC 30 BE 81 7F 5D 74 80 B6 28  md5 of section payload
420 8C A6 1A 2B 67 B7 43 11 EF 9F FC 44 E3 72 87 99  md5 of "Goodbye! Reboot Now" + section header with this md5 zerod out + section payload
430 08 00 00 00 00 04 00 00 00 00 2D 00 64 C3 12 00  type, section start position in fw file, destination location in flash, section length (including 0x40 header)
```

uboot segment consists of:
- preloader header
  - binary + footer length @ 0x4
  - header length @ 0xC
  - 1-byte simple checksum at 0x1C
- uboot binary
- footer is simple 4-byte checksum of binary
