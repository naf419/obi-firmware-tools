Firmware format is identical to obi2xx firmware, except that the 0x400 byte header begins with a different device identifier:

```
000 56 56 58 32 30 30 43 5f 46 57 5f 50 4b 47 30 00  constant VVX200C_FW_PKG0
```

The d230 also contains the firmware for the handset. Its firmware begins with a 0x3C byte header:
```
000 78 56 34 12 ff ff ff ff ff ff ff ff ff ff ff ff  magic constant
010 00 00 10 00 6c 66 2a 00 c8 2a 37 d7 91 76 12 13  0x14=length 0x18=md5
020 b0 45 32 c9 cb 7e 45 d1 ff ff ff ff ff ff ff ff
030 ff ff ff ff ff ff ff ff ff ff ff ff
```

The first arm instruction in the handset firmware gets loaded at 0x0800C000, 
and the code itself copies instructions beginning at 0x82AF5AC to 0xA0000-A9F7C
