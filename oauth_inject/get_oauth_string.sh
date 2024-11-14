lookup_addr() {
	arm-unknown-linux-gnueabi-readelf -a obiapp8680 | grep " $1" | sed 's/.*: \([0-9a-f]*\).*/\1/'
}

ADDR_SYSLOG=$(lookup_addr syslog)
ADDR_STRNCMP=$(lookup_addr strncmp@GLIBC)
ADDR_SPRINTF=$(lookup_addr sprintf@GLIBC)

cat > get_oauth_string.lk <<-EOF
	MEMORY
	{
	  empty_location (RX) : ORIGIN = 0xBC9A0, LENGTH = 0x0010000
	}

	SECTIONS {
	  .text : { *(.text) } > empty_location
	  .data : { *(.data) } > empty_location

	  syslog  = 0x$ADDR_SYSLOG ;
	  strncmp = 0x$ADDR_STRNCMP ;
	  sprintf = 0x$ADDR_SPRINTF ;
	}
EOF
arm-unknown-linux-gnueabi-gcc -c get_oauth_string.c -o get_oauth_string.o -fomit-frame-pointer -O2
arm-unknown-linux-gnueabi-ld get_oauth_string.lk get_oauth_string.o -o get_oauth_string
#xxd get_oauth_string
