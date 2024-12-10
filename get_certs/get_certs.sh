lookup_addr() {
	readelf -a obiapp8680 | grep -E "UND $1" | sed 's/.*: \([0-9a-f]*\).*/\1/'
}
lookup_jump_slot() {
	readelf -a obiapp8680 | grep "$1" | sed 's/.*R_ARM_JUMP_SLOT   \([0-9a-f]*\).*/\1/'
}

ADDR_PRINTF=$(lookup_addr "printf@")
ADDR_OPEN=$(lookup_addr "open@")
ADDR_FSTAT=$(lookup_jump_slot "__fxstat@")
ADDR_CLOSE=$(lookup_addr "close@")
ADDR_MMAP=$(lookup_addr "mmap")
ADDR_SSL_CTX_get_cert_store=$(lookup_jump_slot SSL_CTX_get_cert_store)
ADDR_BIO_new_mem_buf=$(lookup_addr "BIO_new_mem_buf")
ADDR_X509_STORE_add_cert=$(lookup_addr "X509_STORE_add_cert")
ADDR_X509_free=$(lookup_addr "X509_free")
ADDR_PEM_read_bio_X509_AUX=$(lookup_addr "PEM_read_bio_X509_AUX")

echo "printf = 0x$ADDR_PRINTF"
echo "open = 0x$ADDR_OPEN"
echo "fstat = 0x$ADDR_FSTAT"
echo "close = 0x$ADDR_CLOSE"
echo "mmap = 0x$ADDR_MMAP"
echo "SSL_CTX_get_cert_store = 0x$ADDR_SSL_CTX_get_cert_store"
echo "BIO_new_mem_buf = 0x$ADDR_BIO_new_mem_buf"
echo "X509_STORE_add_cert = 0x$ADDR_X509_STORE_add_cert"
echo "X509_free = 0x$ADDR_X509_free"
echo "PEM_read_bio_X509_AUX = 0x$ADDR_PEM_read_bio_X509_AUX"


cat > get_certs.lk <<-EOF
	MEMORY
	{
	  g_certs_after_first_two (RX) : ORIGIN = 0x238100, LENGTH = 0x1480A
	  get_certs (RX) : ORIGIN = 0xc8ab0, LENGTH = 0x128
	}
	
	SECTIONS {
	  .text : { *(.text) } > get_certs
          .data : { *(.data) *(.rodata) } > g_certs_after_first_two

	  printf = 0x$ADDR_PRINTF ;
	  open = 0x$ADDR_OPEN ;
	  __fxstat = 0x$ADDR_FSTAT ;
	  close = 0x$ADDR_CLOSE ;
	  mmap = 0x$ADDR_MMAP ;
	  SSL_CTX_get_cert_store = 0x$ADDR_SSL_CTX_get_cert_store ;
	  BIO_new_mem_buf = 0x$ADDR_BIO_new_mem_buf ;
	  X509_STORE_add_cert = 0x$ADDR_X509_STORE_add_cert ;
	  X509_free = 0x$ADDR_X509_free ;
	  PEM_read_bio_X509_AUX = 0x$ADDR_PEM_read_bio_X509_AUX ;
	}
EOF
arm-unknown-linux-gnueabi-gcc -c get_certs.c -o get_certs.o -fomit-frame-pointer -Os -I /path/to/openssl-1.0.1i/include
arm-unknown-linux-gnueabi-ld get_certs.lk get_certs.o -o get_certs
readelf -x .text -x .rodata get_certs

gcc -DTEST -g get_certs.c -o get_certs.x86_64 -fomit-frame-pointer -O2 -I /path/to/openssl-1.0.1i/include libssl.a.x86_64 libcrypto.a.x86_64
arm-unknown-linux-gnueabi-gcc -DTEST -g get_certs.c -o get_certs.arm -fomit-frame-pointer -O2 -I /path/to/openssl-1.0.1i/include -L /path/to/openssl-1.0.1i -l ssl -l crypto -l dl
