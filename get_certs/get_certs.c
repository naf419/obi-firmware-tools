#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/io.h>
#include <sys/mman.h>

int get_certs(SSL_CTX *ctx) {
#ifdef TEST
  static const char *FNAME = "rootca.pem";
#else
  static const char *FNAME = "/obi/rootca.pem";
#endif

  int count = 0;
  int err_count = 0;
  int fd = open(FNAME, O_RDONLY);
  if (!fd) {
    printf("GET_CERTS: cannot open %s\n", FNAME);
    goto err;
  }
  struct stat s;
  if (fstat(fd, &s)) {
    printf("GET_CERTS: cannot fstat %s\n", FNAME);
    goto err;
  }
  off_t len = s.st_size;
  void* buf = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (!buf) {
    printf("GET_CERTS: cannot mmap len %d\n", len);
    goto err;
  }
  X509_STORE* store = (X509_STORE*) SSL_CTX_get_cert_store(ctx);
  BIO* bio = BIO_new_mem_buf(buf,len);
 
  X509* x509;
  while ( (x509 = (X509*)PEM_read_bio_X509_AUX(bio,NULL,NULL,NULL)) != NULL) {
    if (X509_STORE_add_cert(store,x509) != 0) {
      count++;
    }
    else {
#ifdef TEST
      char name[0x400];
      memset(name,0,0x400);
      X509_NAME* x509_name = X509_get_subject_name(x509);
      X509_NAME_get_text_by_NID(x509_name,0xd,name,0x400);
      printf("error loading cert: %s\n",name);
#endif
      err_count++;
    }
    X509_free(x509);
  }
  //yes im leaking this fd, but just to save space in binary
  //close(fd);
err:
  printf("GET_CERTS: %d CA certificates loaded and %d errors, reading from %s\n", count, err_count, FNAME);
  return count;
	
}

#ifdef TEST
void print_error_string(unsigned long err, const char* const label)
{
    const char* const str = ERR_reason_error_string(err);
    if(str)
        fprintf(stderr, "%s\n", str);
    else
        fprintf(stderr, "%s failed: %lu (0x%lx)\n", label, err, err);
}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
  uint uVar1;
  int bVar2;
  
  if (preverify != 0) {
    return preverify;
  }
  uVar1 = X509_STORE_CTX_get_error(x509_ctx);
  bVar2 = 8 < uVar1;
  if (uVar1 != 9) {
    bVar2 = uVar1 != 0xd;
  }
  if ((bVar2 && (uVar1 != 9 && uVar1 != 0xe)) && (uVar1 != 10)) {
    printf("BASESSL:verifing:%d\n",uVar1);
    return 0;
  }
  return 1;
}

int main(int argc, char** argv)
{
  SSL_library_init();
  SSL_load_error_strings();
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
  if (!ctx) {
    ERR_print_errors_fp(stdout);
  } else {
    get_certs(ctx);
  }

  int uVar6 = SSL_CTX_ctrl(ctx,0x20,0,(void *)0x0);
  SSL_CTX_ctrl(ctx,0x20,uVar6 | 0x40000,(void *)0x0);
  SSL_CTX_set_verify(ctx,3,verify_callback);
  SSL_CTX_set_verify_depth(ctx,0xf);
  SSL_CTX_ctrl(ctx,0x2a,5,(void *)0x0);
  SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM);

  BIO* bio = BIO_new_ssl_connect(ctx);
  int ssl_err = ERR_get_error();

  if(!(bio != NULL))
  {
    print_error_string(ssl_err, "BIO_new_ssl_connect");
    return 0;
  }

  char host_and_port[100];
  snprintf(host_and_port, 99, "%s:%s", argv[1], argv[2]);
  printf("%s\n", host_and_port);
  int res = BIO_set_conn_hostname(bio, host_and_port);
   
  ssl_err = ERR_get_error();

  if(!(1 == res))
  {
    print_error_string(ssl_err, "BIO_set_conn_hostname");
    return 0;
  }

  SSL* ssl;
  BIO_get_ssl(bio, &ssl);
  ssl_err = ERR_get_error();
  
  SSL_set_tlsext_host_name(ssl, argv[1]);

  res = BIO_do_connect(bio);
  ssl_err = ERR_get_error();

  if(!(1 == res))
  {
    print_error_string(ssl_err, "BIO_do_connect");
    return 0;
  }

  res = BIO_do_handshake(bio);
  if (!(1 == res)) {
    printf("handshake failed\n");
    return 0;
  }
 
  res = SSL_get_verify_result(ssl);
  if(!(X509_V_OK == res))
  {
	print_error_string((unsigned long)res, "SSL_get_verify_results");
	return 0;
  } else {
        printf("SUCCESS!\n");
  }

  return 1;
}
#endif
