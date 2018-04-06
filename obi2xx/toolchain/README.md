My notes on building a toolchain to match the obi2xx's existing kernel/libs:

```
export CROSS_OBI200=/some/path/to/toolchain/destination
export PATH=$CROSS_OBI200/arm-unknown-linux-gnueabi/bin:$PATH

tar -xf binutil-2.18.tar.bz2
cd binutils-2.18
patch -p0 < binutils-2.18-*.patch
cd ..
mkdir build-binutils
cd build-binutils
../binutils-2.18/configure --target=arm-unknown-linux-gnueabi --disable-multilib --with-sysroot=$CROSS_OBI200/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi --prefix=$CROSS_OBI200/arm-unknown-linux-gnueabi --disable-werror
make
make install
cd ..

tar -xf linux-2.6.30.10.tar.bz2
cd linux-2.6.30.10
make ARCH=arm INSTALL_HDR_PATH=$CROSS_OBI200/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi headers_install
mkdir $CROSS_OBI200/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi/usr
ln -s $CROSS_OBI200/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi/include/ $CROSS_OBI200/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi/usr/include
cd ..

tar -xf gcc-4.2.1.tar.bz2
mkdir build-gcc-init
cd build-gcc-init
CFLAGS='-std=gnu89' ../gcc-4.2.1/configure --prefix=$CROSS_OBI200/arm-unknown-linux-gnueabi --with-sysroot=$CROSS_OBI200/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi --target=arm-unknown-linux-gnueabi --enable-languages=c --disable-multilib --with-newlib --without-headers --disable-threads --disable-shared
make all-gcc
make install-gcc
cd ..

tar -xf glibc-2.5.tar.bz2
tar -xf glibc-ports-2.5.tar.bz2
mv glibc-ports-2.5 glibs/ports
cd glibc-2.5
patch -p0 < glibc-2.5-*.patch
cd ..
mkdir build-glibc
cd build-glibc
../glibc-2.5/configure --prefix=$CROSS_OBI200/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi --with-headers=$CROSS_OBI200/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi/include --build=$MACHTYPE --host=arm-unknown-linux-gnueabi --target=arm-unknown-linux-gnueabi --disable-multilib libc_cv_forced_unwind=yes libc_cv_c_cleanup=yes
make
make install
cd ..

tar -xf gmp-6.0.0a.tar.xz
mv gmp-6.0.0 gcc-4.2.1/gmp
tar -xf mpc-1.0.2.tar.gz
mv mpc-1.0.2 gcc-4.2.1/mpc
tar -xf mpfr-3.1.2.tar.xz
mv mpfr-3.1.2 gcc-4.2.1/mpfr

mkdir build-gcc-final
cd build-gcc-final
CFLAGS='-fgnu89-inline' ../gcc-4.2.1/configure --prefix=$CROSS_OBI200/arm-unknown-linux-gnueabi --with-sysroot=$CROSS_OBI200/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi --target=arm-unknown-linux-gnueabi --enable-languages=c,c++ --disable-multilib --disable-bootstrap --with-native-system-header-dir=$CROSS_OBI200/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi/include
make
make install
```
