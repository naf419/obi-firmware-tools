#!/bin/bash

src=$1
dest=$2
keep_sig=$3

#determine number of sections from header
count_bytes=`hexdump -n 4 -s $((0x80)) -e '4/1 "%02x"' $src/0-header | tac -rs ..`
declare -i count_int="0x$count_bytes"

cp $src/0-header $dest

declare -i current="0x400"

for i in `seq 1 $count_int`; do
 
 #calculate header fields
 body=$src/$i-body
 md5_payload=`md5sum $body`
 
 size_payload=$(stat -c%s $body)
 declare -i size="$size_payload+0x40"
 
 current_bytes=`printf "%08x" $current | tac -rs ..`
 size_bytes=`printf "%08x" $size | tac -rs ..`

 #temp section header with zerod md5
 cp $src/$i-header $src/$i-header.tmp
 echo $md5_payload       | xxd -p -r | dd of=$src/$i-header.tmp bs=1 seek=$((0x10)) conv=notrunc >/dev/null
 echo "0000000000000000" | xxd -p -r | dd of=$src/$i-header.tmp bs=1 seek=$((0x20)) conv=notrunc >/dev/null
 echo $current_bytes     | xxd -p -r | dd of=$src/$i-header.tmp bs=1 seek=$((0x34)) conv=notrunc >/dev/null
 echo $size_bytes        | xxd -p -r | dd of=$src/$i-header.tmp bs=1 seek=$((0x3C)) conv=notrunc >/dev/null

 #calc md5 including temp header
 echo -n "Goodbye! Reboot Now" > $body.tmp
 cat $src/$i-header.tmp >> $body.tmp
 cat $body >> $body.tmp
 dd if=/dev/zero of=$body.tmp bs=1 seek=$((0x20+19)) count=16 conv=notrunc > /dev/null
 md5_packed=`md5sum $body.tmp`

 #put md5 in temp header
 echo $md5_packed | xxd -p -r | dd of=$src/$i-header.tmp bs=1 seek=$((0x20)) conv=notrunc >/dev/null

 #dump temp header and payload into final fw
 cat $src/$i-header.tmp >> $dest
 cat $body >> $dest

 if [[ "$keep_sig" == "" ]]; then
  #copy section data to fw header
  echo $md5_payload | xxd -p -r | dd of=$dest bs=1 seek=$((0xc0+($i-1)*0x40+0x10)) count=16 conv=notrunc
  dd if=$src/$i-header.tmp of=$dest bs=1 skip=$((0x30)) seek=$((0xc0+($i-1)*0x40)) count=16 conv=notrunc
 fi

 current=$(($current+$size))
done

#update fw header with total bytes
total_bytes=`printf "%08x" $current | tac -rs ..`
echo $total_bytes | xxd -p -r | dd of=$dest bs=1 seek=$((0x84)) conv=notrunc >/dev/null

if [[ "$keep_sig" != "" ]]; then
  echo -n $keep_sig | dd of=$dest bs=1 seek=$((0x3C0)) count=32 conv=notrunc >/dev/null
fi

#relcalc fw header md5
echo -n "Goodbye! Reboot Now" > $src/0-header.tmp
dd if=$dest bs=1 count=$((0x400)) >> $src/0-header.tmp
dd if=/dev/zero of=$src/0-header.tmp bs=1 seek=$((0x28+19)) count=16 conv=notrunc > /dev/null
md5_header=`md5sum $src/0-header.tmp`
echo md5_header=$md5_header
echo $md5_header | xxd -p -r | dd of=$dest bs=1 seek=$((0x28)) conv=notrunc >/dev/null

