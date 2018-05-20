#!/bin/bash

src=$1
dest=_$1

mkdir $dest

#determine number of sections from header
count_bytes=`hexdump -n 4 -s $((0x80)) -e '4/1 "%02x"' $src | tac -rs ..`
declare -i count_int="0x$count_bytes"

dd if=$src of=$dest/0-header bs=1 count=$((0x400))

#dump each section header and payload seperately
for i in `seq 1 $count_int`; do
 declare -i h="$((0xc0))+($i-1)*$((0x40))"
 type=`hexdump -n 4 -s $h -e '4/1 "%02x"' $src`
 offset=`hexdump -n 4 -s $(($h+4)) -e '4/1 "%02x"' $src | tac -rs ..`
 len=`hexdump -n 4 -s $(($h+12)) -e '4/1 "%02x"' $src | tac -rs ..`

 dd if=$src of=$dest/$i-header bs=1 skip=$((0x$offset)) count=$((0x40))
 dd if=$src of=$dest/$i-body ibs=1 skip=$((0x$offset+0x40)) obs=$((0x1000)) count=$((0x$len-0x40))
done
