size=$(stat -c%s $1)
size_hex=$(printf "%08x" $size)

echo $size_hex | xxd -p -r > $1.packed
zlib-flate -compress < $1 >> $1.packed
