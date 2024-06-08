trap 'pkill -9 filesys_server' EXIT

pkill -9 filesys_server
sleep 0.5
pkill -9 filesys_server

rm -rf s{0..19}
sleep 0.5
for i in {0..19}; do
    ./filesys_server --port $((8080+i)) --index $i -s s$i &
done
# timeout 50s ./filesys_server --port 8083 --index 3 -s s3
# echo Server 3 stopped
# sleep 50
# echo Server 3 restarting
# ./filesys_server --port 8083 --index 3 -s s3 > /dev/null &
wait $(jobs -p)
