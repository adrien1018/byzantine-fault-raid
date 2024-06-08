trap 'pkill -9 filesys_server' EXIT

pkill -9 filesys_server
sleep 0.5
pkill -9 filesys_server
#rm -rf s0 s1 s2 s3
sleep 0.5
./filesys_server --port 8080 --index 0 -s s0 &
#./filesys_server --port 8081 --index 1 -s s1 &
#./filesys_server --port 8082 --index 2 -s s2 &
./filesys_server --port 8083 --index 3 -s s3 &
# timeout 50s ./filesys_server --port 8083 --index 3 -s s3
# echo Server 3 stopped
# sleep 50
# echo Server 3 restarting
# ./filesys_server --port 8083 --index 3 -s s3 > /dev/null &
wait $(jobs -p)
