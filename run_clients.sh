./filesys_client --index 0 &
./filesys_client --index 1 &
./filesys_client --index 2 &
wait $(jobs -p)
