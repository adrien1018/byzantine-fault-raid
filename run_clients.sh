./filesys_client --index 0 --key signing_key --debug &
./filesys_client --index 1 --key signing_key --debug &
./filesys_client --index 2 --key signing_key --debug &
wait $(jobs -p)
