./filesys_client --index 0 --key signing_key --mount_point test &
./filesys_client --index 1 --key signing_key --mount_point test &
./filesys_client --index 2 --key signing_key --mount_point test &
wait $(jobs -p)
