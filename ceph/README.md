## Ceph
1. **This step must be done first**. Clone Ceph, build, and install it after applying `ceph_xo.patch` by referring to `setup_ceph.md`.

2. Proceed to and build XO object gateway.
```bash
cd xo-object-gateway
```
Follow the instruction in the `README.md` inside the `xo-object-gateway` folder. The gateway uses the Ceph configuration at `/etc/ceph/ceph.conf` to read backend server addresses, and the file should have already been setup when installing Ceph.

3. Run the gateway without migration enabled on the frontend server to populate the object store. For example, to run with 32 threads (`32`), with no migration enabled (subsequent `0` in the command):
```bash
./server.out eth0 32 0 0 0 0
```

4. Install boto3. This needs to be done also on the client machine:
```bash
pip3 install boto3
```
Ensure `~/.aws/credentials` is created and configured. This should have already been prepared as part of `setup_ceph.md`. The same credentials can be used for both Rados Gateway and XO object gateway because XO object gateway does not implement authentication currently and will simply ignore it.

5. Run the `create_buckets.py` in this repo to create buckets storing sizes of different objects. Changh the `[8, 16, 32, 64, 256, 1024, 2048, 4096]` array in the code for other sizes. Change the `endpoint_url` in the code to point to your gateway.

6. Run the `create_objects.py` in this repo to populate the buckets, pointing to the server running the gateway. For example:
```bash
python3 create_objects.py https://192.168.11.70:8080 20 8kb 1000 8192
```
to populate the 8kib bucket with 1000 objects of that size. Repeat for the other buckets.

7. Repeat the 5-6 for Rados Gateway, by changing the endpoints in the files and command. In `create_buckets.py`, edit the `endpoint_url`.

8. Extract the list of keys by running `python3 list_buckets.py`. Repeat for both Rados Gateway and XO object gateway. They will be written to files specified in the code: e.g., `with open('rgw_obj_list/rgw_'+str(size)+'kb_obj_in_allosd.txt', 'w') as f:`. Replace the path as desired. The endpoint can be changed by editing the `endpoint_url` in the file.

9. Assuming wrk is already setup, copy `s3.lua` in this repo to the `wrk/script`. Inside the script, replace the login keys to the actual ones you got when setting up Rados Gateway in `s3.lau`. They are `key` and `secret`.

10. Create an object list with the following format `/(bucket name)/(object name)`:
```
/1024kb/uadpjkvq
/1024kb/krluoofu
/1024kb/wwbiiaui
/1024kb/fchiegjf
/1024kb/mbjgevtu
/1024kb/ykdgurpd
/1024kb/mctsczoa
/1024kb/vbjjqdtj
/1024kb/eujdsfbg
```
You can use the list created in step 8 to create your desired object list.

11. Run XO object gateway with migration enabled, on all the frontend (gateway host) and backend servers (OSD hosts). Before executing the `./server.out ...` command, ensure the NIC configuration is done on all the server hosts according to the documentation. Refer to the `README.md` in the `xo-object-gateway` folder for parameters, including enabling migration, using sofware or hardware flow stiring, enabling hybrid.

12. On the client host, specify the object request list with `export s3_objects_input_file=(path)`.

13. Run wrk against the frontend server from the client host, for example, to use 32 threads and 200 connections for 10 seconds:
```
./wrk -t32 -c200 -d10 --latency -s ./scripts/s3.lua https://192.168.11.70:8080
```
For Rados Gateway, change the end point and repeat.
