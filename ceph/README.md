## Ceph
1. Clone Ceph, build, and install it after applying `ceph_xo.patch`. Refer to `setup_ceph.md` for detailed instructions.
2. Clone `xo-server` and build it.
```bash
git clone https://github.com/uoenoplab/xo-server
```
Follow the instruction in the `README.md` inside the `xo-server` repo.

3. Run xo-server without migration enabled on the frontend server to populate the object store. For example:
```bash
./server.out eth0 32 0 0 0 0
```
4. Install boto3:
```bash
pip install boto3
```
5. Run the `create_buckets.py` in this repo to create buckets storing sizes of different objects.
6. Run the `create_objects.py` in this repo to populate the buckets, pointing to the server running `xo-server`. For example:
```bash
python3 https://192.168.11.70:8080 20 8kb 1000 8192
```
to populate the 8kib bucket with 1000 objects of that size. Repeat for the other buckets.

7. Repeat the 5-6 for Rados Gateway, by changing the endpoints in the files and command. Also replace the login keys to the actual ones you got when setting up Rados Gateway.
8. Extract the list of keys using `list_objects.py`. Repeat for both Rados Gateway and `xo-gateway`. They will be written to files specified in the code: e.g., `with open('rgw_obj_list/rgw_'+str(size)+'kb_obj_in_allosd.txt', 'w') as f:`. Replace the path as desired.

10. Assuming wrk is already setup, copy `s3.lua` in this repo to the `wrk/script`.
11. Create an object list with the following format `/(bucket name)/(object name):
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

11. Ensure `xo-server` is ready, on all front and backend servers, refer to the `README.md` in the `xo-server` repo.

12. Set the target list `export s3_objects_input_file=(path)`.
13. Run wrk against the frontend server, for example:
```
./wrk --timeout=4s -t32 -c200 -d10 --latency -s ./scripts/s3.lua https://192.168.11.70:8080
```
For Rados Gateway, change the end point, and replace the login keys to the actual ones you got when setting up Rados Gateway in `s3.lau`.
