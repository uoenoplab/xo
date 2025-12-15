import boto3

s3 = boto3.client('s3', endpoint_url='http://192.168.11.80:8080')

for size in [8, 16, 32, 64, 256, 1024, 4096, 8192]:
    marker = None
    with open('rgw_obj_list/rgw_'+str(size)+'kb_obj_in_allosd.txt', 'w') as f:
        while True:
            if marker != None:
                objs = s3.list_objects(Bucket=str(size)+'kb', Marker=marker)
            else:
                objs = s3.list_objects(Bucket=str(size)+'kb')
            last_obj = None
            for obj in objs['Contents']:
                print(str(size)+'kb,'+obj['Key']+','+str(size * 1024), file=f)
                #print(obj['Key']+','+str(size * 1024))
                last_obj = obj['Key']
            if objs['IsTruncated'] == True:
                marker = objs['NextMarker']
                #marker = last_obj
            else:
                break

