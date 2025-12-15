import boto3
s3 = boto3.client('s3', endpoint_url='https://192.168.11.100:8080', verify=False)
#64KB 250 KB 500KB 750KB 1MB 1.25MB 1.5MB 1.75MB 2MB
sizes = [8, 16, 32 64, 128, 256, 512, 1024, 2048, 4096]
#s3.create_bucket(Bucket='testbucket')
for name in sizes:
    print(s3.create_bucket(Bucket=str(name)+'kb'))
