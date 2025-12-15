import sys
import hashlib
import time
import boto3
import string
import random
import multiprocessing
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def worker(thread_id, bucket, count, length, endpoint_url, aws_access_key_id, aws_secret_access_key, data_queue, barrier):
    s3 = boto3.client('s3', use_ssl=True, verify=False, endpoint_url=endpoint_url)
#    print('worker', thread_id, 'to put', count, 'objects')

    for i in range(count):
        key = ''.join(random.choice(string.ascii_lowercase) for i in range(random.randint(5,15)))
        data = ''.join(random.choice(string.ascii_lowercase) for i in range(length))

        data_bytes = str.encode(data)
        #h = hashlib.md5(data_bytes).hexdigest()

        s3.put_object(Bucket=bucket, Key=key, Body=data_bytes)
#        data_queue.put({'key': key, 'body': data_bytes, 'md5': '"'+h+'"', 'owner': thread_id})

if __name__ == '__main__':
    if len(sys.argv) != 6:
        print('Usage: ', sys.argv[0], '[endpoint url] [number of workers] [bucket] [count] [size]')
        exit(1)

    aws_access_key_id = 'RZPDDO3UH95UUTACFZJW'
    aws_secret_access_key = 'UP01IIpPyYLv2EFBMFrYDKrpytqmdSNYuYY535GT'

    endpoint_url = sys.argv[1]
    num_workers = int(sys.argv[2])
    bucket = sys.argv[3]
    count = int(sys.argv[4])
    size = int(sys.argv[5])

    barrier = multiprocessing.Barrier(num_workers)
    data_queue = multiprocessing.Queue(count)

    processes = [multiprocessing.Process(target=worker, args=(i, bucket, count//num_workers, size, endpoint_url, aws_access_key_id, aws_secret_access_key, data_queue, barrier)) for i in range(num_workers)]

    # Start the processes
    for process in processes:
        process.start()
    print('All %d workers started...' % (num_workers))

    for process in processes:
        process.join()

    print('Finished!')
