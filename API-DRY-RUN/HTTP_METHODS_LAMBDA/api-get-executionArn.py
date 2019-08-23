import json
import boto3
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)

'''{
    "masteraccountid": 808065542248,
    "clientexecutionid": "DTIT_CAIMAN-bc711e56-4dbc-4af5-9d93-fb389213c01f",
    "masteruser": "rootUser"
} '''
BUCKET_NAME = "testvirago573"

def lambda_handler(event, context):
    # TODO implement
    log.info("Event: " + json.dumps(event))
    masteraccountid = event['masteraccountid']
    clientexecutionid = event['clientexecutionid']
    file_name = str(masteraccountid)+"/"+clientexecutionid+".json"
    #print (file_name)
    content=read_file_s3(file_name)
    return content
    
    
def read_file_s3(object_key):
    s3client = boto3.client('s3',region_name ='eu-central-1')
    s3read = s3client.get_object(Bucket=BUCKET_NAME, Key=object_key)
    #print (s3read)
    body = s3read['Body']
    return (json.loads(body.read()))
    

    