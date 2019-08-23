import json
import logging
import boto3
import uuid
import datetime
from datetime import date
from datetime import timedelta
from time import sleep

log = logging.getLogger()
log.setLevel(logging.INFO)

DB_TABLE = 'test-table-02'
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(DB_TABLE)
S3_BUCKETNAME = "testvirago573"
s3client = boto3.client('s3', region_name = 'eu-central-1')
#Stepfunction client
stepfunctions = boto3.client('stepfunctions',region_name='ap-south-1')


def check_user_role_access(masteruser,customermasteraccountid):
    item = table.get_item(ConsistentRead=True, Key={"masterUser":masteruser})
    if item.get('Item') is not None:
        role = item.get('Item').get('role')
        if role.lower() == 'admin':
            #check for masteraccount list in db items
            accountaccesslist = item.get('Item').get('Accounts')
            log.info(accountaccesslist['MasterAccounts'])
            for masteraccount in accountaccesslist['MasterAccounts']:
                #check if user has access for stated MasterAccounts
                if masteraccount['masteraccount'] == customermasteraccountid:
                    #proceed with payload creation
                    return 1
        else:
            return 0




def create_payload(event):
    #payload Structure
    payload = {
    "accountemail":event['request']['accountemail'],
    "accountname":event['request']['accountname'],
    "username":event['request']['username'],
    "securityemail":event['request']['securityemail'],
    "customermasteraccountid":event['request']['customermasteraccountid'],
    "ouname":event['request']['ouname'],
    "enabledregions":event['request']['enabledregions'],
    "config":event['request']['config']
    }

    return payload

def execute_step_functions(payload):
    uuidname = ''.join(payload['accountname'].split())
    masteraccount = payload['customermasteraccountid']
    executionid = '{}-{}'.format(uuidname,str(uuid.uuid4()))
    response = stepfunctions.start_execution(
                    stateMachineArn="arn:aws:states:ap-south-1:808065542248:stateMachine:demostatemachine",
                    name=executionid,
                    input=json.dumps(payload)
                    )
    status = stepfunctions.describe_execution(
                    executionArn= response['executionArn']
                    )
    finalstatus = {'executionid':executionid,'status':status['status'],"masteraccount":masteraccount,"accountname":payload['accountname'],"executionArn":status['executionArn']}
    return finalstatus

def update_db_table(masteruser,finalstatus):
    newlist = []
    item = table.get_item(ConsistentRead=True, Key={"masterUser":masteruser})
    if item.get('Item') is not None:

        log.info("item: " + json.dumps(item))
        executionHistory = item.get('Item').get('executionHistory')
        print("*************************************")
        print(executionHistory)
        if executionHistory.__contains__(finalstatus['masteraccount']):
            if (executionHistory[finalstatus['masteraccount']]):
                templist=executionHistory[finalstatus['masteraccount']]
                templist.append(finalstatus['executionArn'])
                updateItem={finalstatus['masteraccount']:templist}
                executionHistory.update(updateItem)
                #print (executionHistory)
            else:
                newlist.append(finalstatus['executionArn'])
                updateItem={finalstatus['masteraccount']:newlist}
                executionHistory.update(updateItem)
                print(executionHistory)
        else:
            thiskey = (finalstatus['masteraccount'])
            value = []
            print("---------------")
            print (thiskey)
            print (type(thiskey))
            value.append(finalstatus['executionArn'])
            #executionHistory.update(thiskey=value)
            executionHistory[finalstatus['masteraccount']]=value
            print (executionHistory)
    #update execution history in db Table

    dbresponse = table.update_item(
                    Key = {
                        "masterUser":masteruser
                    },
                    UpdateExpression='SET executionHistory = :val1',
                    ExpressionAttributeValues={
                        ':val1': executionHistory
                    }
                    )
    log.info(dbresponse)
    return finalstatus
def send_executionhistory_s3(finalstatus):
    #add explicit wait
    temp_file = {}
    temp_payload = {}
    executionarn = finalstatus['executionArn']
    masteraccount = finalstatus['masteraccount']
    uuidname = ''.join(finalstatus['accountname'].split())
    #s3 object path /masteraccountid/status-timestamp.json
    response = stepfunctions.get_execution_history(
                    executionArn=executionarn
                    )
    log.info(response)
    status = response['events']
    for type in status:
      print("in status first for")
      if type['type'] == 'ChoiceStateExited':
        print("in ChoiceStateExited ")
        if type['stateExitedEventDetails']['name']=='Job Complete?':
            print("in Job Complete?")
            output = type['stateExitedEventDetails']['output']
            getstatus = (json.loads(output))
            print (getstatus)
            if (getstatus['accountcreate']['CreateAccountStatus']['State']) == 'IN_PROGRESS':
                print("in SUCCEEDED")
                temp_payload=getstatus['accountcreate']
                object_name = finalstatus['executionid']
                file_name = masteraccount+"/"+object_name+".json"
                s3client.put_object(
                    Bucket=S3_BUCKETNAME,
                    Key=file_name,
                    Body=(json.dumps(temp_payload, indent=2).encode('UTF-8'))
                    )
                print("**S3 file created")

def lambda_handler(event, context):
    log.info("Event: " + json.dumps(event))
    masteruser = event['masteruser']
    if event['request']['customermasteraccountid']:
        #Check user role access
        #call check_user_role
        customermasteraccountid = event['request']['customermasteraccountid']
        userrole = check_user_role_access(masteruser,customermasteraccountid)
        if userrole != 1:
            log.info("Not Authorized!!")
            raise Exception
        else:
            #Create payload
            payload = create_payload(event)
            #execute stepfunctions
            executestep = execute_step_functions(payload)
            updateitem = update_db_table(masteruser,executestep)
            sleep(10)
            addtos3 = send_executionhistory_s3(updateitem)
            log.info(addtos3)
            return (updateitem)
