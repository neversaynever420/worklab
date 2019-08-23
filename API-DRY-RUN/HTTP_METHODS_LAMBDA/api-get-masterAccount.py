import json
import logging
import boto3
import uuid

log = logging.getLogger()
log.setLevel(logging.INFO)

DB_TABLE = 'test-table-02'
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(DB_TABLE)
stepfunctions = boto3.client('stepfunctions',region_name='ap-south-1')

def get_table_item(masteruser,masteraccountid):
    item = table.get_item(ConsistentRead=True, Key={"masterUser":masteruser})
    if item.get('Item') is not None:
        log.info("item: " + json.dumps(item))
        executionhistory = item.get('Item').get('executionHistory')
        print(executionhistory.get(str(masteraccountid)))
        print(type(executionhistory))
        return (executionhistory.get(str(masteraccountid)))
def check_status(executionarn):
    finalstatus = []
    #print (type(executionarn))
    if executionarn:
        for arn in executionarn:
            response = stepfunctions.get_execution_history(
                    executionArn=arn
                    )
            log.info(response)
            status = response['events']
            for type in status:
              if type['type'] == 'ChoiceStateExited':
                  if type['stateExitedEventDetails']['name']=='Job Complete?':
                      log.info((type['stateExitedEventDetails']['output']))
                      output = type['stateExitedEventDetails']['output']
                      getstatus = (json.loads(output))
                      if (getstatus['accountcreate']['CreateAccountStatus']['State']) == 'SUCCEEDED':
                          finalstatus.append(getstatus)
            
        
    return finalstatus

#Stepfunction client

def lambda_handler(event, context):
    # TODO implement
    log.info("Event: " + json.dumps(event))
    '''{
    "masteraccountid": 123456789123,
    "masteruser": "rootUser"
    } '''
    dbresponse = get_table_item(event['masteruser'],event['masteraccountid'])
    #pass execution arn to check status
    status = check_status(dbresponse)
    return status