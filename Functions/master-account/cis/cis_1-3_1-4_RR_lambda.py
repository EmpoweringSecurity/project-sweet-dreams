 # Copyright 2020 Stefan Prioriello
 # SPDX-License-Identifier: MIT
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy of this 
 # software and associated documentation files (the "Software"), to deal in the Software 
 # without restriction, including without limitation the rights to use, copy, modify, 
 # merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
 # permit persons to whom the Software is furnished to do so, subject to the following 
 # conditions:
 #
 # The above copyright notice and this permission notice shall be included in all 
 # copies or substantial portions of the Software.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 # INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 # PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 # OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
import boto3
import json
import datetime
import os
import logging
import argparse

from common import account_session
from common import sns_notification

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):

    #Lambda Environment Variables
    TargetAccountSecurityRoleName=os.environ['TargetAccountSecurityRoleName'] 

    #Variables
    targetAccount=event["detail"]["findings"][0]["AwsAccountId"]
    nonRotatedKeyUserArn = str(event['detail']['findings'][0]['Resources'][0]['Id'])

    nonRotatedKeyUser = nonRotatedKeyUserArn.split('/')[-1]

    logger.info(f"Deactiviating the user name: {nonRotatedKeyUser} from Id: {nonRotatedKeyUserArn}")

    findingId = str(event['detail']['findings'][0]['Id'])
    productArn=event["detail"]["findings"][0]["ProductArn"]  
    lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME'] 

    ##Future feature
    # if event['detail']['findings'][0]['Resources'][0]['Type'] == "AwsIamUser":
    #     finding=event["detail"]
    # elif event['detail']['findings'][0]['Resources'][0]['Type'] == "AwsAccount":
    #     #Notify but do not resolve
    # else:
    #     raise Exception("Neither GuardDuty nor SecurityHub event")

    #Assume role in target account for response 
    session=account_session.get_session(targetAccount, os.environ['TargetAccountSecurityRoleName']) 

    # Create bot3 clients and resource
    iam = session.client('iam')
    securityhub = boto3.client('securityhub')
    iam_resource = session.resource('iam')

    try:
        todaysDatetime = datetime.datetime.now(datetime.timezone.utc)
        paginator = iam.get_paginator('list_access_keys')
        
        for response in paginator.paginate(UserName=nonRotatedKeyUser):
            for keyMetadata in response['AccessKeyMetadata']:
                accessKeyId = str(keyMetadata['AccessKeyId'])
                keyAgeFinder = todaysDatetime - keyMetadata['CreateDate']
                if keyAgeFinder <= datetime.timedelta(days=90):
                    logger.info("Access key: " + accessKeyId + " is compliant")
                else:
                    logger.info("Access key over 90 days old found!")
                    logger.info("Access key: " + accessKeyId + " is non-compliant")

                    #Deactivate key
                    access_key = iam_resource.AccessKey(nonRotatedKeyUser, accessKeyId)
                    access_key.deactivate()
                    
                    logger.info(f"Searching within users:{nonRotatedKeyUser} access key {accessKeyId} in {targetAccount}")

                    get_KeyStatus = iam.list_access_keys(UserName=nonRotatedKeyUser,MaxItems=20)
                    
                    for keys in get_KeyStatus['AccessKeyMetadata']:
                        access_KeyId = str(keys['AccessKeyId'])
                        access_KeyStatus = str(keys['Status'])
                        # find the key Id that matches the exposed key
                        if access_KeyId == accessKeyId:
                            if access_KeyStatus == 'Inactive':
                                logger.info('Access key over 90 days old deactivated!')
                                try:
                                    logger.info(f"Updating Security Hub Finding Id: {findingId}, Product Arn: {productArn} with RESOLVED status")

                                    response = securityhub.batch_update_findings(
                                        FindingIdentifiers=[
                                            {
                                                'Id': findingId,
                                                'ProductArn': productArn
                                            },
                                        ],
                                        Note={
                                            'Text': f'Non compliant access key {accessKeyId} was deactivated sucessfully for {nonRotatedKeyUser}.',
                                            'UpdatedBy': lambdaFunctionName
                                        },
                                        Workflow={
                                            'Status': 'RESOLVED'
                                        },
                                    )
                                    logger.info(response)

                                    #Send Notification
                                    findingTitle=event["detail"]["findings"][0]["Title"]
                                    message = f"Security Hub Finding: {findingTitle} has been successfully responded to and resolved. Finding Id: {findingId}"
                                    sns_notification.sendSNSNotification(os.environ['AlertSnsArn'], message)
                                except Exception as e:
                                    print(e)
                                    raise
    except Exception as e:
        print(e)
        raise