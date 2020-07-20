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
import time
import os
import logging

from common import account_session
from common import sns_notification

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    #VARIABLES
    #Lambda Environment Variables
    TargetAccountSecurityRoleName=os.environ['TargetAccountSecurityRoleName'] 
   
    #Common Variables
    targetAccount=event["detail"]["findings"][0]["AwsAccountId"]
    productArn=event["detail"]["findings"][0]["ProductArn"]  

    # parse non-compliant trail from Security Hub finding
    noncomplaintCloudTrail = str(event['detail']['findings'][0]['Resources'][0]['Id'])
    #Parse to '<TrailName>' because the AliasName for a KMS CMK key has the pattern 'alias/^[a-zA-Z0-9/_-]+$'
    noncompliantTrail = noncomplaintCloudTrail.split('/')[-1]

    findingId = str(event['detail']['findings'][0]['Id'])

    # import lambda runtime vars - imported session token to add to log group name to enforce uniqueness
    lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    lambdaFunctionSeshToken = os.environ['AWS_SESSION_TOKEN']   

    # Set name for Cloudwatch logs group
    cloudwatchLogGroup = 'CloudTrail/CIS2-4-' + noncompliantTrail + "/" + str(int(time.time()))  

    # Import CloudTrail to CloudWatch logging IAM Role
    cloudtrailLoggingRoleName = os.environ['CLOUDTRAIL_CW_LOGGING_ROLE_NAME']              
    
    #Assume role in target account for response 
    session=account_session.get_session(targetAccount, os.environ['TargetAccountSecurityRoleName']) 

    # set boto3 clients
    securityhub = boto3.client('securityhub')
    cwl = session.client('logs')
    cloudtrail = session.client('cloudtrail')

    # create cloudwatch log group
    try:
        createGroup = cwl.create_log_group(
            logGroupName=cloudwatchLogGroup,
        )
        logger.info(createGroup)
    except Exception as e:
        print(e)
        raise
    # wait for CWL group to propagate    
    time.sleep(2)              
    # get CWL ARN
    try:
        describeGroup = cwl.describe_log_groups(logGroupNamePrefix=cloudwatchLogGroup)
        cloudwatchArn = str(describeGroup['logGroups'][0]['arn'])
    except Exception as e:
        print(e)
        raise          

    # update non-compliant Trail
    try:
        updateCloudtrail = cloudtrail.update_trail(
            Name=noncomplaintCloudTrail,
            CloudWatchLogsLogGroupArn=cloudwatchArn,
            CloudWatchLogsRoleArn="arn:aws:iam::" + targetAccount + ":role/" + cloudtrailLoggingRoleName
        )
        logger.info(updateCloudtrail)
        try:
            response = securityhub.batch_update_findings(
                FindingIdentifiers=[
                    {
                        'Id': findingId,
                        'ProductArn': productArn
                    },
                ],
                Note={
                    'Text': 'CloudWatch logging is now enabled for CloudTrail trail ' + noncomplaintCloudTrail,
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