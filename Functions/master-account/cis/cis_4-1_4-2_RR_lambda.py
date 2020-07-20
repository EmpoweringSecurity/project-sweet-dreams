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

    # parse Security Group ID from Security Hub CWE
    non_compliant_sg = str(event['detail']['findings'][0]['Resources'][0]['Details']['AwsEc2SecurityGroup']['GroupId'])
    findingId = str(event['detail']['findings'][0]['Id'])
    
    # import lambda function name from runtime vars
    lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    
    #Assume role in target account for response 
    session=account_session.get_session(targetAccount, os.environ['TargetAccountSecurityRoleName']) 

    #import boto3 clients
    ssm = session.client('ssm')
    securityhub = boto3.client('securityhub')
    try:
        response = ssm.start_automation_execution(
            # Launch SSM Doc via Automation
            DocumentName='AWS-DisablePublicAccessForSecurityGroup',
            DocumentVersion='1',
            Parameters={
                'GroupId': [ non_compliant_sg ]
            }
        )
        logger.info(response)
        try:
            response = securityhub.batch_update_findings(
                FindingIdentifiers=[
                    {
                        'Id': findingId,
                        'ProductArn': productArn
                    },
                ],
                Note={
                    'Text': 'Systems Manager Automation document to remove public access was successfully invoked on Security Group Id: ' + non_compliant_sg + '. Refer to Automation results to determine efficacy.',
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