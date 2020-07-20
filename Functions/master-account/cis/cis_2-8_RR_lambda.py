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

    # Parse ARN of non-compliant resource from Security Hub CWE
    noncompliantCMK = str(event['detail']['findings'][0]['Resources'][0]['Id'])

    # Remove ARN string, create new variable
    findingId = str(event['detail']['findings'][0]['Id'])

    # import lambda function name from env vars
    lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    formattedCMK = noncompliantCMK.replace("AWS::KMS::Key:", "") 

    #Assume role in target account for response 
    session=account_session.get_session(targetAccount, os.environ['TargetAccountSecurityRoleName']) 

    # Import KMS & SecHub Clients
    kms = session.client('kms')
    securityhub = boto3.client('securityhub')        

    # Rotate KMS Key
    try:
        rotate = kms.enable_key_rotation(KeyId=formattedCMK)
        time.sleep(3)
    except Exception as e:
        print(e)
        raise
    try:    
        confirmRotate = kms.get_key_rotation_status(KeyId=formattedCMK)
        rotationStatus = str(confirmRotate['KeyRotationEnabled'])
        if rotationStatus == 'True':
            logger.info("KMS CMK Rotation Successfully Enabled!")
            try:
                response = securityhub.batch_update_findings(
                    FindingIdentifiers=[
                        {
                            'Id': findingId,
                            'ProductArn': productArn
                        },
                    ],
                    Note={
                        'Text': 'Key Rotation successfully enabled for KMS key ' + formattedCMK,
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
        else:
            logger.info("KMS CMK Rotation Failed! Please troubleshoot manually!")
    except Exception as e:
        print(e)
        raise