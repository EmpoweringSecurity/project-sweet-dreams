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
import argparse

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

    # Grab non-logged VPC ID from Security Hub finding
    noncompliantVPCFull = str(event['detail']['findings'][0]['Resources'][0]['Id'])
    noncompliantVPC = noncompliantVPCFull.split('/')[-1]
    findingId = str(event['detail']['findings'][0]['Id'])

    # import lambda runtime vars
    lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME'] 

    # Get Flow Logs Role ARN from env vars
    DeliverLogsPermissionRoleName = os.environ['FLOW_LOG_ROLE_NAME']    

    #Assume role in target account for response 
    session=account_session.get_session(targetAccount, TargetAccountSecurityRoleName) 

    # Import boto3 clients
    cwl = session.client('logs')
    ec2 = session.client('ec2')
    securityhub = boto3.client('securityhub')              

    # set dynamic variable for CW Log Group for VPC Flow Logs
    vpcFlowLogGroup = "VPCFlowLogs/" + noncompliantVPC + "/" + str(int(time.time()))  

    logger.info(f'VPC Flow Log Group Name: {vpcFlowLogGroup} generated based name and current time') 

    # create cloudwatch log group
    try:
        create_log_grp = cwl.create_log_group(logGroupName=vpcFlowLogGroup)
        logger.info(create_log_grp)
    except Exception as e:
        print(e)
        raise              

    # wait for CWL creation to propagate
    time.sleep(3)              

    # create VPC Flow Logging
    try:
        enableFlowlogs = ec2.create_flow_logs(
            DryRun=False,
            DeliverLogsPermissionArn= "arn:aws:iam::" + targetAccount + ":role/" + DeliverLogsPermissionRoleName,
            LogGroupName=vpcFlowLogGroup,
            ResourceIds=[ noncompliantVPC ],
            ResourceType='VPC',
            TrafficType='REJECT',
            LogDestinationType='cloud-watch-logs'
        )
        logger.info(enableFlowlogs)
    except Exception as e:
        print(e)
        raise

    # wait for Flow Log creation to propogate
    time.sleep(2)

    # searches for flow log status, filtered on unique CW Log Group created earlier
    try:
        confirmFlowlogs = ec2.describe_flow_logs(
        DryRun=False,
        Filters=[
            {
                'Name': 'log-group-name',
                'Values': [ vpcFlowLogGroup ]
            },
        ]
        )
        flowStatus = str(confirmFlowlogs['FlowLogs'][0]['FlowLogStatus'])
        if flowStatus == 'ACTIVE':
            try:
                response = securityhub.batch_update_findings(
                    FindingIdentifiers=[
                        {
                            'Id': findingId,
                            'ProductArn': productArn
                        },
                    ],
                    Note={
                        'Text': 'Flow logging is now enabled for VPC ' + noncompliantVPC + 'Log Group: ' + vpcFlowLogGroup,
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
            logger.info('Enabling VPC flow logging failed! Remediate manually')
            return 1
    except Exception as e:
        print(e)
        raise