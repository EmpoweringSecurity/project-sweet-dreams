## Project Sweet Dreams

This project is to help you defend yourself in the Cloud, and it does not matter if you are a Fortune 500 company, state or local government or an SME. Designed to be Cyber force-multiplier as it leverages automation and automated incident response (if enabled) to help empower you to accomplish greater feats in your defence. 

Why is it named ‘Project Sweet Dreams’? I understand some of the pain points you may be experiencing like lack of resources (time and money), lack of skilled people especially in Cloud Security because these are some of the problems I have experienced and continue to help others with. This project is to help you worry about one less than while trying to sleep at night because you know that something is helping you protect your environment while you are asleep. It helps provide you with the peace of mind.

***Disclaimer:*** This project cannot defend you from every cyber threat, but it is a foundational piece that is inexpensive to run by leveraging native services and helps you automate some of the good cyber hygiene practices.

### Solution
Designed with a multi-account environment in mind and that anyone leveraging the AWS platform can use this to help them. This project provides a repeatable pattern to build more response playbooks in a scalable multi-account environment leveraging AWS native tooling. 

The solution has a concept of Response Packs, which is simply a collection of playbooks relating to a standard or technology. The thinking behind this is as more standards are introduced, you would need to add a nested stack to the `master-account-main.yaml`, the Lambda functions to the .zip and add the appropriate roles in the `member-account-main.yaml` file to extend the capability.

### Getting Started
There is a design concept used as Master and Member accounts, which intentionally aligns with Security Hub, which is vital to scaling in a multi-account environment.

#### Pre-requisites
1. Security Hub is enabled and Master/Member relationships configured in your region
2. AWS Config is enabled in your region for the master and each member account
3. In Security Hub, CIS AWS Foundations Benchmark v1.2.0 is enabled for the master and each member account

##### CIS Benchmark Pack Specific Pre-requisites
- CIS 2.4: CloudTrail to CloudWatch role name.
    
    *Resource to help:* If you don’t currently have an IAM role for CloudTrail, follow [these instructions](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html#send-cloudtrail-events-to-cloudwatch-logs-console) from the CloudTrail user guide to create one.

- CIS 2.6: Access Logging Bucket name with S3 Log Delivery Permissions Set.
    
    *Resource to help:* If you do not currently have an S3 bucket configured to receive access logs, follow [these directions](https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html#server-access-logging-overview) from the S3 user guide to create one.

- CIS 2.9: VPC Flow Logs to CloudWatch name. 

    *Resource to help:* If you don’t currently have an IAM role that VPC flow logs can use to deliver logs to CloudWatch, follow [these directions](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-cwl.html#flow-logs-iam) from the VPC user guide to create one.

#### Master Account
1. Download the zip or Clone the repo.
2. Upload all the AWS CloudFormation templates in the `project-sweat-dreams/CloudFormation/master-account/` folder to an S3 bucket in your account
3. Upload the `master-lambda-response-functions.zip` file in the `project-sweat-dreams/Functions/` folder to an S3 bucket in your account
4. Deploy the AWS CloudFormation template `master-account-main.yaml` using Object URL of the template uploaded in your S3 bucket in your Master Security Hub account. Please ensure the parameters are correct, especially your S3 buckets and the location prefixes. 
***IMPORTANT*** Because Security Hub is a regional service, deploy the stack in all your active regions! The solution is designed so that you can leverage CloudFormation StackSets to help you achieve this.

#### Member/Target Account
1. Download the AWS CloudFormation template in `project-sweat-dreams/CloudFormation/member-account/member-account-main.yaml` and deploy it in all your accounts you want the response capability. Because IAM Roles are global resources, you only need to deploy this stack once, per account, therefore you are not required to deploy in every region.

### Solutions Architecture
![Architecture](https://github.com/EmpoweringSecurity/project-sweat-dreams/blob/master/Docs/automated-response-diagrams.jpg) 

#### Manual Response ####
1.  Security Hub aggreates findings from integrated services in the member account.
2.  The master Security Hub account then receives the findings from the member account.
3.  ***Manual*** From the Security Hub console in the master account, you’ll choose a custom action for a finding. Each custom action is emitted as a CloudWatch Event.
4.  The CloudWatch Event rule triggers a Lambda function. This function is mapped to a custom action, based on the custom action’s ARN.
5.  The Lambda function invoked will perform a response by assuming a role in the target account, then excute the required actions. 
6.  If successful, the Lambda function will update the Security Hub finding in the master account to Workflow Status equals RESOLVED and update the notes.
7.  If successful, the Lambda function will send a message to the SNS Alerts Topic where you can configure whatever subscribers you would like.
#### Automated Response ####
1.  Security Hub aggreates findings from integrated services in the member account.
2.  The master Security Hub account then receives the findings from the member account.
3.  ***Automated*** From the Security Hub in the master account, the event is emited to CloudWatch.
4.  A finding sent to Security Hub and is evaluated by a CloudWatch Event Rule if there is a matched event pattern.
5.  The Lambda function invoked will perform a response by assuming a role in the target account, then excute the required actions. 
6.  If successful, the Lambda function will update the Security Hub finding in the master account to Workflow Status equals RESOLVED and update the notes.
7.  If successful, the Lambda function will send a message to the SNS Alerts Topic where you can configure whatever subscribers you would like.

### Response Packs
#### CIS AWS Benchmark Response Pack:
https://github.com/EmpoweringSecurity/project-sweat-dreams/blob/master/Docs/CIS_BENCHMARK_PACK.md
#### More to come...

## License

This library is licensed under the MIT License. See the LICENSE file.

## Credits
Thank you to some of the resources shared.

[Blog Post: Automated Response and Remediation with AWS Security Hub.](https://aws.amazon.com/blogs/security/automated-response-and-remediation-with-aws-security-hub/)
[Related GitHub](https://github.com/aws-samples/aws-security-hub-response-and-remediation)

[Blog Post: How to perform automated incident response in a multi-account environment.](https://aws.amazon.com/blogs/security/how-to-perform-automated-incident-response-multi-account-environment/)
[Related GitHub](https://github.com/aws-samples/automated-incident-response-with-ssm)