from os import getenv
import json
import boto3

SNS_TOPIC_ARN = getenv('SNS_TOPIC_ARN')
WEB_ACL_ID = getenv('WEB_ACL_ID')

SUBJECT = 'WAF blocked IP list for "{}" updated'

sns = boto3.client('sns')
waf = boto3.client('waf')

def get_acl_by_id(web_acl_id):
    return waf.get_web_acl(WebACLId=web_acl_id)['WebACL']

def publish(data):
    if not SNS_TOPIC_ARN:
        return

    if WEB_ACL_ID:
        web_acl_name = get_acl_by_id(WEB_ACL_ID)['Name']
    else:
        web_acl_name = 'unknown'

    msg = {
      'web_acl_id': WEB_ACL_ID,
      'web_acl_name': web_acl_name,
      'payload': data
    }

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=SUBJECT.format(web_acl_name),
        Message=json.dumps(msg)
    )
