import boto3
import json
import traceback
from collections.abc import Iterable


def get_client(service, region=None):
    if not region:
        return boto3.client(service)
    return boto3.client(service, region_name=region)


AWS_CONFIG_CLIENT = get_client('config', 'eu-west-1')
AWS_S3_CLIENT = get_client('s3')

TRAIL_S3_BUCKET = None
TRAIL_S3_BUCKET_REGION = None


def s3_modify_access_log(bucket_name, log_bucket, log_prefix):
    try:
        AWS_S3_CLIENT.put_bucket_acl(
            ACL='log-delivery-write', Bucket=log_bucket)

        bucket_logging = {
            'LoggingEnabled': {
                'TargetBucket': log_bucket,
                'TargetPrefix': log_prefix
            }
        }
        #print("new log definition: " + json.dumps(bucket_logging))
        AWS_S3_CLIENT.put_bucket_logging(Bucket=bucket_name, BucketLoggingStatus=bucket_logging)
        print(' -- logging set to arn:aws:s3:::{}/{}'.format(log_bucket, log_prefix))
    except Exception as e:
        print(e)
        print(traceback.format_exc())


def s3_get_bucket_location(bucket_name):
    try:
        return AWS_S3_CLIENT.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        return None


# sets the access log for given bucket
# tries to use the same bucket as used for CloudTrail, for buckets located in other regions logs are set in the same bucket
def s3_set_access_log(bucket_name):
    bucket_region = s3_get_bucket_location(bucket_name)
    if bucket_name == None:
        print('ERROR: Bucket location cannot be determined, most likely bucket doesn\'t exist')
        return
    log_def = AWS_S3_CLIENT.get_bucket_logging(Bucket=bucket_name)
    #print(">>>>> " + json.dumps(log_def))
    log_bucket = None
    if 'LoggingEnabled' in log_def:
        log_bucket = "arn:aws:s3:::" + log_def['LoggingEnabled']['TargetBucket']
        if log_def['LoggingEnabled']['TargetPrefix']: 
            log_bucket += "/" + log_def['LoggingEnabled']['TargetPrefix']
        log_bucket += " " + s3_get_bucket_location(log_def['LoggingEnabled']['TargetBucket'])
        
        print(' -- logging: {}'.format(log_bucket))
    else:
        if bucket_region == TRAIL_S3_BUCKET_REGION:
            # set trail bucket as log bucket
            s3_modify_access_log(bucket_name, TRAIL_S3_BUCKET, bucket_name)
        else:
            # set access log to the logs folder in the same bucket, it should be rare that we have buckets in other regions
            s3_modify_access_log(bucket_name, bucket_name, 'logs/')



def s3_apply_https_only_policy(bucket_name):
    
    bucketArn = "arn:aws:s3:::" + bucket_name
    secure_in_transit_sid = "EnforceHttpsAlways"
    secure_in_transit = {
        "Sid": secure_in_transit_sid,
        "Effect": "Deny",
        "Principal": "*",
        "Action": "*",
        "Resource": [
           bucketArn,
           bucketArn+"/*"
        ],
        "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    }
    
    bucket_policy = None
    try:
        policy = AWS_S3_CLIENT.get_bucket_policy(Bucket=bucket_name)
        policyObj = json.loads(policy['Policy'])
        if policyObj['Statement']:
            alreadySecured = False
            for statement in policyObj['Statement']:
                if statement['Sid'] == secure_in_transit_sid:
                    alreadySecured = True
                # print('  -- ' + statement['Sid'])
            if not alreadySecured:
                policyObj['Statement'].append(secure_in_transit)
                bucket_policy = json.dumps(policyObj)
        
    except Exception as e:
        # bucket doesn't have policy yet
        bucket_policy = {
            'Version': '2012-10-17',
            'Statement': [secure_in_transit]
            }
        bucket_policy = json.dumps(bucket_policy)
    
    if bucket_policy != None:
        try:
            AWS_S3_CLIENT.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)
            print(' -- applied {}, effective policy: {}'.format(secure_in_transit_sid, bucket_policy))
        except Exception as e:
            print(e)
    else:
        print(' -- bucket already has valid Policy'.format())



def fix_1_critical_s3_bucket_correctly_configured(bucket_name):
    try:
        bucket_location = AWS_S3_CLIENT.get_bucket_location(Bucket=bucket_name)
        #if bucket['Name'] == 'aws-codestar-eu-central-1-947012279941-lambda-test-pipe':
        print('######################################################')
        print('# Bucket {} - {}'.format(bucket_name, bucket_location['LocationConstraint']) )
        s3_apply_https_only_policy(bucket_name)
        s3_set_access_log(bucket_name)
    except Exception as e:
        print(e)
        print(traceback.format_exc())


def vpc_load(vpc_id, vpc_region):
    try:
        AWS_EC2_RESOURCE = boto3.resource('ec2', vpc_region)
        vpc = AWS_EC2_RESOURCE.Vpc(vpc_id)
    except Exception as e:
        print(e)
        print(traceback.format_exc())


def vpc_check_if_empty(vpc):
    subresources = ','.join(map(str, vpc.get_available_subresources()))
    subresources_str = "empty"
    if isinstance(subresources, Iterable):
        subresources_str = ','.join(map(str, subresources))
    subnets = "empty"
    if isinstance(vpc.subnets, Iterable):
        subnets = ','.join(map(str, vpc.subnets))
    if not subresources and not isinstance(vpc.subnets, Iterable):
        return True
    else:
        print(" -- subresources: " + subresources)
        print(" -- subnets: " + subnets)
        return False


# removes vpc dependencies except instances, endpoints and peering connections
def vpc_remove_dependencies(vpc):
    # detach and delete all gateways associated with the vpc
    for gw in vpc.internet_gateways.all():
        print(" --- detaching GW " + gw.id)
        vpc.detach_internet_gateway(InternetGatewayId=gw.id)
        gw.delete()
    # delete all route table associations
    for rt in vpc.route_tables.all():
        for rta in rt.associations:
            if not rta.main:
                print(" --- deleting route table " + rta.id)
                rta.delete()
    # delete our security groups
    for sg in vpc.security_groups.all():
        if sg.group_name != 'default':
            print(" --- deleting security group " + sg.group_name)
            sg.delete()
    # delete non-default network acls
    for netacl in vpc.network_acls.all():
        if not netacl.is_default:
            print(" --- deleting NACL " + netacl.id)
            netacl.delete()
    # delete network interfaces
    for subnet in vpc.subnets.all():
        for interface in subnet.network_interfaces.all():
            print(" --- deleting subnet network interfaces " + interface.id)
            interface.delete()
        print(" --- deleting subnet " + subnet.id)
        subnet.delete()



def fix_3_medium_vpc_flow_logs_enabled(vpc_id, vpc_region):
    vpc = vpc_load(vpc_id, vpc_region)
    if not vpc:
        print('VPC does not exist')
        return
    if vpc_check_if_empty(vpc):
        if vpc_region != TRAIL_S3_BUCKET_REGION:
            print(' -- empty VPC - we should delete the VPC')
        else:
            print(' -- empty VPC in your main region, please consider deleting it')
    else:
        print(' -- we need to set up VPC Flow Logs')



def fix_3_medium_vpc_no_default_vpc(vpc_id, vpc_region):
    vpc = vpc_load(vpc_id, vpc_region)
    if not vpc:
        print('VPC does not exist')
        return
    if vpc_check_if_empty(vpc):
        if vpc_region != TRAIL_S3_BUCKET_REGION:
            print(' -- empty VPC - deleting the VPC')
            # UNCOMMENT THE FOLLOWING TWO LINES IF YOU'D LIKE TO CLEAN UP DEFAULT VPCs
            #vpc_remove_dependencies(vpc)
            #get_client('ec2', vpc_region).delete_vpc(VpcId=vpc_id)
        else:
            print(' -- empty VPC in your main region, please consider deleting it')



def get_not_compliant_evaluations(rule_name):
    all_eval_part = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(ConfigRuleName=rule_name, ComplianceTypes=['NON_COMPLIANT'], Limit=100)
    all_eval = []
    while True:
        for eva in all_eval_part['EvaluationResults']:
            all_eval.append(eva)
        if 'NextToken' in all_eval_part:
            next_token = all_eval_part['NextToken']
            all_eval_part = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(ConfigRuleName=rule_name, NextToken=next_token, Limit=100)
        else:
            break
    return all_eval

def get_all_rules():
    all_rules_part = AWS_CONFIG_CLIENT.describe_config_rules()
    all_rules = []
    while True:
        for rule in all_rules_part['ConfigRules']:
            all_rules.append(rule)
        if 'NextToken' in all_rules_part:
            next_token = all_rules_part['NextToken']
            all_rules_part = AWS_CONFIG_CLIENT.describe_config_rules(NextToken=next_token)
        else:
            break
    return all_rules



def get_trail_bucket_region():
    print('######### Cloud Trails #######')
    try:
        AWS_TRAIL_CLIENT = get_client('cloudtrail')
        trails = AWS_TRAIL_CLIENT.describe_trails(trailNameList=[],includeShadowTrails=False)
        #print(trails['trailList'])
        if len(trails['trailList']) > 0:
            TRAIL_S3_BUCKET = trails['trailList'][0]['S3BucketName']
            TRAIL_S3_BUCKET_REGION = AWS_S3_CLIENT.get_bucket_location(Bucket=TRAIL_S3_BUCKET)['LocationConstraint']
            print('Cloud trail bucket \'{}\' located in {} will be used for S3 bucket access logs - if we need to set it'.format(TRAIL_S3_BUCKET, TRAIL_S3_BUCKET_REGION))
        else:
            print('!!!!!!!!!!!!!!!! ERROR: Trail bucket and location not recognized')
    except Exception as e:
        print(e)
    print('##############################')


def check_pcs_config_rules(risk_level):
    config_rule_list = {}
    try:
        config_rule_list = get_all_rules()
    except Exception as e:
        print(e)
    print('######### Config Rules #######')
    for rule in config_rule_list:
        if ord(rule['ConfigRuleName'][0]) - ord('1') < risk_level + 1:
            rule_evaluations = get_not_compliant_evaluations(rule['ConfigRuleName'])
            if len(rule_evaluations) > 0:
                print("{} - {} not compliant resources - {}".format(rule['ConfigRuleName'], len(rule_evaluations), rule['Description']))
            if rule['ConfigRuleName'] == '1_CRITICAL-S3_BUCKET_CORRECTLY_CONFIGURED':
                for evaluation in rule_evaluations:
                    #print(evaluation)
                    print("## " + evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']
                        + " " + evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'])
                    fix_1_critical_s3_bucket_correctly_configured(evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'])
                print()
            elif rule['ConfigRuleName'] == '2_HIGH-MANDATORY_RESOURCE_TAGGING_FOLLOWED':
                # we do not print not-tagged resources for now
                print()
            elif rule['ConfigRuleName'] == '3_MEDIUM-VPC_FLOW_LOGS_ENABLED':
                for evaluation in rule_evaluations:
                    resource_id = evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
                    print("## " + evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType'] + " " + resource_id)
                    vpc_region = resource_id.split(':')[3]
                    vpc_id = resource_id[resource_id.index('/') + 1:]
                    fix_3_medium_vpc_flow_logs_enabled(vpc_id, vpc_region)
                print()
            elif rule['ConfigRuleName'] == '3_MEDIUM-VPC_NO_DEFAULT_VPC':
                for evaluation in rule_evaluations:
                    resource_id = evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
                    print("## " + evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType'] + " " + resource_id)
                    vpc_region = resource_id.split(':')[3]
                    vpc_id = resource_id[resource_id.index('/') + 1:]
                    fix_3_medium_vpc_no_default_vpc(vpc_id, vpc_region)
                print()
            elif rule['ConfigRuleName'] == '3_MEDIUM-RECOMMENDED_RESOURCE_TAGGING_FOLLOWED':
                # we do not print not-tagged resources for now
                print()
            else:
                for evaluation in rule_evaluations:
                    print("## " + evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']
                        + " " + evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'])
    print('##################################')




HIGH_RISKS=1
MEDIUM_RISKS=2
LOW_RISKS=3

get_trail_bucket_region()
check_pcs_config_rules(MEDIUM_RISKS)


# list_buckets_resp = AWS_S3_CLIENT.list_buckets()
# for bucket in list_buckets_resp['Buckets']:
#     fix_1_critical_s3_bucket_correctly_configured(bucket['Name'])
    
