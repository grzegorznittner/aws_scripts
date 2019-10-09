import boto3
import json
import traceback
from collections.abc import Iterable


#################################################
# set to True if you want to delete default VPCs
DELETE_DEFAULT_VPC=True
MODIFY_NOT_COMPLAINT_SG=True

TAG_ENVIRONMENT = ''
TAG_PONUMBER = 'PO1234567890'
TAG_LMENTITY = 'VGSL'
TAG_BU = 'GROUP-CONSUMER'
TAG_PROJECT = 'START'
TAG_MANAGEDBY = 'dl-gt_info_start@vodafone.com'
TAG_CONFIDENTIALITY = 'C3'
TAG_VERSION = 'V2.0'
TAG_BUSINESS_SERVICE = TAG_LMENTITY+'-AWS-'+TAG_PROJECT+'-'+TAG_ENVIRONMENT
#
#################################################

def get_client(service, region=None):
    if not region:
        return boto3.client(service)
    return boto3.client(service, region_name=region)


AWS_S3_CLIENT = get_client('s3')

TRAIL_S3_BUCKET = None
TRAIL_S3_BUCKET_REGION = None
REGIONS = []

def check_available_regions():
    global REGIONS
    try:
        client = get_client('ec2')
        REGIONS = [region['RegionName'] for region in client.describe_regions()['Regions']]
    except Exception as e:
        print(e)


# Method tags given resource list with SecurityZone tag
# It is not part of regular config check/fix, should be run manually to set that tag
def ec2_tag_resource_list():
    resources = {
        'arn:aws:ec2:eu-central-1:account-id:instance/i-abc1234567890': 'DEV',
        'arn:aws:ec2:eu-central-1:account-id:internet-gateway/igw-abc1234567890': 'E-O',
        'arn:aws:ec2:eu-central-1:account-id:network-acl/acl-abc1234567890': 'DEV'
    }

    for k, v in resources.items():
        vpc_region = k.split(':')[3]
        client = get_client('resourcegroupstaggingapi', vpc_region)
        print('# tagging {} with SecurityZone: {}'.format(k, v))
        client.tag_resources(ResourceARNList=[k], Tags={'SecurityZone': v} )



def ec2_describe_tag(region_name, resource_id):
    client = get_client('ec2', region_name)
    result = client.describe_tags(Filters=[
        {
            'Name': 'resource-id',
            'Values': [ resource_id ]
        }
    ])
    return result['Tags']


def set_tag_values():
    global TAG_ENVIRONMENT, TAG_PONUMBER, TAG_LMENTITY, TAG_BU, TAG_PROJECT, TAG_MANAGEDBY
    global TAG_CONFIDENTIALITY, TAG_VERSION, TAG_BUSINESS_SERVICE
    print('## Default labels:')
    print('## TAG_PONUMBER = {}'.format(TAG_PONUMBER))
    print('## TAG_LMENTITY = {}'.format(TAG_LMENTITY))
    print('## TAG_BU = {}'.format(TAG_BU))
    print('## TAG_PROJECT = {}'.format(TAG_PROJECT))
    print('## TAG_MANAGEDBY = {}'.format(TAG_MANAGEDBY))
    print('## TAG_CONFIDENTIALITY = {}'.format(TAG_CONFIDENTIALITY))
    print('## TAG_VERSION = {}'.format(TAG_VERSION))
    print()
    while not TAG_ENVIRONMENT in ['SANDBOX', 'MGMT', 'DEV', 'TEST', 'PRE-PROD', 'PROD']:
        TAG_ENVIRONMENT = input('Please set the environment tag value (allowed values: SANDBOX, MGMT, DEV, TEST, PRE-PROD, PROD)? ')
    TAG_BUSINESS_SERVICE = TAG_LMENTITY+'-AWS-'+TAG_PROJECT+'-'+TAG_ENVIRONMENT


def unset_wrong_tags(client, resource_id):
    try:
        response = client.untag_resources(
            ResourceARNList=[resource_id],
            TagKeys=['TAG_ENVIRONMENT','TAG_PONUMBER','TAG_LMENTITY','TAG_BU','TAG_PROJECT',
                'TAG_MANAGEDBY','TAG_CONFIDENTIALITY','TAG_VERSION','TAG_BUSINESS_SERVICE']
        )
    except Exception as e:
        print(e)
        #print(traceback.format_exc())


def cloudfront_tag_resource(resource_id, tags):
    items = []
    for k, v in tags.items():
        items.append({'Key': k, 'Value': v})
    #print(items)
    client = get_client('cloudfront')
    client.tag_resource(Resource=resource_id, Tags={ 'Items': items})


def fix_2_high_mandatory_resource_tagging_followed(region_name, resource_type, resource_id):
    global TAG_ENVIRONMENT, TAG_PONUMBER, TAG_LMENTITY, TAG_BU, TAG_PROJECT, TAG_MANAGEDBY
    global TAG_CONFIDENTIALITY, TAG_VERSION, TAG_BUSINESS_SERVICE
    if TAG_ENVIRONMENT == '':
        set_tag_values()
    tags = {
        'Environment': TAG_ENVIRONMENT,
        'PONumber': TAG_PONUMBER,
        'LMEntity': TAG_LMENTITY,
        'BU': TAG_BU,
        'Project': TAG_PROJECT,
        'ManagedBy': TAG_MANAGEDBY,
        'Confidentiality': TAG_CONFIDENTIALITY,
        'TaggingVersion': TAG_VERSION,
        'BusinessService': TAG_BUSINESS_SERVICE
    }
    
    try:
        if resource_type == 'AWS::CloudFront::Distribution':
            # cloudfront needs to he tagged using cloudfront api which uses different parameters
            cloudfront_tag_resource(resource_id, tags)
        else:
            client = get_client('resourcegroupstaggingapi', region_name)
            unset_wrong_tags(client, resource_id)
            client.tag_resources(ResourceARNList=[resource_id], Tags=tags)
        print(' -- resource tagged')
    except Exception as e:
        print('Error: resource id: {}, region: {}'.format(resource_id, region_name))
        print(e)
        #print(traceback.format_exc())


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
        location = AWS_S3_CLIENT.get_bucket_location(Bucket=bucket_name)
        #print(' --- bucket {} region: {}'.format(location, location['LocationConstraint']))
        if location['LocationConstraint']!=None:
            return location['LocationConstraint']
        else:
            return 'us-east-1'
    except Exception as e:
        print(e)
        #print(traceback.format_exc())
        return None


# sets the access log for given bucket
# tries to use the same bucket as used for CloudTrail, for buckets located in other regions logs are set in the same bucket
def s3_set_access_log(bucket_name):
    global TRAIL_S3_BUCKET_REGION, TRAIL_S3_BUCKET
    
    bucket_region = s3_get_bucket_location(bucket_name)
    if bucket_name == None:
        print('ERROR: Bucket location cannot be determined, most likely bucket doesn\'t exist')
        return
    log_def = AWS_S3_CLIENT.get_bucket_logging(Bucket=bucket_name)
    #print(">>>>> " + json.dumps(log_def))
    set_logs = True
    
    if 'LoggingEnabled' in log_def and 'TargetBucket' in log_def['LoggingEnabled']:
        log_bucket = "arn:aws:s3:::" + log_def['LoggingEnabled']['TargetBucket']
        #print(' --- logging target bucket: ' + log_bucket)
        log_bucket_region = s3_get_bucket_location(log_def['LoggingEnabled']['TargetBucket'])
        if log_def['LoggingEnabled']['TargetPrefix']: 
            log_bucket += "/" + log_def['LoggingEnabled']['TargetPrefix']
        log_bucket += " " + log_bucket_region
        print(' -- logging: {}'.format(log_bucket))
        set_logs = False
        if not log_def['LoggingEnabled']['TargetPrefix'].endswith('/'):
            print(' -- logging needs to be fixed: {}'.format(log_bucket))
            set_logs=True
        if bucket_region==TRAIL_S3_BUCKET_REGION and log_def['LoggingEnabled']['TargetBucket']!=TRAIL_S3_BUCKET:
            print(' -- logging needs to be fixed: {}'.format(log_bucket))
            set_logs=True
    if set_logs:
        if bucket_region==TRAIL_S3_BUCKET_REGION:
            # set trail bucket as log bucket
            s3_modify_access_log(bucket_name, TRAIL_S3_BUCKET, bucket_name + '/')
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
        bucket_location = s3_get_bucket_location(bucket_name)
        if bucket_location:
            print('# Bucket {} - {}'.format(bucket_name, bucket_location) )
            s3_apply_https_only_policy(bucket_name)
            s3_set_access_log(bucket_name)
        else:
            print('# Bucket {} does not exist'.format(bucket_name) )
    except Exception as e:
        print(e)
        print(traceback.format_exc())


def vpc_load(vpc_id, vpc_region):
    try:
        AWS_EC2_RESOURCE = boto3.resource('ec2', vpc_region)
        vpc = AWS_EC2_RESOURCE.Vpc(vpc_id)
        vpc.load()
        return vpc
    except Exception as e:
        print(e)
        #print(traceback.format_exc())
        return None


def vpc_check_if_empty(vpc):
    empty = True
    for instance in vpc.instances.all():
        empty = False
        print(' --- instance {}'.format(instance))
    for gw in vpc.internet_gateways.all():
        print(' --- GW {}'.format(gw.id))
    for rt in vpc.route_tables.all():
        for rta in rt.associations:
            if not rta.main:
                print(' --- route table {}'.format(rta.id))
    for sg in vpc.security_groups.all():
        if sg.group_name != 'default':
            print(" --- security group " + sg.group_name)
    for netacl in vpc.network_acls.all():
        if not netacl.is_default:
            print(" --- NACL " + netacl.id)
    for subnet in vpc.subnets.all():
        for interface in subnet.network_interfaces.all():
            print(" --- subnet network interfaces " + interface.id)
    return empty


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
    global TRAIL_S3_BUCKET_REGION
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
        if vpc.is_default:
            print(' -- default vpc {} in region {} should be deleted'.format(vpc_id, vpc_region))
            if DELETE_DEFAULT_VPC:
                answer = input('Do you want to delete vpc {} region {}? [Y/n]'.format(vpc_id, vpc_region))
                if answer == 'Y':
                    print(' -- deleting the VPC')
                    # UNCOMMENT THE FOLLOWING TWO LINES IF YOU'D LIKE TO CLEAN UP DEFAULT VPCs
                    vpc_remove_dependencies(vpc)
                    get_client('ec2', vpc_region).delete_vpc(VpcId=vpc_id)
        else:
            print(' -- not default vpc {} {}'.format(vpc_id, vpc_region))
    else:
        print(' -- vpc is not empty {} {}'.format(vpc_id, vpc_region))



def sg_get_resources(sg_id, vpc_region):
    security_group_resources = []
    # Security groups used by classic ELBs
    AWS_ELB_CLIENT = get_client('elb', vpc_region)
    elb_dict = AWS_ELB_CLIENT.describe_load_balancers()
    for elb in elb_dict['LoadBalancerDescriptions']:
        for j in elb['SecurityGroups']:
            security_group_resources.append(elb)
    
    # Security groups used by ALBs
    AWS_ALB_CLIENT = get_client('elbv2', vpc_region)
    elb2_dict = AWS_ALB_CLIENT.describe_load_balancers()
    for alb in elb2_dict['LoadBalancers']:
        for j in alb['SecurityGroups']:
            security_group_resources.append(alb)
    
    # Security groups used by RDS
    AWS_ALB_CLIENT = get_client('rds', vpc_region)
    rds_dict = AWS_ALB_CLIENT.describe_db_security_groups()
    
    for rds in rds_dict['DBSecurityGroups']:
        for j in rds['EC2SecurityGroups']:
            security_group_resources.append(rds)
    return security_group_resources


def sg_print_details(sg_id, sg, vpc_region, short=False):
    if not short:
        print('## SecurityGroup id:{} name:{} belongs to vpc id:{} region:{}'.format(sg_id, sg.group_name, sg.vpc_id, vpc_region))
    print(' --- inbound rules:')
    for ig_perm in sg.ip_permissions:
        print('      {}'.format(ig_perm))
    print(' --- outbound rules:')
    for ig_perm in sg.ip_permissions_egress:
        print('      {}'.format(ig_perm))
    # AWS_EC2_CLIENT = get_client('ec2', vpc_region)
    # response = AWS_EC2_CLIENT.describe_security_groups(GroupIds=[sg_id])
    # print(' --- sg describe: {}'.format(json.dumps(response['SecurityGroups'][0], indent=4, sort_keys=True)))

def sg_secure_ingress(ig_perm):
    if ig_perm['IpRanges']:
        if 'CidrIp' in ig_perm['IpRanges'][0]:
            if ig_perm['IpRanges'][0]['CidrIp'] == '0.0.0.0/0':
                return False
    if ig_perm['IpProtocol'] == '-1':
        return False
    return True

def sg_block_public_ingress(sg, ig_perm):
    try:
        sg.revoke_ingress(IpPermissions=[ig_perm])
    except Exception as e:
        print(e)
        #print(traceback.format_exc())
        return None


def sg_secure_egress(ig_perm):
    if ig_perm['IpRanges']:
        if 'CidrIp' in ig_perm['IpRanges'][0]:
            if ig_perm['IpRanges'][0]['CidrIp'] == '0.0.0.0/0':
                return False
    if ig_perm['IpProtocol'] == '-1':
        return False
    return True


def sg_block_public_egress(sg, ig_perm):
    try:
        sg.revoke_egress(IpPermissions=[ig_perm])
    except Exception as e:
        print(e)
        #print(traceback.format_exc())
        return None



def fix_3_medium_vpc_security_group_default_blocked(sg_id, vpc_region):
    try:
        ec2 = boto3.resource('ec2', vpc_region)
        sg = ec2.SecurityGroup(sg_id)
        sg.load()
        sg_print_details(sg_id, sg, vpc_region)
        vpc = vpc_load(sg.vpc_id, vpc_region)
        
        sg_resources = sg_get_resources(sg_id, vpc_region)
        if sg_resources:
            for r in sg_resources:
                print (' --- {}'.format(r))
        else:
            print (' --- no associated resources found (ELB,ALB,RDS)')
            sg_modified = False
            if MODIFY_NOT_COMPLAINT_SG:
                print(' - Securing inbound rules:')
                for ig_perm in sg.ip_permissions:
                    if not sg_secure_ingress(ig_perm):
                        print('      {}'.format(ig_perm))
                        answer = input('Do you want to remove open access rule? [Y/n] ')
                        if answer == 'Y':
                            print(' -- removing open access rule')
                            sg_block_public_ingress(sg, ig_perm)
                            sg_modified = True
                print(' - Securing outbound rules:')
                for ig_perm in sg.ip_permissions_egress:
                    if not sg_secure_ingress(ig_perm):
                        print('      {}'.format(ig_perm))
                        answer = input('Do you want to remove open access rule? [Y/n] ')
                        if answer == 'Y':
                            print(' -- removing open access rule')
                            sg_block_public_egress(sg, ig_perm)
                            sg_modified = True
                if sg_modified:
                    sg.load()
                    print(' - security group rules after changes:')
                    sg_print_details(sg_id, sg, vpc_region, short=True)
    except Exception as e:
        print('## {} - error handling security group'.format(sg_id))
        print(e)
        print(traceback.format_exc())


def get_not_compliant_evaluations(client, rule_name):
    all_eval_part = client.get_compliance_details_by_config_rule(ConfigRuleName=rule_name, ComplianceTypes=['NON_COMPLIANT'], Limit=100)
    all_eval = []
    while True:
        for eva in all_eval_part['EvaluationResults']:
            all_eval.append(eva)
        if 'NextToken' in all_eval_part:
            next_token = all_eval_part['NextToken']
            all_eval_part = client.get_compliance_details_by_config_rule(ConfigRuleName=rule_name, NextToken=next_token, Limit=100)
        else:
            break
    return all_eval

def get_all_rules(client):
    all_rules_part = client.describe_config_rules()
    all_rules = []
    while True:
        for rule in all_rules_part['ConfigRules']:
            all_rules.append(rule)
        if 'NextToken' in all_rules_part:
            next_token = all_rules_part['NextToken']
            all_rules_part = client.describe_config_rules(NextToken=next_token)
        else:
            break
    return all_rules



def get_trail_bucket_region():
    global TRAIL_S3_BUCKET_REGION, TRAIL_S3_BUCKET
    print('######### Cloud Trails #######')
    try:
        AWS_TRAIL_CLIENT = get_client('cloudtrail')
        trails = AWS_TRAIL_CLIENT.describe_trails(trailNameList=[],includeShadowTrails=False)
        #print(trails['trailList'])
        if len(trails['trailList']) > 0:
            TRAIL_S3_BUCKET = trails['trailList'][0]['S3BucketName']
            TRAIL_S3_BUCKET_REGION = s3_get_bucket_location(TRAIL_S3_BUCKET)
            print('Cloud trail bucket \'{}\' located in {} will be used for S3 bucket access logs - if we need to set it'.format(TRAIL_S3_BUCKET, TRAIL_S3_BUCKET_REGION))
        else:
            print('!!!!!!!!!!!!!!!! ERROR: Trail bucket and location not recognized')
    except Exception as e:
        print(e)
    print('##############################')


def check_pcs_config_rules(risk_level, region_name):
    AWS_CONFIG_CLIENT = get_client('config', region_name)
    config_rule_list = {}
    try:
        config_rule_list = get_all_rules(AWS_CONFIG_CLIENT)
    except Exception as e:
        print(e)
    ec2_special_tagging_resources = []
    print('######### Config Rules #######')
    for rule in config_rule_list:
        if ord(rule['ConfigRuleName'][0]) - ord('1') < risk_level + 1:
            rule_evaluations = get_not_compliant_evaluations(AWS_CONFIG_CLIENT, rule['ConfigRuleName'])
            if len(rule_evaluations) > 0:
                print("###### {} ######".format(rule['ConfigRuleName']))
                print("## {} not compliant resources - {}".format(len(rule_evaluations), rule['Description']))
            for evaluation in rule_evaluations:
                #print(evaluation)
                resource_id = evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
                resource_type = evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']
                
                vpc_region = 'eu-central-1'
                resource_short_id = resource_id
                if resource_id.startswith('arn:aws:'):
                    vpc_region = resource_id.split(':')[3]
                if not vpc_region in REGIONS:
                    vpc_region = "eu-central-1"
                if resource_id.find('/') > 0:
                    resource_short_id = resource_id[resource_id.index('/') + 1:]
                
                if resource_type == 'AWS::S3::Bucket':
                    resource_id = 'arn:aws:s3:::'+resource_id
                if resource_type == 'AWS::CloudFront::Distribution':
                    vpc_region = None
                
                print("## {} - {}".format(resource_type, resource_id))

                if rule['ConfigRuleName'] == '1_CRITICAL-S3_BUCKET_CORRECTLY_CONFIGURED':
                    fix_1_critical_s3_bucket_correctly_configured(resource_id)
                elif rule['ConfigRuleName'] == '2_HIGH-MANDATORY_RESOURCE_TAGGING_FOLLOWED':
                    if resource_id.startswith('arn:aws:ec2') and not resource_id in ec2_special_tagging_resources:
                        ec2_special_tagging_resources.append(resource_id)
                    fix_2_high_mandatory_resource_tagging_followed(vpc_region, resource_type, resource_id)
                elif rule['ConfigRuleName'] == '3_MEDIUM-VPC_FLOW_LOGS_ENABLED':
                    fix_3_medium_vpc_flow_logs_enabled(resource_short_id, vpc_region)
                elif rule['ConfigRuleName'] == '3_MEDIUM-VPC_NO_DEFAULT_VPC':
                    if resource_id.split(':')[5].startswith('vpc/'):
                        fix_3_medium_vpc_no_default_vpc(resource_short_id, vpc_region)
                elif rule['ConfigRuleName'] == '3_MEDIUM-RECOMMENDED_RESOURCE_TAGGING_FOLLOWED':
                    if resource_id.startswith('arn:aws:ec2') and not resource_id in ec2_special_tagging_resources:
                        ec2_special_tagging_resources.append(resource_id)
                    fix_2_high_mandatory_resource_tagging_followed(vpc_region, resource_type, resource_id)
                elif rule['ConfigRuleName'] == '3_MEDIUM-VPC_SECURITY_GROUP_DEFAULT_BLOCKED':
                    if resource_id.split(':')[5].startswith('security_group/'):
                        fix_3_medium_vpc_security_group_default_blocked(resource_short_id, vpc_region)
                else:
                    None
        print('##')
    print('The following resources needs to be tagged manually with tag \'SecurityZone\':')
    for resource_id in ec2_special_tagging_resources:
        resource_short_id = resource_id[resource_id.index('/') + 1:]
        vpc_region = resource_id.split(':')[3]
        tags = ec2_describe_tag(vpc_region, resource_short_id)
        zone = [tag['Value'] for tag in tags if tag['Key']=='SecurityZone']
        print('# {} SecurityZone: {}'.format(resource_id, zone))
    print('##################################')
    print('')




HIGH_RISKS=1
MEDIUM_RISKS=2
LOW_RISKS=3

check_available_regions()
get_trail_bucket_region()
check_pcs_config_rules(MEDIUM_RISKS, 'eu-west-1')

#ec2_tag_resource_list()


# list_buckets_resp = AWS_S3_CLIENT.list_buckets()
# for bucket in list_buckets_resp['Buckets']:
#     fix_1_critical_s3_bucket_correctly_configured(bucket['Name'])

