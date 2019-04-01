import boto3
import re
ec2 = boto3.resource('ec2')

def revoke_ingress(desc, port, cidrip, group_name, security_group):
    
    
    print desc +','+port+','+cidrip+','+group_name
    
    # Optional Code to enable IP Range Filterring 
    if (str(re.match("(172.31.)+\d+.\d+\/+(32)", str(cidrip))) == 'None' and  str(re.match("(10.)\d+.\d+.\d+\/+(32)", str(cidrip))) == 'None' ):
        
        print 'revoke'
        # Calling Revoke Ingress
        security_group.revoke_ingress(
            GroupName=security_group.group_name,
            IpPermissions=[
                {
                    'FromPort': port,
                    'ToPort': port,
                    'IpProtocol': 'tcp',
                    'IpRanges': [
                        {
                            'CidrIp': ip_range['CidrIp'],
                            'Description': ip_range['Description']
                        },
                    ]
                }
            ]
                )
    else:
        print 'not revoke'
    
        
        
def lambda_handler(event, context):

    # Filtering instances based on tag:Name
    # Optional Can be skipped if not working on a particular instance
    filters = [
        {
            'Name': 'tag:Name',
            'Values': ['<InstanceName1>','InstanceName2']
        },
        
    ]
    
    
    instances = ec2.instances.filter(Filters=filters)
    
    for instance in instances:    
        
        # Extracting all GroupId of all the security_groups in that particular instance
        all_sg_ids = [sg['GroupId'] for sg in instance.security_groups]
        for sg_id in all_sg_ids:
                   
            security_group = ec2.SecurityGroup(sg_id)
            
            tag = list(security_group.tags)
            
            # Extracting all Ip Permissions from that particular security_group
            ips = list(security_group.ip_permissions)
            
            for x in range(len(ips)):
                
                IpRangesList = ips[x]['IpRanges']
                for iprs in IpRangesList:
                
                    if 'CidrIp' in iprs :
                        if 'Description' in iprs :
                            if any(['22' == str(ips[x]['FromPort']),'2299' == str(ips[x]['FromPort'])]):
                                #print 'Description: ' + iprs['Description'] + ' , ' + 'FromPort: '+str(ips[x]['FromPort'])  + ' , ' + 'ToPort: '+str(ips[x]['ToPort'])  + ' , ' +  'CidrIp: ' + iprs['CidrIp']
                                revoke_ingress(iprs['Description'], str(ips[x]['FromPort']), iprs['CidrIp'], security_group.group_name, security_group)
                        else:
                            if any(['22' == str(ips[x]['FromPort']),'2299' == str(ips[x]['FromPort'])]):
                                print 'Description: ' + 'blank' + ' , ' +  'CidrIp: ' + iprs['CidrIp']
                    
            
    return 'Done'
