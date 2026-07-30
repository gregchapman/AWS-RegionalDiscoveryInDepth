#!/usr/bin/env python3
"""
Map all internet-facing resources in an AWS account/region.

Traces traffic paths: Internet → Load Balancers → EC2 → RDS
Identifies direct internet exposure via IGW-routed subnets and 0.0.0.0/0 SG rules.

Usage:
    python map-all-internet-facing-resources.py --region us-gov-west-1
    python map-all-internet-facing-resources.py --region us-gov-east-1
"""

import sys
import argparse

import boto3


def parse_args():
    parser = argparse.ArgumentParser(
        description="Map internet-facing resources and trace traffic paths (LB → EC2 → RDS)."
    )
    parser.add_argument(
        "--region", required=True,
        help="AWS region to scan (e.g., us-gov-west-1, us-gov-east-1)"
    )
    return parser.parse_args()


args = parse_args()
region = args.region

# Determine account ID for output filename
sts_client = boto3.client('sts', region_name=region)
try:
    account_id = sts_client.get_caller_identity()['Account']
except Exception as e:
    print(f"ERROR: Could not determine AWS account ID: {e}", file=sys.stderr)
    sys.exit(1)

OUTPUT_FILE = f"{account_id}-{region}-inet-paths.txt"

# Redirect all print output to both screen and file
class TeeOutput:
    """Write to both stdout and a file simultaneously."""
    def __init__(self, filepath):
        self.file = open(filepath, 'w', encoding='utf-8')
        self.stdout = sys.stdout
    def write(self, data):
        self.stdout.write(data)
        self.file.write(data)
    def flush(self):
        self.stdout.flush()
        self.file.flush()
    def close(self):
        self.file.close()

tee = TeeOutput(OUTPUT_FILE)
sys.stdout = tee

print(f"==============================")
print(f"Scanning {region}")
print(f"Account: {account_id}")
print(f"Output:  {OUTPUT_FILE}")
print(f"==============================")

# Initialize clients with the specified region
ec2_client = boto3.client('ec2', region_name=region)
elbv2_client = boto3.client('elbv2', region_name=region)
rds_client = boto3.client('rds', region_name=region)

def get_load_balancer_info():
    lb_info = []
    load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']
    for lb in load_balancers:
        lb_name = lb['LoadBalancerName']
        lb_arn = lb['LoadBalancerArn']
        lb_targets = elbv2_client.describe_target_groups(LoadBalancerArn=lb_arn)['TargetGroups']
        target_info = [{'TargetGroupArn': tg['TargetGroupArn'], 'Name': tg['TargetGroupName']} for tg in lb_targets]
        lb_info.append({'LoadBalancerName': lb_name, 'TargetGroups': target_info})
    return lb_info

def get_ec2_instances():
    instances = []
    ec2_instances = ec2_client.describe_instances()['Reservations']
    for reservation in ec2_instances:
        for instance in reservation['Instances']:
            # Skip instances without a subnet (terminated, pending, or classic)
            if 'SubnetId' not in instance:
                continue
            instance_id = instance['InstanceId']
            instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'No Name')
            security_groups = instance.get('SecurityGroups', [])
            subnet_id = instance['SubnetId']
            instances.append({'InstanceId': instance_id, 'InstanceName': instance_name, 'SecurityGroups': security_groups, 'SubnetId': subnet_id})
    return instances

def get_rds_instances():
    rds_instances = []
    db_instances = rds_client.describe_db_instances()['DBInstances']
    for db in db_instances:
        db_id = db['DBInstanceIdentifier']
        endpoint = db['Endpoint']['Address']
        security_groups = db['VpcSecurityGroups']
        rds_instances.append({'DBInstanceIdentifier': db_id, 'Endpoint': endpoint, 'SecurityGroups': security_groups})
    return rds_instances

def get_security_group_permissions(security_group_ids):
    allowed_traffic = {
        'SSH': [],  # List of sources allowed to access SSH (port 22)
        'RDP': [],  # List of sources allowed to access RDP (port 3389)
        'SSH_Global': False,  # Global access for SSH (via 0.0.0.0/0)
        'RDP_Global': False,  # Global access for RDP (via 0.0.0.0/0)
        'InternetAccess': False  # Any rule with 0.0.0.0/0, regardless of port
    }
    
    security_groups = ec2_client.describe_security_groups(GroupIds=security_group_ids)['SecurityGroups']
    
    for sg in security_groups:
        for rule in sg['IpPermissions']:
            to_port = rule.get('ToPort')
            ip_ranges = rule.get('IpRanges', [])
            if not ip_ranges:
                continue
            
            # Iterate through all IP ranges in the rule
            for ip_range in ip_ranges:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip:
                    # SSH (port 22) logic
                    if to_port == 22:
                        allowed_traffic['SSH'].append(cidr_ip)
                        if cidr_ip == '0.0.0.0/0':
                            allowed_traffic['SSH_Global'] = True
                            allowed_traffic['InternetAccess'] = True
                    
                    # RDP (port 3389) logic
                    elif to_port == 3389:
                        allowed_traffic['RDP'].append(cidr_ip)
                        if cidr_ip == '0.0.0.0/0':
                            allowed_traffic['RDP_Global'] = True
                            allowed_traffic['InternetAccess'] = True
                    
                    # Any rule with 0.0.0.0/0 for global access
                    if cidr_ip == '0.0.0.0/0':
                        allowed_traffic['InternetAccess'] = True
                        
    return allowed_traffic

def get_instances_in_target_group(target_group_arn):
    target_instances = []
    targets = elbv2_client.describe_target_health(TargetGroupArn=target_group_arn)['TargetHealthDescriptions']
    for target in targets:
        instance_id = target['Target']['Id']
        target_instances.append(instance_id)
    return target_instances

def is_subnet_routable_to_internet(subnet_id):
    # Check if the subnet has a route to an Internet Gateway (IGW)
    route_tables = ec2_client.describe_route_tables(
        Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
    )['RouteTables']
    
    for route_table in route_tables:
        for route in route_table['Routes']:
            if route.get('GatewayId', '').startswith('igw-'):
                return True
    return False

def get_rds_allowed_sources(rds_security_group_ids, ec2_instances):
    # Check what EC2 instances or IP ranges can connect to the RDS instance by checking the inbound rules
    allowed_sources = []
    security_groups = ec2_client.describe_security_groups(GroupIds=rds_security_group_ids)['SecurityGroups']
    for sg in security_groups:
        for rule in sg['IpPermissions']:
            # Check for EC2 instances in the same security group
            for sg_pair in rule.get('UserIdGroupPairs', []):
                for ec2 in ec2_instances:
                    for ec2_sg in ec2['SecurityGroups']:
                        if ec2_sg['GroupId'] == sg_pair['GroupId']:
                            allowed_sources.append({'Type': 'EC2', 'InstanceName': ec2['InstanceName'], 'InstanceId': ec2['InstanceId']})
            # Check if the rule allows traffic from the Internet
            for ip_range in rule.get('IpRanges', []):
                if ip_range['CidrIp'] == '0.0.0.0/0':
                    allowed_sources.append({'Type': 'Internet', 'Cidr': ip_range['CidrIp']})
    return allowed_sources

def trace_ec2_direct_internet_traffic(ec2_info, rds_info):
    """Map EC2 instances that accept traffic directly from the Internet."""
    print("\nDirect Internet to EC2 Instances:")
    for ec2_instance in ec2_info:
        sg_ids = [sg['GroupId'] for sg in ec2_instance['SecurityGroups']]
        traffic_permissions = get_security_group_permissions(sg_ids)

        # Check if the EC2 instance has Internet access directly
        if traffic_permissions['InternetAccess']:
            internet_routable = is_subnet_routable_to_internet(ec2_instance['SubnetId'])
            if internet_routable:
                print(f"EC2 Instance: {ec2_instance['InstanceName']} ({ec2_instance['InstanceId']}) accepts traffic directly from the Internet.")
                print(f"  SSH Allowed: {traffic_permissions['SSH']}")
                print(f"  RDP Allowed: {traffic_permissions['RDP']}")
                print(f"  Subnet is routable to the Internet (via IGW).")

                # Check if the EC2 instance connects to any RDS instance
                rds_connections = [rds for rds in rds_info if ec2_instance['InstanceId'] in 
                                [src['InstanceId'] for src in get_rds_allowed_sources([sg['VpcSecurityGroupId'] for sg in rds['SecurityGroups']], ec2_info)]]
                if rds_connections:
                    for rds in rds_connections:
                        print(f"  Connects to RDS Instance: {rds['DBInstanceIdentifier']} ({rds['Endpoint']})")
                else:
                    print(f"  No RDS connections from EC2 Instance: {ec2_instance['InstanceName']}.")
            else:
                print(f"EC2 Instance: {ec2_instance['InstanceName']} is NOT in a subnet routable to the Internet.")
        else:
            print(f"EC2 Instance: {ec2_instance['InstanceName']} does not accept traffic directly from the Internet.")

def trace_full_flow(lb_info, ec2_info, rds_info):
    # Internet -> Load Balancer -> EC2 -> RDS flow
    for lb in lb_info:
        print(f"Load Balancer: {lb['LoadBalancerName']}")
        for tg in lb['TargetGroups']:
            print(f"  Target Group: {tg['Name']}")
            target_instances = get_instances_in_target_group(tg['TargetGroupArn'])
            if target_instances:
                print("    Instances mapped to the Target Group:")
                for instance_id in target_instances:
                    ec2_instance = next((ec2 for ec2 in ec2_info if ec2['InstanceId'] == instance_id), None)
                    if ec2_instance:
                        print(f"      EC2 Instance: {ec2_instance['InstanceName']} ({ec2_instance['InstanceId']})")
                        sg_ids = [sg['GroupId'] for sg in ec2_instance['SecurityGroups']]
                        traffic_permissions = get_security_group_permissions(sg_ids)
                        print(f"        SSH Allowed: {traffic_permissions['SSH']}")
                        print(f"        RDP Allowed: {traffic_permissions['RDP']}")
                        print(f"        Global Access via Security Group: {traffic_permissions['InternetAccess']}")
                        
                        internet_routable = is_subnet_routable_to_internet(ec2_instance['SubnetId'])
                        if internet_routable:
                            print("        Instance is in a subnet with a route to the Internet (via IGW).")
                        else:
                            print("        Instance is in a subnet without a direct route to the Internet.")
                        
                        # Check if the EC2 instance connects to an RDS instance
                        rds_connections = [
                            rds for rds in rds_info if ec2_instance['InstanceId'] in [
                                src['InstanceId'] for src in get_rds_allowed_sources(
                                    [sg['VpcSecurityGroupId'] for sg in rds['SecurityGroups']], ec2_info) 
                                if 'InstanceId' in src
                            ]
                        ]
                        if rds_connections:
                            for rds in rds_connections:
                                print(f"        Connects to RDS Instance: {rds['DBInstanceIdentifier']} ({rds['Endpoint']})")
                        else:
                            print("        No RDS connections from this EC2 instance.")
            else:
                print("    No instances are currently mapped to this Target Group.")
    
    print("\nRDS Instances:")
    for rds in rds_info:
        print(f"  RDS Instance: {rds['DBInstanceIdentifier']} ({rds['Endpoint']})")
        sg_ids = [sg['VpcSecurityGroupId'] for sg in rds['SecurityGroups']]
        traffic_permissions = get_security_group_permissions(sg_ids)
        print(f"    SSH Allowed: {traffic_permissions['SSH']}")
        print(f"    RDP Allowed: {traffic_permissions['RDP']}")
        print(f"    Global Access via Security Group: {traffic_permissions['InternetAccess']}")
        
        # Check allowed sources for RDS
        allowed_sources = get_rds_allowed_sources(sg_ids, ec2_info)
        if allowed_sources:
            print("    Allowed sources:")
            for source in allowed_sources:
                if source['Type'] == 'EC2':
                    print(f"      EC2 Instance: {source['InstanceName']} ({source['InstanceId']})")
                elif source['Type'] == 'Internet':
                    print(f"      Internet: Allowed from {source['Cidr']}")
        else:
            print("    No resources are allowed to connect to this RDS instance.")

def main():
    lb_info = get_load_balancer_info()
    ec2_info = get_ec2_instances()
    rds_info = get_rds_instances()
    
    # Full traffic flow mapping
    trace_full_flow(lb_info, ec2_info, rds_info)
    
    # Direct Internet traffic to EC2
    trace_ec2_direct_internet_traffic(ec2_info, rds_info)

    # Close output file
    print(f"\n{'='*30}")
    print(f"Results written to: {OUTPUT_FILE}")
    sys.stdout = tee.stdout
    tee.close()
    print(f"Results written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
