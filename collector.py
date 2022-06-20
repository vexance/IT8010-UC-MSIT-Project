import argparse, boto3, getpass, sqlite3, termcolor, uuid


def print_error(msg: str) -> None:
    '''Prints red error message: [x] {msg}'''
    print(termcolor.colored('[x] ', 'red'), f'{msg}')
    return None


def print_warning(msg: str) -> None:
    '''Prints orange warning message: [!] {msg}'''
    print(termcolor.colored('[!] ', 'yellow'), f'{msg}')
    return None


def print_success(msg: str) -> None:
    '''Prints green success message: [+] {msg}'''
    print(termcolor.colored('[+] ', 'green'), f'{msg}')
    return None


def get_ec2_instances(session: boto3.Session) -> dict:
    '''Queries AWS APIs for EC2 Instance config info'''
    client = session.client('ec2')
    instances = []
    try:
        res = client.describe_instances()
        instances = res.get('Reservations', [{}])[0].get('Instances', [])
    except Exception as err:
        print_error(f'Unable to call Describe Instances: {err}')
        exit()

    print_success('Successfully called \'Describe Instances\'')

    instance_info = {
        'Instances': {},
        'SGs': [], # passed to get_sg_rules()
        'Subnets': [] # passed to get_nacl_rules()
    }

    for ec2 in instances:
        instance_id = ec2.get('InstanceId', None)
        subnet = ec2.get('SubnetId', None)
        security_group = ec2.get('NetworkInterfaces', [{}])[0].get('Groups', [{}])[0].get('GroupId', None)
        
        # IP Address Info
        private_ip = ec2.get('PrivateIpAddress', 'N/A')
        private_ip = private_ip if (private_ip != '') else 'N/A'
        pub_dns_name = ec2.get('PublicDnsName', 'N/A')
        pub_dns_name = pub_dns_name if (pub_dns_name != '') else 'N/A'

        # EC2 Instance State (e.g., running, stopping, stopped, etc)
        ec2_state = ec2.get('State', {}).get('Name', 'Unknown').capitalize()

        # Associated IAM role - if present may be able to break seg based off permissions
        profile_arn = ec2.get('IamInstanceProfile', {}).get('Arn', 'None/None')
        profile_name = profile_arn.split('/')[1] # format is arn:aws::iam:ACCCOUNT_ID:instance-profile/<ProfileName>

        instance_info['Instances'][instance_id] = {
            'Id': instance_id,
            'PrivateIp': private_ip,
            'PublicDNSName': pub_dns_name,
            'InstanceState': ec2_state,
            'Subnet': subnet,
            'SecurityGroup': security_group,
            'AssociatedRole': profile_name
        }
        instance_info['SGs'].append(security_group)
        instance_info['Subnets'].append(subnet)

    return instance_info


def get_sg_rules(session: boto3.Session, groups: list) -> dict:
    '''Retrieves rule sets for specified security groups'''
    client = session.client('ec2')
    sg_rulesets = {}
    try:
        res = client.describe_security_groups(GroupIds=groups)
        sec_groups = res.get('SecurityGroups', [])
    except Exception as err:
        print_error(f'Unable to call Describe Security Group Rules: {err}')

    print_success('Successfully called \'Describe Security Groups\'')

    for group in sec_groups:
        group_id = group.get('GroupId')
        sg_rulesets[group_id] = []
        
        # Ingress Rules: ACCEPT FROM ? TO GroupId PORT ?/?
        for entry in group.get('IpPermissions', []):
            cidr_ranges = []
            
            # Allowed Sources in IPv4
            for ipentry in entry.get('IpRanges', []):
                cidr = ipentry.get('CidrIp', '')
                cidr_ranges.append(cidr)
            # Allowed Sources in IPv6
            for ipentry in entry.get('Ipv6Ranges', []):
                cidr = ipentry.get('CidrIp', '')
                cidr_ranges.append(cidr)

            src_ips = ', '.join(cidr_ranges)

            dst_port_end = entry.get('ToPort', 'Any')
            dst_port_start = entry.get('FromPort', 'Any')
            
            dst_port = ''
            if dst_port_start == dst_port_end:
                dst_port = dst_port_start
            else: # Range of Ports
                dst_port = f'{dst_port_start}-{dst_port_end}'

            proto = entry.get('IpProtocol', '-1')

            proto = proto if (proto != '-1') else 'Any'

            sg_rulesets[group_id].append({
                'Action': 'Allow', # Security Groups are allow-only deny-by-default
                'From': src_ips,
                'To': group_id,
                'Port': f'{dst_port}/{proto}'
            })

        # Egress Rules ACCEPT FROM GroupId TO ? PORT ?/?
        for entry in group.get('IpPermissionsEgress', []): 
            cidr_ranges = []

            # Allowed destinations in IPv4
            for ipentry in entry.get('IpRanges', []):
                cidr = ipentry.get('CidrIp', '')
                cidr_ranges.append(cidr)
            # Allowed destinations in IPv6
            for ipentry in entry.get('Ipv6Ranges', []):
                cidr = ipentry.get('CidrIp', '')
                cidr_ranges.append(cidr)
            
            dst_ips = ', '.join(cidr_ranges)
            
            dst_port = entry.get('ToPort', 'Any')
            proto = entry.get('IpProtocol', '-1')

            proto = proto if (proto != '-1') else 'Any'
            dst_port = dst_port if (proto != '-1') else 'Any'

            sg_rulesets[group_id].append({
                'Action': 'Allow',
                'From': group_id,
                'To': dst_ips,
                'Port': f'{dst_port}/{proto}'
            })

    return sg_rulesets


def get_nacl_rules(session: boto3.Session, subnets: list) -> dict:
    '''Gets Network ACL ruleset configurations'''
    client = boto3.client('ec2')
    nacl_rulesets = {}

    try:
        res = client.describe_network_acls(Filters=[{
            'Name': 'association.subnet-id',
            'Values': subnets
        }])
        nacl_configs = res.get('NetworkAcls', [])
    except Exception as err:
        print_error(f'Unable to call Describe Network ACLs: {err}')
        exit()

    print_success('Successfully called \'Describe Network ACLs\'')

    for nacl in nacl_configs:
        nacl_id = nacl.get('Associations', [{}])[0].get('NetworkAclId', None)
 
        # Associations are one-to-many nacls-to-subnets
        # I.e., each subnet has ONE associated NACL, but one NACL may effect multiple subnets
        associations = []
        for entry in nacl.get('Associations', []):
            subnet_id = entry.get('SubnetId', '')
            nacl_rulesets[subnet_id] = [] # initialize
            associations.append(subnet_id)

        for entry in nacl.get('Entries', []):
            # Rules are evaluated from low => high
            rule_id = entry.get('RuleNumber', -1)

            # Network ACLs can explicitly allow or deny
            action = entry.get('RuleAction', 'Deny').capitalize()
            
            # Determine traffic direction
            is_egress = entry.get('Egress', False)

            # Determine port range
            dst_port_start = entry.get('PortRange', {}).get('From', 'Any')
            dst_port_end = entry.get('PortRange', {}).get('To', dst_port_start)

            dst_port = ''
            if dst_port_start == dst_port_end:
                dst_port = dst_port_start
            else: # Range of Ports
                dst_port = f'{dst_port_start}-{dst_port_end}'

            # Determine protocol
            proto = entry.get('Protocol', '-1')
            if proto == '6':
                proto = 'tcp'
            elif proto == '-1':
                proto = 'Any'
            else: # UDP remains...
                proto = 'udp'

            # Determine IPv4/IPv6 CIDR 
            cidr = entry.get('CidrBlock', None)
            if not cidr:
                cidr = entry.get('Ipv6CidrBlack')

            # Now to append to each associated Subnet's rules
            for subnet_id in associations:
                rule_src = subnet_id if (is_egress) else cidr
                rule_dst = cidr if (is_egress) else subnet_id

                nacl_rulesets[subnet_id].append({
                    'RuleId': rule_id,
                    'Action': action,
                    'From': rule_src,
                    'To': rule_dst,
                    'Port': f'{dst_port}/{proto}'
                })
            

    return nacl_rulesets


def create_db() -> None:
    con = sqlite3.connect('./ecsegscan.sqlite')
    con.execute('''
        create table instances(
            instance_id char(32) PRIMARY KEY NOT NULL,
            subnet_id char(32) NOT NULL,
            sg_id char(32) NOT NULL,
            private_ip char(16),
            pub_dns_name char(128),
            state char(16),
            role char(128)
        )
    ''')

    con.execute('''
        create table networkacls(
            entry_id char(36) PRIMARY KEY NOT NULL,
            subnet_id char(32) NOT NULL,
            rule_id int NOT NULL,
            action bool NOT NULL,
            src char(128) NOT NULL,
            dst char(128) NOT NULL,
            proto char(4) NOT NULL,
            port_range char(16) NOT NULL
        )
    ''')

    con.execute('''
        create table securitygroups(
            entry_id char(36) PRIMARY KEY NOT NULL,
            sg_id char(32) NOT NULL,
            src char(128) NOT NULL,
            dst char(128) NOT NULL,
            proto char(4) NOT NULL,
            port_range char(16) NOT NULL
        )
    ''')

    con.close()
    return None


def insert_into_db(table: str, vals: list) -> None:
    '''
        Enters values into a database table\n
        table: Instances; vals: instance_id, subnet_id, sg_id, private_ip, pub_dns_name, state, role\n
        table: NetworkACLs; vals: subnet_id, rule_id, action, src, dst, proto, port_range\n
        table: SecurityGroups; vals: sg_id, src, dst, proto, port_range
    '''
    
    if table not in ['Instances', 'NetworkACLs', 'SecurityGroups']:
        return None # Do nothing if incorrect table used

    query_base, query_args = '', ''    
    if table == 'Instances':
        query_base = 'insert into instances(instance_id, subnet_id, sg_id, private_ip, pub_dns_name, state, role) values'
        query_args = f'("{vals[0]}", "{vals[1]}", "{vals[2]}", "{vals[3]}", "{vals[4]}", "{vals[5]}", "{vals[6]}")'
    elif table == 'NetworkACLs':
        query_base = 'insert into networkacls(entry_id, subnet_id, rule_id, action, src, dst, proto, port_range) values'
        entry_id = str(uuid.uuid4())
        query_args = f'("{entry_id}", "{vals[0]}", {vals[1]}, {vals[2]}, "{vals[3]}", "{vals[4]}", "{vals[5]}", "{vals[6]}")'
    elif table == 'SecurityGroups':
        query_base = 'insert into securitygroups(entry_id, sg_id, src, dst, proto, port_range) values'
        entry_id = str(uuid.uuid4())
        query_args = f'("{entry_id}", "{vals[0]}", "{vals[1]}", "{vals[2]}", "{vals[3]}", "{vals[4]}")'
    
    query = f'{query_base} {query_args};'
    con = sqlite3.connect('./ecsegscan.sqlite')
    con.execute(query)
    con.commit()
    con.close()
    return None


def enter_config_data(configs: dict) -> None:
    '''Enters all EC2 Instance, Network ACL, and Security Group info into sqlite database'''

    # Start with Instances
    instances = configs.get('Instances', {}).keys() # list of ec2s
    for key in instances:
        ec2 = configs['Instances'][key] # 'ec2' obj (dict)
        instance_id = ec2['Id']
        priv_ip = ec2['PrivateIp']
        pub_dns = ec2['PublicDNSName']
        ec2_state = ec2['InstanceState']
        subnet = ec2['Subnet']
        sg = ec2['SecurityGroup']
        role = ec2['AssociatedRole']

        vals = [instance_id, subnet, sg, priv_ip, pub_dns, ec2_state, role]
        insert_into_db('Instances', vals)

    # Enter NetworkACL rules
    nacls = configs.get('NetworkACLs', {}).keys() # list of subnets
    for subnet in nacls:
        rules = configs['NetworkACLs'][subnet] # list of 'ruleset' objs (dicts)
        
        # Iterate over each rule entry
        for entry in rules:
            rule_id = entry['RuleId']
            action = entry['Action']
            action = True if (action == 'Allow') else False
            src = entry['From']
            dst = entry['To']
            port = entry['Port'].split('/')[0]
            proto = entry['Port'].split('/')[1]

            vals = [subnet, rule_id, action, src, dst, proto, port]
            insert_into_db('NetworkACLs', vals)
    
    # Enter Security Group rules
    sgs = configs.get('SecurityGroups', {}).keys() # list of SGs
    for sg in sgs:
        rules = configs['SecurityGroups'][sg] # List of rulsets just like in nacls loop

        for entry in rules:
            action = entry['Action']
            action = True if (action == 'Allow') else False
            src = entry['From']
            dst = entry['To']
            port = entry['Port'].split('/')[0]
            proto = entry['Port'].split('/')[1]

            vals = [sg, src, dst, proto, port]
            insert_into_db('SecurityGroups', vals)
    
    
    return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser('ECSegScan', 'python3 collector.py <args>')
    parser.add_argument('--access-key-id', required=False, default=None, type=str, help='AWS Access Key Id')
    parser.add_argument('--secret-key', required=False, default=None, type=str, help='AWS Secret Access Key')
    parser.add_argument('--session-token', required=False, default=None, type=str, help='AWS Role Session Token [optional]')
    parser.add_argument('--region', required=False, default='us-east-1', type=str, help='Primary AWS Region [default: us-east-1]')
    args = parser.parse_args()
    if not args.access_key_id:
        args.access_key_id = getpass.getpass('\tAccess Key Id: ')
    if not args.secret_key:
        args.secret_access_key = getpass.getpass('\tSecret Key: ')

    # Authenticate to the AWS APIs
    session = None
    try:
        if args.session_token: # Temporary role creds
            session = boto3.Session(args.access_key_id, args.secret_key, args.session_token, args.region)
        else: # Static key creds
            session = boto3.Session(args.access_key_id, args.secret_key, region_name = args.region)
    except Exception as err:
        print_error(f'Unable to establish AWS Session: {err}')
    
    config_data = {
        'Instances': {},
        'SecurityGroups': {},
        'NetworkACLs': {}
    }
   
    # Collect EC2 Instance Config Data
    instance_info = get_ec2_instances(session)
    config_data['Instances'] = instance_info['Instances']
    security_groups = instance_info['SGs']
    subnets = instance_info['Subnets']

    sg_rulesets = get_sg_rules(session, security_groups)
    config_data['SecurityGroups'] = sg_rulesets

    nacl_rulesets = get_nacl_rules(session, subnets)
    config_data['NetworkACLs'] = nacl_rulesets

    # Enter configs into database
    create_db()
    enter_config_data(config_data)

    exit()
