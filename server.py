import bottle, sqlite3

@bottle.route('/')
def get_index() -> str:
    return bottle.static_file('index.html', '.')


@bottle.get('/api/list/instances')
def get_instances() -> list:
    '''Called by AJAX request to list instances ids and private ips'''
    instances = []
    con = sqlite3.connect('./ecsegscan.sqlite')
    results = con.execute('select instance_id from instances;') # distinct not necessary because id is primary key
    for row in results:
        instances.append(row[0])

    con.close()
    return bottle.json_dumps(instances)


@bottle.get('/api/list/instances/subnet/<subnet>')
def get_instances_in_subnet(subnet: str) -> list:
    '''List EC2s within a given subnet'''
    ec2s = []
    con = sqlite3.connect('./ecsegscan.sqlite')
    results = con.execute(f'select instance_id from instances where subnet_id like "%{subnet}%"') # Trying like to do fuzzy searches
    for row in results:
        ec2s.append(row[0])
    
    con.close()
    return bottle.json_dumps(ec2s)


@bottle.get('/api/list/instances/securitygroup/<sg_id>')
def get_instances_in_sg(sg_id: str) -> list:
    '''List EC2s within a given security group'''
    ec2s = []
    con = sqlite3.connect('./ecsegscan.sqlite')
    results = con.execute(f'select instance_id from instances where sg_id = "{sg_id}"') # Trying like to do fuzzy searches
    for row in results:
        ec2s.append(row[0])
    
    con.close()
    print('halp')
    return bottle.json_dumps(ec2s)


@bottle.get('/api/list/subnets')
def get_subnets() -> list:
    '''List any subnet ids within database'''
    subnets = []
    con = sqlite3.connect('./ecsegscan.sqlite')
    results = con.execute('select distinct subnet_id from networkacls;')
    for row in results:
        subnets.append(row[0])

    con.close()
    return bottle.json_dumps(subnets)


@bottle.get('/api/list/securitygroups')
def get_security_groups() -> list:
    '''List any security groups within the databse'''
    sgs = []
    con = sqlite3.connect('./ecsegscan.sqlite')
    results = con.execute('select distinct sg_id from securitygroups;')
    for row in results:
        sgs.append(row[0])
    con.close()
    return bottle.json_dumps(sgs)


@bottle.get('/api/search/nacl/<nacl_id>')
def search_nacl(nacl_id: str) -> dict:
    '''Retrieves firewall rules for a provided network acl'''
    nacl_entries = {'Ingress' : [], 'Egress': []} # will contain ingress/egress
    con = sqlite3.connect('./ecsegscan.sqlite')
    results = con.execute(f'select rule_id, action, src, dst, port_range, proto from networkacls where subnet_id = "{nacl_id}";')
    for row in results:
        action = 'Allow' if (row[1] == 1) else 'Deny'
        rule_id, src, dst, port_range, proto = row[0], row[2], row[3], row[4], row[5]
        is_egress = (nacl_id == src)
        entry = {
                'RuleId': rule_id,
                'Action': action,
                'Src': src,
                'Dst': dst,
                'Port': f'{port_range}/{proto}'            
        }
        if is_egress:
            nacl_entries['Egress'].append(entry)
        else:
            nacl_entries['Ingress'].append(entry)
    con.close()

    return bottle.json_dumps(nacl_entries)


@bottle.get('/api/search/securitygroup/<sg_id>')
def search_security_group(sg_id: str) -> dict:
    '''Retrieves firewall rules for a provided security group Id'''
    sg_entries = {'Ingress': [], 'Egress': []} # similar to nacl searches but no rule_id
    con = sqlite3.connect('./ecsegscan.sqlite')
    results = con.execute(f'select src, dst, port_range, proto from securitygroups where sg_id = "{sg_id}";')
    for row in results:
        src, dst, port_range, proto = row[0], row[1], row[2], row[3]
        is_egress = (sg_id == src)
        entry = {
            'Action': 'Allow', # SGs are allow-only deny-by-default
            'Src': src,
            'Dst': dst,
            'Port': f'{port_range}/{proto}'
        }
        if is_egress:
            sg_entries['Egress'].append(entry)
        else:
            sg_entries['Ingress'].append(entry)

    # Add the deny by defaults
    deny_by_default = {
        'Action': 'Deny',
        'Src': 'Any',
        'Dst': 'Any',
        'Port': 'Any/Any'
    }
    sg_entries['Egress'].append(deny_by_default)
    sg_entries['Ingress'].append(deny_by_default)

    return bottle.json_dumps(sg_entries)


@bottle.get('/api/search/instance/id/<ec2_id>')
def search_instance_by_id(ec2_id: str) -> dict:
    '''Retrieves instance configs for a supplied id'''
    con = sqlite3.connect('./ecsegscan.sqlite')
    results = con.execute(f'select * from instances where instance_id = "{ec2_id}";')
    ec2_config = {}
    for row in results:
        ec2_config['InstanceId'] = row[0]
        ec2_config['SubnetId'] = row[1]
        ec2_config['SecurityGroup'] = row[2]
        ec2_config['PrivateIp'] = row[3]
        ec2_config['PublicDNS'] = row[4]
        ec2_config['State'] = row[5]
        ec2_config['IAMRole'] = row[6]
    con.close()
    return bottle.json_dumps(ec2_config)


@bottle.get('/api/search/instance/ip/<ip_addr>')
def search_instance_by_ip(ip_addr: str):
    '''Returns ec2 configs for a supplied IP address'''
    con = sqlite3.connect('./ecsegscan.sqlite')
    results = con.execute(f'select * from instances where private_ip = "{ip_addr}";')
    ec2_config = {}
    for row in results:
        ec2_config['InstanceId'] = row[0]
        ec2_config['SubnetId'] = row[1]
        ec2_config['SecurityGroup'] = row[2]
        ec2_config['PrivateIp'] = row[3]
        ec2_config['PublicDNS'] = row[4]
        ec2_config['State'] = row[5]
        ec2_config['IAMRole'] = row[6]
    con.close()
    return bottle.json_dumps(ec2_config)


@bottle.get('/api/count/instances/nacl/<nacl_id>')
def count_instances_by_nacl(nacl_id: str) -> dict:
    '''Returns number of EC2s in a subnet'''
    con = sqlite3.connect('./ecsegscan.sqlite')
    results = con.execute(f'select count(instance_id) from instances where subnet_id = "{nacl_id}";')
    val = results[0][0]
    con.close()
    return {'SubnetId': nacl_id, 'EC2Count': val}

bottle.run(host='127.0.0.1', port=8000)