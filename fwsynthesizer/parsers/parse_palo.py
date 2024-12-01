#!/usr/bin/env python2

from ipaddr import IPv4Address, IPv4Network, NetmaskValueError ,AddressValueError
from fwsynthesizer.parsers.helper_parse_panos import XMLParser

################################################################################
# CONFIG PARSING

# def strip_comments(contents):
#     return re.sub("\!.*\n", "!\n", contents)

def parse_file(contents):

    parser = XMLParser(contents, "panos")
    # scope_param, config_type, device_group_name = parser.parse_config_and_set_scope(contents)
    parser.config_type = 'local'
    
    run_objects_list = []  # Initialize as empty list
    parsed_data = parser.parse_all()

    service_including_buidin_ones= parsed_data["Service"]
    service_including_buidin_ones.append({
        "name": "service-http",
        "protocol":{
            "tcp":{"port": "80,8080"}
        }
    })
    service_including_buidin_ones.append({
        "name": "service-https",
        "protocol":{
            "tcp":{"port": "443"}
        }
    })



    return parsed_data["Interfaces"], [parsed_data["security_pre_rules"],parsed_data["security_post_rules"]], \
        [parsed_data["nat_pre_rules"],parsed_data["nat_post_rules"]], parsed_data["Routes"],parsed_data["Address"] , service_including_buidin_ones

def get_ip_for_ip_or_address_object(ip,addresses):
    try:
        interface_ip=IPv4Network(ip,strict=False)
    except (NetmaskValueError, AddressValueError):
        #get from Address objekts if its not an i
        interface_ip = IPv4Network([entry['ip_netmask'] for entry in addresses if entry['name'] == ip][0],strict=False)
    return interface_ip


def convert_file(interfaces, rules, nats, routes, addresses, services):
    output = ""
    # todo service_groups
    service_dict={s["name"]:s["protocol"] for s in services}

    default_route = [r for r in routes if IPv4Network(r["destination"]).with_prefixlen == '0.0.0.0/0'][0] # Only the first one
    dr_ip = get_ip_for_ip_or_address_object(default_route["nexthop"],addresses)

    # Get default route
    for interface in interfaces:
        for i,ip in enumerate(interface["ips"]["layer3"]["ips"]):
            interface_ip = get_ip_for_ip_or_address_object(ip,addresses)
            
            interface["ips"]["layer3"]["ips"][i] = interface_ip.with_prefixlen
            if dr_ip in interface_ip:
                # print(interface_ip.ip)
                interface["ips"]["layer3"]["ips"][i] = IPv4Network(format(interface_ip.ip)+"/0").with_prefixlen

    interfaces = sorted(interfaces,key=lambda x:  IPv4Network(x['ips']['layer3']['ips'][0]).numhosts)

    def handle_rules(ruleset,output):
        action_translation ={
            "allow": "ACCEPT",
            "deny": "DROP",
            "drop": "DROP",
        }
        conds =[]
        for rule in ruleset:
            if rule["disabled"] ==True:
                continue
            l_cond =[]
            ### source
            s_cond = []
            skip_current_condition = False  
            try:
                if rule["source"][0] == "any":
                    skip_current_condition=True
            except:
                pass
            if not skip_current_condition:
                for source in rule["source"]:
                    s_cond.append(get_ip_for_ip_or_address_object(source,addresses).with_prefixlen)

                l_cond.append(' || '.join('(srcIp == {})'.format(s) for s in s_cond))

            ### destination
            d_cond = []
            skip_current_condition = False  
            try:
                if rule["destination"][0] == "any":
                    skip_current_condition=True
            except:
                pass
            if not skip_current_condition:
                for destination in rule["destination"]:
                    d_cond.append(get_ip_for_ip_or_address_object(destination,addresses).with_prefixlen)

                l_cond.append(' || '.join('(dstIp == {})'.format(s) for s in d_cond))

            ### services
            p_cond = []
            skip_current_condition = False  
            try:
                if rule["service"][0] == "any":
                    skip_current_condition=True
            except:
                pass
            if not skip_current_condition:
                for service in rule["service"]:
                    proto = service_dict[service].keys()[0]
                    port = service_dict[service][proto]["port"]
                    p_cond.append((proto,port))
                l_cond.append(' || '.join('(protocol == {} && port == {})'.format(*p) for p in p_cond))
        
            ###action
            action = action_translation[rule["action"]]
            conds.append('({}, {})'.format(' && '.join(l_cond),action))


        output += ' \n '.join(conds)

        return output

    output += "CHAIN InF DROP:\n"
    pre_rules, post_rules =rules
    output= handle_rules(pre_rules,output)
    output= handle_rules(post_rules,output)
    


    # TODO State 
    # TODO NAT


    return output

################################################################################
# TESTS


if __name__ == '__main__':
    import fwsynthesizer
    converter = fwsynthesizer.converter(
        parser=parse_file,
        converter=lambda x,_: convert_file(*x)
    )

    contents = open('../../examples/cisco/cisco_ok.txt').read()

    print(converter(contents=contents, interfaces=None))

    p = parse_file(contents)
    print(p)
