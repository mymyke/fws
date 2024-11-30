#!/usr/bin/env python2

import re
from collections import defaultdict
# import xml.etree.ElementTree as ET

from fwsynthesizer.parsers.helper_parse_panos import XMLParser

################################################################################
# CONFIG PARSING

# def strip_comments(contents):
#     return re.sub("\!.*\n", "!\n", contents)

def parse_file(contents):
    acls = defaultdict(list)
    acl_conds = defaultdict(list)
    interfaces = {}
    nats = []
    routes = []

    parser = XMLParser(contents, "panos")
    # scope_param, config_type, device_group_name = parser.parse_config_and_set_scope(contents)
    parser.config_type = 'local'
    
    run_objects_list = []  # Initialize as empty list
    parsed_data = parser.parse_all()


    return parsed_data["Interfaces"], [parsed_data["security_pre_rules"],parsed_data["security_post_rules"]], \
        [parsed_data["nat_pre_rules"],parsed_data["nat_post_rules"]], parsed_data["Routes"]

def convert_file(interfaces, rules, nats, routes):

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
