import fwsynthesizer
from fwsynthesizer.parsers import parse_palo

frontend = fwsynthesizer.Frontend(
    name="PALO",
    diagram="diagrams/palo.diagram",
    language_converter=fwsynthesizer.converter(
        parser=parse_palo.parse_file,
        converter=lambda x,_: parse_palo.convert_file(*x)
    ),
    interfaces_enabled=False
)

# https://knowledgebase.paloaltonetworks.com/servlet/rtaImage?eid=ka14u000000obin&feoid=00N0g000003VPSv&refid=0EM0g000001AeP6

# https://i0.wp.com/sanchitgurukul.com/wp-content/uploads/2019/03/packetprocessing-pan-front.png?resize=640%2C432&ssl=1

# https://sanchitgurukul.com/palo-alto-firewall-packet-flow/