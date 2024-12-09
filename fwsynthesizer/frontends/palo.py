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