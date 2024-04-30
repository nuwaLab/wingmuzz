from lxml import etree
import sys
import struct
import binascii

def get_field_name(f):
    if f.get("name") is not None:
        return f.get("name").replace(".","_")
    else:
        return "???"

def get_block_name(f):
    if f.get("show") is not None:
        return f.get("show")
    else:
        return "???"

# Here we try to identify the type of the field. If we fail we just fall back to Blob
def transform_field(f,root,depth):
    node = None
    #print field
    if len(f.get('name'))==0:
        node=etree.Element('Block')
        node.set("name", get_block_name(f))
        return node

    try:
        if int(f.get("value"),16)==int(f.get("show")):
            node=etree.Element('Number')
            node.set("size", len(f.get("value"))*4)
            node.set("value", f.get("show"))
            node.set("endian", "big")
            node.set("name", get_field_name(f))
            return node
    except:
        pass

    try:
        parsed=False
        endian="little"
        show=0
        if f.get("show").startswith("0x"):
            show=int(f.get("show"),16)
        else:
            show=int(f.get("show"))
        if len(f.get("value"))==2 and show==int(f.get("value"),16):
            parsed=True
        if len(f.get("value"))==8 and (struct.unpack(">I",binascii.unhexlify(f.get("value")))[0]==show or struct.unpack(">i",binascii.unhexlify(f.get("value")))[0]==show):
            parsed=True
            endian="little"
        if len(f.get("value"))==4 and (struct.unpack(">H",binascii.unhexlify(f.get("value")))[0]==show or struct.unpack(">h",binascii.unhexlify(f.get("value")))[0]==show):
            parsed=True
            endian="little"
        if len(f.get("value"))==8 and (struct.unpack("<I",binascii.unhexlify(f.get("value")))[0]==show or struct.unpack("<i",binascii.unhexlify(f.get("value")))[0]==show):
            parsed=True
            endian="big"
        if len(f.get("value"))==4 and (struct.unpack("<H",binascii.unhexlify(f.get("value")))[0]==show or struct.unpack("<h",binascii.unhexlify(f.get("value")))[0]==show):
            parsed=True
            endian="big"
        if len(f.get("value"))==2 and (struct.unpack("<B",binascii.unhexlify(f.get("value")))[0]==show or struct.unpack("<b",binascii.unhexlify(f.get("value")))[0]==show):
            parsed=True
            endian="little"
        if parsed:
            node=etree.Element('Number')
            node.set("size", str(len(f.get("value"))*4))
            node.set("value", f.get("value"))
            node.set("valueType", "hex")
            node.set("endian", endian)
            node.set("name", get_field_name(f))
            return node
    except Exception as e:
        print(e)
        pass

    try:
        if binascii.unhexlify(f.get("value")).decode('utf-8')==f.get("show"):
            node=etree.Element("String")
            node.set("length", f.get("size"))
            node.set("value", f.get("show"))
            node.set("name", get_field_name(f))
            return node
    except:
        pass
    node=etree.Element('Blob')
    node.set("valueType", "hex")
    if f.get("value") is not None:
        node.set("value", f.get("value"))
        node.set("size", str(len(f.get("value"))*4))
    node.set("name", get_field_name(f))
    return node


def parse_field(field,root,depth=0):
    # print "-"*depth, field.get("name")
    node=None
    if field.tag=="field":
        node=transform_field(field, root, depth)
        root.append(node)
    else:
        node=root
    for f in field.getchildren():
        parse_field(f, node, depth+1)


if __name__ == '__main__':
    
    PIT_FILE = "dns.xml"
    # read xxx.pdml file location from cmd 
    tree=etree.parse(open(sys.argv[1], 'rb'))
    # name should be protocol's name
    field=tree.xpath('/pdml/packet/proto[@name=\'dns\']')[0]

    root=etree.Element('DataModel')
    parse_field(field,root)
    
    with open(PIT_FILE, "w") as file:
        file.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
        file.write("<Peach xmlns=\"http://peachfuzzer.com/2012/Peach\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://peachfuzzer.com/2012/Peach ../peach.xsd\">\n")
        file.write(etree.tostring(root,pretty_print=True).decode('utf-8'))
        file.write("\n\t<Test name=\"Default\">\n")
        file.write("\t\t<Publisher class=\"ConsoleHex\"/>\n")
        file.write("\t</Test>\n")
        file.write("</Peach>")
