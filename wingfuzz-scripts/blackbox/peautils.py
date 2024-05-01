import os
from pqml2pit import *
from utils import *

def peachGreyCaseSend(bin, raw_case):
    # Create a spk file
    with open('tmp.xml', 'a') as newfile:
        newfile.truncate(0)
        create_xml_header(newfile)
        newfile.write("\n\t<DataModel name=\"" + PROTOCOL + "\">\n")
        newfile.write("\t\t<Blob valueType=\"hex\" value=\"" + str(raw_case) + "\"\n")
        newfile.write("</DataModel>\n")
        create_xml_state(newfile)
        create_xml_agent(newfile)
        create_xml_test(newfile)
        file.write("\n</Peach>")

        os.system(f"{bin} {newfile} >peach_log 2>&1")


def read_peach_indir(in_dir):
    in_file = find_files(in_dir, '.raw')
    msg_list = []
    for file in in_file:
        with open(file, 'rb') as f:
            content = f.read1()
            msg_list.append(content)
    return msg_list
