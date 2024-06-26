import sys
import socket
from utils import *

last_command = ""

def sendtoserver(request, target_ip, target_port, files_run):
    global last_command

    #create connection to target fuzz server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(4)

    #try connecting to client and recieving response
    try:
        client.connect((target_ip, target_port))
        response = client.recv(8192)

        #Check if certain string is in response, if its not print last command
        #this is to check if fuzz string changed the server response
        #if its the same, send the next fuzz string
        if "Welcome".encode('utf-8') in response:
            client.send(request)
        else:
            print("[INFO] Server response changed")
            print(f"[INFO] Last Command Fuzzed: {last_command}")
            print("\tFiles Run: ")
            print("\t" + ','.join(files_run))


    #If a timeout occurs while connecting (4 seconds), print error and show last command fuzzed
    #This could indicate the server crashed
    except socket.timeout:
        print("[ERROR] Connection to Server Timed Out")
        if last_command == "":
            print("[ERROR] Unable to connect to the target computer.")
            sys.exit(0)
        else:
            print("[INFO] Last Command Fuzzed:")
            print("\t" + last_command)
            print("")
            print("\tFiles Run:")
            print("\t" + ','.join(files_run))
            sys.exit(0)

    #set last command global
    last_command = request
    client.close()


def heartbeat(target_ip, target_port):
    #create connection to target fuzz server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(4)

    #try connecting to client and recieving response
    try:
        client.connect((target_ip, target_port))
    except socket.timeout:
        print("[ERROR] Connection to Server Timed Out")
        sys.exit(0)
    
    client.close()


def greyCaseSend(bin, tcp_or_udp, raw_case, target_ip, target_port):
    # Create a spk file
    with open('tmp.spk', 'a') as newfile:
        newfile.truncate(0)
        newfile.write("s_binary(\"")
        newfile.write(str(raw_case)[2:].strip('\'').replace('\\x', ''))
        newfile.write("\");")
        if tcp_or_udp == 1:
            os.system(f'{bin} {target_ip} {target_port} {newfile} 0 0 >log 2>&1')
        else:
            os.system(f'{bin} {target_ip} {target_port} {newfile} 0 0 100000 >log 2>&1')


def read_spike_indir(in_dir):
    in_file = find_files(in_dir, '.raw')
    msg_list = []
    for file in in_file:
        with open(file, 'rb') as f:
            content = f.read1()
            msg_list.append(content)
    return msg_list


def usage():
    print("Spike Fuzzing \n[Usage]: spike-nowing(-proxy).py -l proxy_ip:port -t target_ip:port -d spikefiles_directory -e excludes \n\
    -l --local               -Set up local proxy on this ip:port \n\
    -t --target              -Target computer:port to fuzz \n\
    -d --dir                 -Directory where spike files reside \n\
    -e --exclude             -File names to exclude - common seperated \n\
    -h --help                -Help \n[Examples]: \n\
    spike-nowing.py -l 127.0.0.1:9999 -t 192.168.1.105:9999 -d /root/Downloads/spike -e TRUN.spk,GMON.spk \n\
    spike-nowing.py -h")
    sys.exit(0)

