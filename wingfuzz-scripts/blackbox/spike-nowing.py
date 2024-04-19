import os
import sys
import getopt
import socket
import threading
from utils import *

''' ------------< SPIKE AND TARGET CONFIGURATION >------------ '''
# ===== Network Params =====
PROXY_IP = '127.0.0.1'
PROXY_PORT = 12345
TARGET_IP = '127.0.0.1' # local/remote machine
TARGET_PORT = 21
# ===== Target Params =====
PROTOCOL = "ftp"
WORK_DIR = "~/wingfuzz"
BINARY = "proftpd_v1.3.8"
SUM_BITMAP = b''
# ===== Spike Params =====
#exclude = ['TRUN','STATS','TIME','SRUN','HELP','EXIT','GDOG']
EXCLUDE = []
SKIPSTR = 0
SKIPVAR = 0
SPKS_DIR = '~/wingfuzz/ftp/conf'
# Running spike scripts using the TCP/UDP script interpreter 
# spike-fuzzer-generic-send_tcp / spike-fuzzer-generic-send_udp
BIN = '~/Spike-Fuzzer/usr/bin/spike-fuzzer-generic-send_tcp'
'''----------------------------------------------------------- '''


last_command = ""
files_run = []


def handle_client_connection(client_socket):
    #place spike payload in request string and send it to target through sendtoserver
    request = client_socket.recv(8192)
    client_socket.send("ACK".encode('utf-8'))

    #send spike payload to server
    sendtoserver(request)
    client_socket.close()

def sendtoserver(request):
    global last_command

    #create connection to target fuzz server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(4)

    #try connecting to client and recieving response
    try:
        client.connect((TARGET_IP, TARGET_PORT))
        response = client.recv(8192)

        #Check if certain string is in response, if its not print last command
        #this is to check if fuzz string changed the server response
        #if its the same, send the next fuzz string
        if "Welcome".encode('utf-8') in response:
            client.send(request)
        else:
            print("[INFO] Server response changed")
            print(f"\tLast Command Fuzzed: {last_command}")
            print("\tFiles Run: ")
            print("\t" + ','.join(files_run))


    #If a timeout occurs while connecting (4 seconds), print error and show last command fuzzed
    #This could indicate the server crashed
    except socket.timeout:
        print("")
        print("[INFO] Connection to Server Timed Out")
        if last_command == "":
            print("\tUnable to connect to the target computer.")
            sys.exit(0)
        else:
            print("\tLast Command Fuzzed:")
            print("\t" + last_command)
            print("")
            print("\tFiles Run:")
            print("\t" + ','.join(files_run))
            sys.exit(0)

    #set last command global
    last_command = request
    client.close()


def run_spike():
    #if there are no excluded spikes, grab all spk files in the provided spks_dir and run spike
    if len(EXCLUDE) == 0:
        flist = os.listdir(SPKS_DIR)
        for file in sorted(flist):
            name = file.split('.')
            if file.endswith(".spk"):
                newfile = SPKS_DIR + '/' + file
                print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
                files_run.append(name[0])
                os.system(f'{BIN} {PROXY_IP} {PROXY_PORT} {newfile} {SKIPSTR} {SKIPVAR} >log 2>&1')

    # if there are exclusions, grab all spk files that dont contain the exclusion and run spike
    else:
        flist = os.listdir(SPKS_DIR)
        for file in sorted(flist):
            name = file.split('.')
            if file.endswith(".spk") and name[0] not in EXCLUDE:
                newfile = SPKS_DIR + '/' + file
                print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
                files_run.append(name[0])
                os.system(f'{BIN} {PROXY_IP} {PROXY_PORT} {newfile} {SKIPSTR} {SKIPVAR} >log 2>&1')


def fuzz_application(server):
    #create client socket connection
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((TARGET_IP, TARGET_PORT))

    #call method to run spike which will send the fuzz data to our proxy server
    client_handler = threading.Thread(target=run_spike, args=())
    client_handler.start()

    while True:
        #Accept the connection from localhost to proxy and send the socket to handle_client_connections
        client_sock, _ = server.accept()
        handle_client_connection(client_sock)

        global SUM_BITMAP
    
        bitmap = get_bitmap(shmid)
        clean_shm(shmid)
    
        if SUM_BITMAP == b'':
            SUM_BITMAP = bitmap
        else:
            record_path = './record.txt'
            SUM_BITMAP = update_sum_bitmap(bitmap, SUM_BITMAP, record_path)

def usage():
    print("Spike Fuzzing Proxy \nUsage: spike-proxy.py -l proxy_ip:port -t target_ip:port -d spikefiles_directory -e excludes \n\
    -l --local               -Set up local proxy on this ip:port \n\
    -t --target              -Target computer:port to fuzz \n\
    -d --dir                 -Directory where spike files reside \n\
    -e --exclude             -File names to exclude - common seperated \n\
    -h --help                -Help \nExamples: \n\
    spikeproxy.py -l 127.0.0.1:9999 -t 192.168.1.105:9999 -d /root/Downloads/spike -e TRUN.spk,GMON.spk \n\
    spikeproxy.py -h")
    sys.exit(0)


if __name__ == "__main__":
    if not len (sys.argv[1:]):
        usage()

    try:
        opts,args= getopt.getopt(sys.argv[1:],"hl:t:d:e:b", ["help","local","target","dir","exclude","bad"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o,a in opts:
        if o in ("-h","--help"):
            usage()
        elif o in ("-l","--local"):
            try:
                h = a.split(':')
                PROXY_IP = h[0]
                PROXY_PORT = int(h[1])
            except:
                usage()
                sys.exit(0)
        elif o in ("-t","--local"):
            try:
                d = a.split(':')
                TARGET_IP = d[0]
                TARGET_PORT = int(d[1])
            except:
                usage()
                sys.exit(0)
        elif o in ("-d","--dir"):
            try:
                SPKS_DIR = a
            except:
                usage()
                sys.exit(0)
        elif o in ("-e", "--exclude"):
            if ',' in a:
                ex = a.split(',')
                for e in ex:
                    EXCLUDE.append(e)
            else:
                EXCLUDE.append(a)

    print("")
    print("[INFO] Starting Spike Proxy")
    
    # Create SHM to record Coverage
    shmid = open_shm()
    program_boot = f"sudo __AFL_SHM_ID={str(shmid)} {WORK_DIR}/{PROTOCOL}/repo/{BINARY} &"
    p = execute(program_boot)
    time.sleep(1)

    # Create Proxy Binding
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((PROXY_IP, PROXY_PORT))
        server.listen(5)
        print(f'[INFO] __AFL_SHM_ID={str(shmid)}')
        print(f'[INFO] Spike Proxy Listening on {PROXY_IP}:{PROXY_PORT}')

        fuzz_application(server)

