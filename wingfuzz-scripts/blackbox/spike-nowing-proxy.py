import os
import sys
import errno
import getopt
import socket
import threading
from utils import *
from spiutils import *

''' ------------< SPIKE AND TARGET CONFIGURATION >------------ '''
# ===== Network Params =====
PROXY_IP = '0.0.0.0'
PROXY_PORT = 12345
TARGET_IP = '0.0.0.0' # local/remote machine
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
SPKS_DIR = '/home/dez/wingfuzz/ftp/conf'
# Running spike scripts using the TCP/UDP script interpreter 
# spike-fuzzer-generic-send_tcp / spike-fuzzer-generic-send_udp
BIN = '~/Spike-Fuzzer/usr/bin/spike-fuzzer-generic-send_tcp'
# BIN = '~/Spike-Fuzzer/usr/bin/spike-fuzzer-generic-send_udp'
'''----------------------------------------------------------- '''

files_run = []

def handle_client_connection(client_socket, target_ip, target_port, files_run):
    #place spike payload in request string and send it to target through sendtoserver
    request = client_socket.recv(8192)
    try:
        client_socket.send("ACK".encode('utf-8'))
    except IOError as e:
        if e.errno == errno.EPIPE:
            print("[ERROR] Broken pipe, need check.")
            client_socket.close()
            return

    #send spike payload to server
    sendtoserver(request, target_ip, target_port, files_run)
    client_socket.close()



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
    global SUM_BITMAP
    #create client socket connection
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((TARGET_IP, TARGET_PORT))

    #call method to run spike which will send the fuzz data to our proxy server
    client_handler = threading.Thread(target=run_spike, args=())
    client_handler.start()
    
    while True:
        #Accept the connection from localhost to proxy and send the socket to handle_client_connections
        client_sock, _ = server.accept()
        handle_client_connection(client_sock, TARGET_IP, TARGET_PORT, files_run)
    
        bitmap = get_bitmap(shmid)
        clean_shm(shmid)
    
        if SUM_BITMAP == b'':
            SUM_BITMAP = bitmap
        else:
            record_path = './record.txt'
            SUM_BITMAP = update_sum_bitmap(bitmap, SUM_BITMAP, record_path)


def spike_cmd_boot():
    global PROXY_IP, PROXY_PORT, TARGET_IP, TARGET_PORT, SPKS_DIR

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

    print("\n[INFO] Starting Spike Proxy")


# Spike-nowing, just blackbox fuzzing
if __name__ == "__main__":
    
    spike_cmd_boot()
    
    # Create SHM to record Coverage
    shmid = open_shm()
    program_close = f"sudo pkill -9 -f /repo/{BINARY}"
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
    
    p = execute(program_close)
    close_shm(shmid)