import os
import gc
import sys
import errno
import getopt
import socket
import threading
from utils import *
from spiutils import *

''' ------------< SPIKE AND TARGET CONFIGURATION >------------ '''
# ===== Network Params =====
PROXY_IP = '127.0.0.1'
PROXY_PORT = 12345
TARGET_IP = '0.0.0.0' # local/remote machine
TARGET_PORT = 4200
# ===== Target Params =====
PROTOCOL = "dicom"
WORK_DIR = "~/wingfuzz"
BINARY = "storescp_v3.6.7"
SUM_BITMAP = b''
IN_DIR = f"../../../bak-wingfuzz/{PROTOCOL}/in/"
# ===== Spike Params =====
#exclude = ['TRUN','STATS','TIME','SRUN','HELP','EXIT','GDOG']
EXCLUDE = []
SKIPSTR = 0
SKIPVAR = 0
SPKS_DIR = '/home/dez/wingfuzz/dicom/conf'
TCP_OR_UDP = 1  # TCP = 1; UDP = 0; Configure it
DURATION_TIME = 3600
UDP_TOTAL_SEND = 10000000    # UDP send number of cases
# Running spike scripts using the TCP/UDP script interpreter 
# spike-fuzzer-generic-send_tcp / spike-fuzzer-generic-send_udp
BIN = '~/Spike-Fuzzer/usr/bin/spike-fuzzer-generic-send_tcp'
# BIN = '~/Spike-Fuzzer/usr/bin/spike-fuzzer-generic-send_udp'
'''----------------------------------------------------------- '''

files_run = []
msg_list = read_spike_indir(IN_DIR)

# Backup for proxy mode
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


def handle_greybox_connection(msg_list, target_ip, target_port):
    global SUM_BITMAP

    for i in range(0, len(msg_list)):
        request = msg_list[i]
        greyCaseSend(BIN, TCP_OR_UDP, request, target_ip, target_port)

        bitmap = get_bitmap(shmid)
        clean_shm(shmid)
        if SUM_BITMAP == b'':
            SUM_BITMAP = bitmap
        else:
            record_path = './record.txt'
            SUM_BITMAP = update_sum_bitmap(bitmap, SUM_BITMAP, record_path)


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
                if TCP_OR_UDP == 1:
                    os.system(f'{BIN} {TARGET_IP} {TARGET_PORT} {newfile} {SKIPSTR} {SKIPVAR} >log 2>&1')
                else: 
                    os.system(f'{BIN} {TARGET_IP} {TARGET_PORT} {newfile} {SKIPSTR} {SKIPVAR} {UDP_TOTAL_SEND} >log 2>&1')

    # if there are exclusions, grab all spk files that dont contain the exclusion and run spike
    else:
        flist = os.listdir(SPKS_DIR)
        for file in sorted(flist):
            name = file.split('.')
            if file.endswith(".spk") and name[0] not in EXCLUDE:
                newfile = SPKS_DIR + '/' + file
                print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
                files_run.append(name[0])
                if TCP_OR_UDP == 1:
                    os.system(f'{BIN} {TARGET_IP} {TARGET_PORT} {newfile} {SKIPSTR} {SKIPVAR} >log 2>&1')
                else: 
                    os.system(f'{BIN} {TARGET_IP} {TARGET_PORT} {newfile} {SKIPSTR} {SKIPVAR} {UDP_TOTAL_SEND} >log 2>&1')


def cov_log_duration(duration):
    global SUM_BITMAP

    start_time = time.time()

    if len(msg_list) != 0:
        handle_greybox_connection(msg_list, TARGET_IP, TARGET_PORT)

    while time.time() - start_time < duration:
        bitmap = get_bitmap(shmid)
        clean_shm(shmid)

        if SUM_BITMAP == b'':
            SUM_BITMAP = bitmap
        else:
            record_path = './record.txt'
            SUM_BITMAP = update_sum_bitmap(bitmap, SUM_BITMAP, record_path)


def spike_cmd_boot():
    global PROXY_IP, PROXY_PORT, TARGET_IP, TARGET_PORT, SPKS_DIR, EXCLUDE

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

    print("\n[INFO] Starting Spike-Wing")


# Record message from grey-box
def record_msg(b_msg):
    now = datetime.now()
    formatted_time = now.strftime("%Y-%m-%d-%H-%M-%S")
    print(f"Black_Box_Fuzzing Get MSG - {formatted_time}")
    print(f"MSG - {b_msg}")
    file = os.path.join(IN_DIR, f"Grey-Box-{formatted_time}.raw")
    with open(file, 'wb') as f:
        f.write(b_msg)
        time.sleep(2)  # need some time to write


if __name__ == "__main__":
    
    spike_cmd_boot()
    
    # Create SHM to record Coverage
    shmid = open_shm()
    program_close = f"sudo pkill -9 -f /repo/{BINARY}"
    program_boot = f"sudo __AFL_SHM_ID={str(shmid)} {WORK_DIR}/{PROTOCOL}/repo/{BINARY} -ll fatal 4200 &"
    p = execute(program_boot)
    time.sleep(1)

    # Create Proxy Binding
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((PROXY_IP, PROXY_PORT))
        server.listen(5)
        print(f'[INFO] __AFL_SHM_ID={str(shmid)}')
        print(f'[INFO] Spike Proxy Listening on {PROXY_IP}:{PROXY_PORT}')

        for idx in range(0, 10):
            # Prevent OOM
            gc.collect()

            client_handler = threading.Thread(target=run_spike(), args=())
            client_handler.start()

            cov_log_duration(DURATION_TIME)

            conn, addr = server.accept()
            with conn:
                flag = conn.recv(4)
                while True:
                    # Sticky Packets and Packet Splitting
                    if flag.decode('utf-8') == 'mesg':
                        flag = bytes()  # set as null
                        test = conn.recv(8).decode('utf-8')
                        msg_len = test.split('.')[0]
                        part_msg = test.split('.')[1]
                        res_data_len = int(msg_len) - 7 + len(msg_len)
                        recv_data = b''
                        while len(recv_data) < res_data_len:
                            data = conn.recv(res_data_len - len(recv_data))
                            if not data:
                                break
                            recv_data += data
                        msg = part_msg + recv_data.decode('utf-8')
                        b_msg = bytes(msg, 'latin-1').decode('unicode_escape').encode('latin-1')
                        record_msg(b_msg)
                        # read another flag
                        flag = conn.recv(4)
                    elif flag.decode('utf-8') == 'stop' or flag == bytes():
                        now = datetime.now()
                        formatted_time = now.strftime("%Y-%m-%d-%H-%M-%S")
                        print(f"Black_Box_Fuzzing Quit - {formatted_time}")
                        #stop_thread = True  
                        break
            
            msg_list = read_spike_indir(IN_DIR)
    
    p = execute(program_close)
    close_shm(shmid)