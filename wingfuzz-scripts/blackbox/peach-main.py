import os
import gc
import sys
import errno
import getopt
import socket
import threading
from utils import *
from spiutils import *

''' ------------< PEACH AND TARGET CONFIGURATION >------------ '''
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
IN_DIR = f"../../../bak-wingfuzz/{PROTOCOL}/in/"
# ===== Peach Params =====
#exclude = ['TRUN','STATS','TIME','SRUN','HELP','EXIT','GDOG']
EXCLUDE = []
SKIPSTR = 0
SKIPVAR = 0
PITS_DIR = '/home/dez/wingfuzz/ntp/conf'
DURATION_TIME = 3600
# Running PIT files using the peach binary 
BIN = '~/peach-3.1.124/peach'
'''----------------------------------------------------------- '''

files_run = []
msg_list = read_spike_indir(IN_DIR)

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

def handle_greybox_connection(msg_list, target_ip, target_port, files_run):
    global SUM_BITMAP

    for i in range(0, len(msg_list)):
        request = msg_list[i]
        sendtoserver(request, target_ip, target_port, files_run)

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
        flist = os.listdir(PITS_DIR)
        for file in sorted(flist):
            name = file.split('.')
            if file.endswith(".spk"):
                newfile = PITS_DIR + '/' + file
                print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
                files_run.append(name[0])
                os.system(f'{BIN} {PROXY_IP} {PROXY_PORT} {newfile} {SKIPSTR} {SKIPVAR} >log 2>&1')

    # if there are exclusions, grab all spk files that dont contain the exclusion and run spike
    else:
        flist = os.listdir(PITS_DIR)
        for file in sorted(flist):
            name = file.split('.')
            if file.endswith(".spk") and name[0] not in EXCLUDE:
                newfile = PITS_DIR + '/' + file
                print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
                files_run.append(name[0])
                os.system(f'{BIN} {PROXY_IP} {PROXY_PORT} {newfile} {SKIPSTR} {SKIPVAR} >log 2>&1')


def fuzz_application_duration(server, duration):
    global SUM_BITMAP
    start = time.time()
    #create client socket connection
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((TARGET_IP, TARGET_PORT))

    if len(msg_list) != 0:
        handle_greybox_connection(msg_list, TARGET_IP, TARGET_PORT, files_run)

    #call method to run spike which will send the fuzz data to our proxy server
    client_handler = threading.Thread(target=run_spike, args=())
    client_handler.start()

    while time.time() - start < duration:
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
    pass

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
    print("========================== [PEACH MANUAL] ==========================")
    os.system(f'{BIN} -h')
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

        for idx in range(0, 10):
            # Prevent OOM
            gc.collect()

            fuzz_application_duration(server, DURATION_TIME)

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