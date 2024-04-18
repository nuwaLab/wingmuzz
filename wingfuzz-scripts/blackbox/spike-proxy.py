import os
import sys
import getopt
import socket
import threading

last_command = ""
files_run = []

''' ========= CONFIGURATION ========= '''
# define spike proxy bind ip
proxy_ip = '127.0.0.1'
proxy_port = 12345
# define remote target to fuzz
target_ip= ''
target_port = 9999
#Spike Paramaters
#exclude = ['TRUN','STATS','TIME','SRUN','HELP','EXIT','GDOG']
exclude = []
skipstring = 0
skipvar = 0
path = '/root/Desktop/exploits/EIP/VulnServer/spikes'
bin = '/usr/bin/generic_send_tcp'


def handle_client_connection(client_socket):
    #place spike payload in request string and send it to target through sendtoserver
    request = client_socket.recv(8192)
    client_socket.send('ACK')

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
        client.connect((target_ip, target_port))
        response = client.recv(8192)

        #Check if certain string is in response, if its not print last command
        #this is to check if fuzz string changed the server response
        #if its the same, send the next fuzz string
        if 'Welcome' in response:
            client.send(request)
        else:
            print("")
            print("[*] Server response changed")
            print("\tLast Command Fuzzed:")
            print("\t" + last_command)
            print("\tFiles Run:")
            print("\t" + ','.join(files_run))


    #If a timeout occurs while connecting (4 seconds), print error and show last command fuzzed
    #This could indicate the server crashed
    except socket.timeout:
        print("")
        print("[*] Connection to Server Timed Out")
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
    #if there are no excluded spikes, grab all spk files in the provided path and run spike
    if exclude == "":
        flist = os.listdir(path)
        for file in sorted(flist):
            if file.endswith(".spk"):
                newfile = path + '/' + file
                print("")
                print("[*]Fuzzing {}:{} Using {}".format(target_ip, target_port, file))
                files_run.append(name[0])
                os.system(bin + ' {} {} {} {} {} >out 2>&1'.format(bind_ip, bind_port, newfile, skipstring, skipvar))

    # if there are exclusions, grab all spk files that dont contain the exclusion and run spike
    else:
        flist = os.listdir(path)
        for file in sorted(flist):
            name = file.split('.')
            if file.endswith(".spk") and name[0] not in exclude:
                newfile = path + '/' + file
                print("")
                print("[*]Fuzzing {}:{} Using {}".format(target_ip,target_port,file))
                files_run.append(name[0])
                os.system(bin + ' {} {} {} {} {} >out 2>&1'.format(bind_ip, bind_port, newfile, skipstring, skipvar))


def fuzz_application(server):


    #create client socket connection
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_ip, target_port))

    #call method to run spike which will send the fuzz data to our proxy server
    client_handler = threading.Thread(target=run_spike, args=())
    client_handler.start()

    while True:
        #Accept the connection from localhost to proxy and send the socket to handle_client_connections
        client_sock, address = server.accept()
        handle_client_connection(client_sock)

def usage():
    print("Spike Fuzzing Proxy \n\
     Usage: spikeproxy.py -l proxy_ip:port -t target_ip:port -d spikefiles_directory -e excludes \n\
     -l --local               -Set up local proxy on this ip:port \n\
     -t --target              -Target computer:port to fuzz \n\
     -d --dir                 -Directory where spike files reside \n\
     -e --exclude             -File names to exclude - common seperated \n\
     -h --help                -Help \nExamples: \n\
     spikeproxy.py -l 127.0.0.1:9999 -t 192.168.1.105:9999 -d /root/Downloads/spike -e TRUN.spk,GMON.spk \n\
     spikeproxy.py -h")
    sys.exit(0)


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
            bind_ip = h[0]
            bind_port = int(h[1])
        except:
            usage()
            sys.exit(0)
    elif o in ("-t","--local"):
        try:
            d = a.split(':')
            target_ip = d[0]
            target_port = int(d[1])
        except:
            usage()
            sys.exit(0)
    elif o in ("-d","--dir"):
        try:
            path = a
        except:
            usage()
            sys.exit(0)
    elif o in ("-e", "--exclude"):
        if ',' in a:
            ex = a.split(',')
            for e in ex:
                exclude.append(e)
        else:
            exclude.append(a)

print("")
print("Starting Spike Proxy")

#Create Proxy Binding
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((bind_ip, bind_port))
server.listen(5)

print("")
print('[*]Spike Proxy Listening on {}:{}'.format(bind_ip, bind_port))

fuzz_application(server)

